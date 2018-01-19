package policy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/leodotcloud/log"
	"github.com/mitchellh/hashstructure"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher-metadata/metadata"
	selutil "github.com/rancher/go-rancher-metadata/util"
	pmutils "github.com/rancher/plugin-manager/utils"
)

const (
	// TODO: Having contention with hostports iptables rules logic
	// Discuss with @ibuildthecloud, fix it for 1.5
	//hookToChain = "CATTLE_FORWARD"
	hookToChain                  = "FORWARD"
	cattleNetworkPolicyChainName = "CATTLE_NETWORK_POLICY"
	ipsetNameMaxLength           = 31
)

type watcher struct {
	c                   metadata.Client
	lastApplied         time.Time
	doCleanup           bool
	shutdownInProgress  bool
	signalCh            chan os.Signal
	exitCh              chan int
	defaultNetwork      *metadata.Network
	validNetworks       map[string]*metadata.Network
	defaultSubnet       string
	stacks              []metadata.Stack
	services            []metadata.Service
	containers          []metadata.Container
	containersMapByUUID map[string]*metadata.Container
	servicesMapByName   map[string]*metadata.Service
	appliedIPsets       map[string]map[string]bool
	appliedRules        map[int]map[string]Rule
	ipsets              map[string]map[string]bool
	ipsetsNamesMap      map[string]string
	rules               map[int]map[string]Rule
	selfHost            *metadata.Host
	appliednp           *NetworkPolicy
	np                  *NetworkPolicy
	name                string
	regionName          string
	environments        []metadata.Environment
}

// Rule is used to store the info need to be a iptables rule
type Rule struct {
	dst        string
	src        string
	ports      []string
	isStateful bool
	action     string
	system     bool
}

func setupKernelParameters() error {
	cmd := "sysctl -w net.bridge.bridge-nf-call-iptables=1"
	return executeCommandNoStdoutNoStderr(cmd)
}

func (rule *Rule) iptables(defaultPolicyAction string) []byte {
	buf := &bytes.Buffer{}
	var ruleTarget string

	// TODO: Check for ports etc

	if rule.isStateful {
		buf.WriteString(fmt.Sprintf("-A %v ", cattleNetworkPolicyChainName))
		if rule.dst != "" {
			buf.WriteString(fmt.Sprintf("-m set --match-set %v dst ", rule.dst))
		}

		if rule.src != "" {
			buf.WriteString(fmt.Sprintf("-m set --match-set %v src ", rule.src))
		}
		buf.WriteString(fmt.Sprintf("-m conntrack --ctstate NEW,ESTABLISHED,RELATED "))
		if rule.action == ActionAllow {
			ruleTarget = "RETURN"
		} else {
			ruleTarget = "DROP"
		}

		buf.WriteString(fmt.Sprintf("-j %v\n", ruleTarget))

		// Reverse path
		buf.WriteString(fmt.Sprintf("-A %v ", cattleNetworkPolicyChainName))
		if rule.dst != "" {
			buf.WriteString(fmt.Sprintf("-m set --match-set %v dst ", rule.src))
		}

		if rule.src != "" {
			buf.WriteString(fmt.Sprintf("-m set --match-set %v src ", rule.dst))
		}
		buf.WriteString(fmt.Sprintf("-m conntrack --ctstate ESTABLISHED,RELATED "))
		if rule.action == ActionAllow {
			ruleTarget = "RETURN"
		} else {
			ruleTarget = "DROP"
		}

		buf.WriteString(fmt.Sprintf("-j %v\n", ruleTarget))

	} else {
		buf.WriteString(fmt.Sprintf("-A %v ", cattleNetworkPolicyChainName))
		if rule.dst != "" {
			buf.WriteString(fmt.Sprintf("-m set --match-set %v dst ", rule.dst))
		}

		if rule.src != "" {
			buf.WriteString(fmt.Sprintf("-m set --match-set %v src ", rule.src))
		}

		if rule.action == ActionAllow {
			ruleTarget = "RETURN"
		} else {
			ruleTarget = "DROP"
		}

		buf.WriteString(fmt.Sprintf("-j %v\n", ruleTarget))

	}

	return buf.Bytes()
}

// Watch is used to monitor metadata for changes
func Watch(c metadata.Client, exitCh chan int, doCleanup bool) error {
	err := setupKernelParameters()
	if err != nil {
		log.Errorf("Error setting up needed kernel parameters: %v", err)
		return err
	}

	sCh := make(chan os.Signal, 2)
	signal.Notify(sCh, os.Interrupt, syscall.SIGTERM)

	w := &watcher{
		c:                  c,
		shutdownInProgress: false,
		doCleanup:          doCleanup,
		exitCh:             exitCh,
		signalCh:           sCh,
	}

	go w.shutdown()
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

func (w *watcher) shutdown() {
	<-w.signalCh
	log.Infof("Got shutdown signal")

	w.shutdownInProgress = true

	// This is probably a good place to add clean up logic
	if w.doCleanup {
		w.cleanup()
	}

	w.exitCh <- 0
}

func (w *watcher) onChangeNoError(version string) {
	log.Debugf("onChangeNoError version: %v", version)
	if w.shutdownInProgress {
		log.Infof("Shutdown in progress, no more processing")
		return
	}

	if err := w.onChange(version); err != nil {
		log.Errorf("Failed to apply network NetworkPolicy: %v", err)
	}
}

func getBridgeSubnet(network *metadata.Network) (string, error) {
	conf, _ := network.Metadata["cniConfig"].(map[string]interface{})
	for _, file := range conf {
		props, _ := file.(map[string]interface{})
		bridgeSubnet, _ := props["bridgeSubnet"].(string)
		return bridgeSubnet, nil
	}

	return "", fmt.Errorf("Couldn't find bridgeSubnet for network: %v", network)
}

func (w *watcher) fetchNetworkInfo() error {
	hasErrored := false
	networks, _, err := pmutils.GetLocalNetworksAndRoutersFromMetadata(w.c)
	if err != nil {
		return err
	}

	if len(networks) != 1 {
		return fmt.Errorf("expected one local network, found: %v", len(networks))
	}

	w.defaultNetwork = &networks[0]
	log.Debugf("defaultNetwork: %v", w.defaultNetwork)

	w.validNetworks = make(map[string]*metadata.Network)
	w.validNetworks[w.defaultNetwork.UUID] = &networks[0]

	_, w.defaultSubnet = pmutils.GetBridgeInfo(*w.defaultNetwork, *w.selfHost)
	log.Debugf("defaultSubnet: %v", w.defaultSubnet)

	if w.regionName != "" {
		for _, aEnvironment := range w.environments {
			var aEnvNetworks []metadata.Network
			if len(aEnvironment.Hosts) > 0 {
				aEnvNetworks, _ = pmutils.GetLocalNetworksAndRouters(
					aEnvironment.Networks,
					aEnvironment.Hosts[0],
					aEnvironment.Services,
				)
			}
			//log.Debugf("aEnvNetworks: %v", aEnvNetworks)

			if len(aEnvNetworks) != 1 {
				log.Errorf("expected one network, but found %v for env=%v", len(aEnvNetworks), aEnvironment.Name)
				hasErrored = true
				continue
			}
			w.validNetworks[aEnvNetworks[0].UUID] = &aEnvNetworks[0]
		}
	}

	if hasErrored {
		return fmt.Errorf("error fetching network info")
	}

	log.Debugf("validNetworks: %v", w.validNetworks)
	return nil
}

func (w *watcher) isValidNetwork(uuid string) bool {
	_, found := w.validNetworks[uuid]
	return found
}

//
// group_by doesn't apply to system containers
// groupByMap:
//	   labelValue1:
//	       local:
//			   10.42.1.1: true
//		   all:
//			   10.42.1.1: true
//			   10.42.1.2: true
//	   labelValue2:
//	       local:
//			   10.42.2.1: true
//		   all:
//			   10.42.2.1: true
//			   10.42.2.2: true
//
func (w *watcher) getContainersGroupedBy(label string) map[string]map[string]map[string]bool {
	log.Debugf("getting containers grouped by: %v", label)
	groupByMap := make(map[string]map[string]map[string]bool)

	for _, aContainer := range w.containers {
		if aContainer.System {
			continue
		}
		if w.isValidNetwork(aContainer.NetworkUUID) {
			if labelValue, labelExists := aContainer.Labels[label]; labelExists {
				aLabelValueMap, aLabelValueMapExists := groupByMap[labelValue]
				if !aLabelValueMapExists {
					aLabelValueMap = make(map[string]map[string]bool)
					aLabelValueMap["local"] = make(map[string]bool)
					aLabelValueMap["all"] = make(map[string]bool)
					groupByMap[labelValue] = aLabelValueMap
				}

				if aContainer.HostUUID == w.selfHost.UUID {
					if aContainer.PrimaryIp != "" {
						aLabelValueMap["local"][aContainer.PrimaryIp] = true
					}
				}
				if aContainer.PrimaryIp != "" {
					aLabelValueMap["all"][aContainer.PrimaryIp] = true
				}
			}
		}
	}

	log.Debugf("groupByMap: %v", groupByMap)
	return groupByMap
}

// This function returns IP addresses of local and all containers of the stack
// on the default network
func (w *watcher) getInfoFromStack(stack metadata.Stack) (map[string]bool, map[string]bool) {
	local := make(map[string]bool)
	all := make(map[string]bool)
	for _, aService := range stack.Services {
		for _, aContainer := range aService.Containers {
			if w.isValidNetwork(aContainer.NetworkUUID) {
				if aContainer.HostUUID == w.selfHost.UUID {
					if aContainer.PrimaryIp != "" {
						local[aContainer.PrimaryIp] = true
					}
				}
				if aContainer.PrimaryIp != "" {
					all[aContainer.PrimaryIp] = true
				}
			}
		}
	}

	return local, all
}

// This function returns IP addresses of local and all containers of the service
// on the default network.
// Any sidekick service is also considered part of the same service.
func (w *watcher) getInfoFromService(service metadata.Service) (map[string]bool, map[string]bool) {
	log.Debugf("getInfoFromService service: %v", service)
	local := make(map[string]bool)
	all := make(map[string]bool)

	// This means it's a sidekick service, it will handled as part of the
	// primary service, so skipping here.
	if service.Name != service.PrimaryServiceName {
		log.Debugf("service: %v is sidekick, skipping", service.Name)
		return local, all
	}

	for _, aContainer := range service.Containers {
		if w.isValidNetwork(aContainer.NetworkUUID) {
			if aContainer.HostUUID == w.selfHost.UUID {
				if aContainer.PrimaryIp != "" {
					local[aContainer.PrimaryIp] = true
				}
			}
			if aContainer.PrimaryIp != "" {
				all[aContainer.PrimaryIp] = true
			}
		}
	}

	for _, aSKServiceName := range service.Sidekicks {
		aSKServiceNameLowerCase := strings.ToLower(aSKServiceName)
		log.Debugf("aSKServiceNameLowerCase: %v", aSKServiceNameLowerCase)
		fullSKServiceName := service.StackName + "/" + aSKServiceNameLowerCase
		sidekickService, found := w.servicesMapByName[fullSKServiceName]
		if !found {
			log.Errorf("unable to find sidekick service: %v", fullSKServiceName)
			continue
		}

		for _, aContainer := range sidekickService.Containers {
			if w.isValidNetwork(aContainer.NetworkUUID) {
				if aContainer.HostUUID == w.selfHost.UUID {
					if aContainer.PrimaryIp != "" {
						local[aContainer.PrimaryIp] = true
					}
				}
				if aContainer.PrimaryIp != "" {
					all[aContainer.PrimaryIp] = true
				}
			}
		}
	}

	return local, all
}

// This function returns IP addresses of dst and src containers of the linkedToContainers
// on the default network
func (w *watcher) getInfoFromLinkedContainers(
	linkedToContainerUUID string, linkedFromContainersMap map[string]*metadata.Container) (
	map[string]bool, map[string]bool) {
	log.Debugf("getInfoFromLinkedContainers")

	var dst, src map[string]bool
	linkedToLocal := make(map[string]bool)
	linkedToAll := make(map[string]bool)
	linkedFromLocal := make(map[string]bool)
	linkedFromAll := make(map[string]bool)

	linkedToContainer, ok := w.containersMapByUUID[linkedToContainerUUID]
	if !ok {
		log.Errorf("error finding container by name: %v", linkedToContainerUUID)
		return dst, src
	}
	log.Debugf("linkedToContainer: %+v", linkedToContainer)

	if linkedToContainer.PrimaryIp != "" {
		if linkedToContainer.HostUUID == w.selfHost.UUID {
			linkedToLocal[linkedToContainer.PrimaryIp] = true
		}
		linkedToAll[linkedToContainer.PrimaryIp] = true
	}

	for _, linkedFromContainer := range linkedFromContainersMap {
		log.Debugf("linkedFromContainer: %+v", linkedFromContainer)
		if linkedFromContainer.PrimaryIp != "" {
			if linkedFromContainer.HostUUID == w.selfHost.UUID {
				linkedFromLocal[linkedFromContainer.PrimaryIp] = true
			}
			linkedFromAll[linkedFromContainer.PrimaryIp] = true
		}
	}

	log.Debugf("linkedToLocal: %v", linkedToLocal)
	log.Debugf("linkedToAll: %v", linkedToAll)
	log.Debugf("linkedFromLocal: %v", linkedFromLocal)
	log.Debugf("linkedFromAll: %v", linkedFromAll)

	if len(linkedToLocal) > 0 {
		dst = linkedToLocal
		src = linkedFromAll
	} else {
		if len(linkedFromLocal) > 0 {
			dst = linkedToAll
			src = linkedFromLocal
		}
	}

	log.Debugf("dst: %v", dst)
	log.Debugf("src: %v", src)
	return dst, src
}

// This function returns IP addresses of dst and src containers of the linkedTo service
// on the default network
func (w *watcher) getInfoFromLinkedServices(
	linkedTo string, linkedFromMap map[string]*metadata.Service) (
	map[string]bool, map[string]bool) {
	log.Debugf("getInfoFromLinkedServices")

	var dst, src map[string]bool

	linkedToService, ok := w.servicesMapByName[linkedTo]
	if !ok {
		log.Errorf("error finding service by name: %v", linkedTo)
		return nil, nil
	}
	linkedToLocal, linkedToAll := w.getInfoFromService(*linkedToService)
	log.Debugf("linkedToLocal: %v", linkedToLocal)
	log.Debugf("linkedToAll: %v", linkedToAll)

	linkedFromAll := make(map[string]bool)
	for _, aLinkedFromService := range linkedFromMap {
		fromLocal, fromAll := w.getInfoFromService(*aLinkedFromService)
		log.Debugf("fromLocal: %v", fromLocal)
		log.Debugf("fromAll: %v", fromAll)

		if len(linkedToLocal) > 0 {
			for k, v := range fromAll {
				linkedFromAll[k] = v
			}
		} else {
			if len(fromLocal) > 0 {
				for k, v := range fromLocal {
					linkedFromAll[k] = v
				}
			}
		}
	}

	if len(linkedFromAll) > 0 {
		dst = linkedToAll
		src = linkedFromAll
	}

	log.Debugf("dst: %v", dst)
	log.Debugf("src: %v", src)
	return dst, src
}

func (w *watcher) generateHash(s string) (string, error) {
	hash, err := hashstructure.Hash(s, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", hash), nil
}

func (w *watcher) getAllLocalContainers() map[string]bool {
	all := make(map[string]bool)

	for _, aContainer := range w.containers {
		if aContainer.System {
			continue
		}
		if w.isValidNetwork(aContainer.NetworkUUID) {
			if aContainer.HostUUID == w.selfHost.UUID {
				if aContainer.PrimaryIp != "" {
					all[aContainer.PrimaryIp] = true
				}
			}
		}
	}

	log.Debugf("all local containers: %v", all)
	return all
}

func (w *watcher) defaultPolicyAction(action string) (map[string]Rule, error) {
	defPolicyActionMap := make(map[string]Rule)

	ruleName := "all.local.containers"
	all := w.getAllLocalContainers()
	isStateful := false
	isDstSystem := false
	isSrcSystem := false
	r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, all, nil)
	if err != nil {
		return nil, err
	}
	r.action = action
	defPolicyActionMap[ruleName] = *r

	log.Debugf("defPolicyActionMap: %v", defPolicyActionMap)
	return defPolicyActionMap, nil
}

func (w *watcher) defaultSystemStackPolicies() (map[string]Rule, error) {
	defSysRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		if !stack.System {
			continue
		}

		_, all := w.getInfoFromStack(stack)

		ruleName := fmt.Sprintf("from.system.stack.%v", stack.Name)
		isStateful := false
		isDstSystem := true
		isSrcSystem := true
		r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, nil, all)
		if err != nil {
			return nil, err
		}
		r.action = ActionAllow
		defSysRulesMap[ruleName] = *r
	}

	log.Debugf("defSysRulesMap: %v", defSysRulesMap)
	return defSysRulesMap, nil
}

func (w *watcher) withinStackHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	log.Debugf("withinStackHandler")
	withinStackRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		if stack.System {
			continue
		}
		local, all := w.getInfoFromStack(stack)
		if len(local) > 0 {
			ruleName := fmt.Sprintf("within.stack.%v", stack.Name)
			isStateful := false
			isDstSystem := false
			isSrcSystem := false
			if stack.System {
				isDstSystem = true
				isSrcSystem = true
			}
			r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = p.Action

			withinStackRulesMap[ruleName] = *r
		} else {
			log.Debugf("stack: %v doesn't have any local containers, skipping", stack.Name)
			continue
		}
	}

	log.Debugf("withinStackRulesMap: %v", withinStackRulesMap)
	return withinStackRulesMap, nil
}

func (w *watcher) buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem bool, ruleName string, local, all map[string]bool) (*Rule, error) {
	var err error
	var srcSetName, dstSetName, hashedDstSetName, hashedSrcSetName string

	if local != nil {
		dstSetName = fmt.Sprintf("dst.%v", ruleName)
		hashedDstSetName, err = w.generateHash(dstSetName)
		if err != nil {
			log.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}

		if isDstSystem {
			hashedDstSetName = "RNCH-S-" + hashedDstSetName
		} else {
			hashedDstSetName = "RNCH-U-" + hashedDstSetName
		}

		if len(hashedDstSetName) > ipsetNameMaxLength {
			log.Errorf("length of ipset names exceeded %v. hashedDstSetName: %v", ipsetNameMaxLength, hashedDstSetName)
			hashedDstSetName = hashedDstSetName[0 : ipsetNameMaxLength-1]
		}
		if existingSet, exists := w.ipsets[hashedDstSetName]; exists {
			if !reflect.DeepEqual(existingSet, local) {
				return nil, fmt.Errorf("%v: mismatch existingSet: %v local:%v", hashedDstSetName, existingSet, local)
			}
		} else {
			w.ipsets[hashedDstSetName] = local
			w.ipsetsNamesMap[hashedDstSetName] = dstSetName
		}
	}

	if all != nil {

		srcSetName = fmt.Sprintf("src.%v", ruleName)
		hashedSrcSetName, err = w.generateHash(srcSetName)
		if err != nil {
			log.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}
		if isSrcSystem {
			hashedSrcSetName = "RNCH-S-" + hashedSrcSetName
		} else {
			hashedSrcSetName = "RNCH-U-" + hashedSrcSetName
		}
		if len(hashedSrcSetName) > ipsetNameMaxLength {
			log.Errorf("length of ipset names exceeded %v. hashedSrcSetName: %v", ipsetNameMaxLength, hashedSrcSetName)
			hashedSrcSetName = hashedSrcSetName[0 : ipsetNameMaxLength-1]
		}
		if existingSet, exists := w.ipsets[hashedSrcSetName]; exists {
			if !reflect.DeepEqual(existingSet, all) {
				log.Errorf("%v: mismatch existingSet: %v all:%v", hashedSrcSetName, existingSet, all)
			}
		} else {
			w.ipsets[hashedSrcSetName] = all
			w.ipsetsNamesMap[hashedSrcSetName] = srcSetName
		}
	}

	log.Debugf("dst: %v (%v) src: %v (%v)", hashedDstSetName, dstSetName, hashedSrcSetName, srcSetName)

	r := &Rule{dst: hashedDstSetName,
		src:        hashedSrcSetName,
		isStateful: isStateful,
	}

	return r, nil
}

func (w *watcher) withinServiceHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	log.Debugf("withinServiceHandler")
	withinServiceRulesMap := make(map[string]Rule)
	for _, service := range w.services {
		if service.System {
			continue
		}
		local, all := w.getInfoFromService(service)
		if len(local) > 0 {
			ruleName := fmt.Sprintf("within.service.%v.%v", service.StackName, service.Name)
			isStateful := false
			isDstSystem := false
			isSrcSystem := false
			r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = p.Action

			withinServiceRulesMap[ruleName] = *r
		} else {
			log.Debugf("service: %v doesn't have any local containers, skipping", service.Name)
			continue
		}
	}

	log.Debugf("withinServiceRulesMap: %v", withinServiceRulesMap)
	return withinServiceRulesMap, nil
}

func (w *watcher) withinLinkedHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	log.Debugf("withinLinkedHandler")
	withinLinkedRulesMap := make(map[string]Rule)

	linkedMappings := w.buildLinkedMappings()

	for linkedTo, linkedFromMap := range linkedMappings {
		log.Debugf("linkedTo: %v, linkedFromMap: %v", linkedTo, linkedFromMap)

		local, all := w.getInfoFromLinkedServices(linkedTo, linkedFromMap)
		if len(local) > 0 {
			ruleName := fmt.Sprintf("within.linked.%v", linkedTo)
			isStateful := true
			isDstSystem := false
			isSrcSystem := false
			r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = p.Action

			withinLinkedRulesMap[ruleName] = *r
		} else {
			log.Debugf("linked service: %v doesn't have any local containers, skipping", linkedTo)
			continue
		}
	}

	// Process links of standalone containers
	linkedContainersMap := buildLinkedMappingsForContainers(w.containers)
	for linkedToContainerUUID, linkedFromContainersMap := range linkedContainersMap {
		log.Debugf("linkedToContainerUUID: %v, linkedFromContainersMap: %v", linkedToContainerUUID, linkedFromContainersMap)

		local, all := w.getInfoFromLinkedContainers(linkedToContainerUUID, linkedFromContainersMap)
		if len(local) > 0 {
			displayName := linkedToContainerUUID
			if linkedToContainer, ok := w.containersMapByUUID[linkedToContainerUUID]; ok {
				displayName = linkedToContainer.Name
			}
			ruleName := fmt.Sprintf("within.linked.linkedTo.%v", displayName)
			isStateful := true
			isDstSystem := false
			isSrcSystem := false
			r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = p.Action

			withinLinkedRulesMap[ruleName] = *r
		}
	}

	log.Debugf("withinLinkedRulesMap: %v", withinLinkedRulesMap)
	return withinLinkedRulesMap, nil
}

func buildLinkedMappingsForContainers(
	containers []metadata.Container) map[string]map[string]*metadata.Container {
	log.Debugf("buildLinkedMappingsForContainers")

	linkedContainersMap := make(map[string]map[string]*metadata.Container)

	for index, aContainer := range containers {
		if len(aContainer.Links) > 0 {
			for _, linkedContainerUUID := range aContainer.Links {
				if _, found := linkedContainersMap[linkedContainerUUID]; !found {
					linkedContainersMap[linkedContainerUUID] = make(map[string]*metadata.Container)
				}
				linkedContainersMap[linkedContainerUUID][aContainer.UUID] = &containers[index]
			}
		}
	}

	log.Debugf("linkedContainersMap: %v", linkedContainersMap)
	return linkedContainersMap
}

func (w *watcher) findLocalMatchingServices(remoteLB string, lb metadata.Service, match *map[string]map[string]*metadata.Service) {
	//log.Debugf("finding local matching services for lb: %v", lb)
	for _, aService := range w.services {
		if aService.System {
			continue
		}
		//log.Debugf("checking for match service: %v", aService.Name)
		for _, aPortRule := range lb.LBConfig.PortRules {
			if aPortRule.Selector == "" {
				continue
			}

			if (aPortRule.Region != "" && aPortRule.Region != w.regionName) ||
				(aPortRule.Environment != "" && aPortRule.Environment != w.name) {
				continue
			}

			if selutil.IsSelectorMatch(aPortRule.Selector, aService.Labels) {
				log.Debugf("sel: %v, match service: %v", aPortRule.Selector, aService.Name)
				key := aService.StackName + "/" + aService.Name
				if _, found := (*match)[key]; !found {
					(*match)[key] = make(map[string]*metadata.Service)
				}
				lbKey := lb.StackName + "/" + lb.Name
				if remoteLB != "" {
					lbKey = remoteLB
				}
				(*match)[key][lbKey] = &lb
			}
		}
	}

	log.Debugf("localMatchingServices for lb[%v]: %v", lb.Name, match)
}

func (w *watcher) findRemoteMatchingServices(lb metadata.Service, match *map[string]map[string]*metadata.Service) {
	//log.Debugf("finding local matching services for lb: %v", lb)
	for _, aEnv := range w.environments {
		for _, aService := range aEnv.Services {
			if aService.System {
				continue
			}
			//log.Debugf("checking for match service: %v", aService.Name)
			for _, aPortRule := range lb.LBConfig.PortRules {
				if aPortRule.Selector == "" {
					continue
				}

				if (aPortRule.Region != "" && aPortRule.Region != aEnv.RegionName) ||
					(aPortRule.Environment != "" && aPortRule.Environment != aEnv.Name) {
					continue
				}

				if selutil.IsSelectorMatch(aPortRule.Selector, aService.Labels) {
					log.Debugf("sel: %v, match service: %v", aPortRule.Selector, aService.Name)
					key := aEnv.RegionName + "/" + aEnv.Name + "/" + aService.StackName + "/" + aService.Name
					if _, found := (*match)[key]; !found {
						(*match)[key] = make(map[string]*metadata.Service)
					}
					(*match)[key][lb.StackName+"/"+lb.Name] = &lb
				}
			}
		}
	}

	log.Debugf("remoteMatchingServices for lb[%v]: %v", lb.Name, match)
}

func (w *watcher) buildLBSelectorMappings(linkedServiceMapPtr *map[string]map[string]*metadata.Service) {
	// Walk through current env services to find lb services
	var localLBServices []*metadata.Service
	for index, aService := range w.services {
		if aService.Kind != "loadBalancerService" {
			continue
		}
		log.Debugf("found local lb: %v", aService.Name)
		localLBServices = append(localLBServices, &w.services[index])
	}
	log.Debugf("localLBServices: %v", localLBServices)

	// Find selector matching services in local and remote env
	for _, aLBService := range localLBServices {
		w.findLocalMatchingServices("", *aLBService, linkedServiceMapPtr)
		w.findRemoteMatchingServices(*aLBService, linkedServiceMapPtr)
	}

	// Walk through remote env services to find lb services
	remoteLBServices := make(map[string]*metadata.Service)
	for envIndex, aRemoteEnv := range w.environments {
		for index, aService := range aRemoteEnv.Services {
			if aService.Kind != "loadBalancerService" {
				continue
			}
			log.Debugf("found remote lb: %v", aService.Name)
			lbKey := aRemoteEnv.RegionName + "/" + aRemoteEnv.Name + "/" + aService.StackName + "/" + aService.Name
			remoteLBServices[lbKey] = &w.environments[envIndex].Services[index]
		}
	}
	log.Debugf("remoteLBServices: %v", remoteLBServices)

	// Find selector matching services in current env
	for k, aRemoteLB := range remoteLBServices {
		w.findLocalMatchingServices(k, *aRemoteLB, linkedServiceMapPtr)
	}
}

func (w *watcher) buildLinkedMappings() map[string]map[string]*metadata.Service {
	log.Debugf("buildLinkedMappings")
	linkedServicesMap := make(map[string]map[string]*metadata.Service)

	for index, service := range w.services {
		if service.System || len(service.Links) == 0 {
			continue
		}
		//log.Debugf("service: %v", service)
		log.Debugf("service:%v service.Links: %v", service.Name, service.Links)
		for linkedService := range service.Links {
			//log.Debugf("linkedService='%v'", linkedService)
			if linkedService == "" {
				continue
			}
			linkedServiceLowerCase := strings.ToLower(linkedService)
			if _, found := linkedServicesMap[linkedServiceLowerCase]; !found {
				linkedServicesMap[linkedServiceLowerCase] = make(map[string]*metadata.Service)
			}
			sKey := service.StackName + "/" + service.Name
			linkedServicesMap[linkedServiceLowerCase][sKey] = &w.services[index]
		}
	}

	if w.regionName != "" {
		for _, aEnv := range w.environments {
			for index, aService := range aEnv.Services {
				if aService.System || len(aService.Links) == 0 {
					continue
				}
				//log.Debugf("aService: %v", aService)
				log.Debugf("aService: %v aService.Links: %v", aService.Name, aService.Links)
				for linkedService := range aService.Links {
					//log.Debugf("linkedService='%v'", linkedService)
					if linkedService == "" {
						continue
					}

					if !isCrossRegionLink(linkedService) {
						continue
					}

					isLocal, localLink := w.covertToLocalLink(linkedService)
					if !isLocal {
						log.Debugf("linkedService: %v not local", linkedService)
						continue
					}

					linkedServiceLowerCase := strings.ToLower(localLink)
					if _, found := linkedServicesMap[linkedServiceLowerCase]; !found {
						linkedServicesMap[linkedServiceLowerCase] = make(map[string]*metadata.Service)
					}
					sKey := aEnv.RegionName + "/" + aEnv.Name + "/" + aService.StackName + "/" + aService.Name
					linkedServicesMap[linkedServiceLowerCase][sKey] = &aEnv.Services[index]
				}

			}
		}
	}

	w.buildLBSelectorMappings(&linkedServicesMap)

	log.Debugf("linkedServicesMap: %v", linkedServicesMap)
	return linkedServicesMap
}

func isCrossRegionLink(link string) bool {
	return (strings.Count(link, "/") > 1)
}

// Valid local links:
// localRegionName/envName/stackName/serviceName
// envName/stackName/serviceName
func (w *watcher) covertToLocalLink(link string) (bool, string) {
	words := strings.Split(link, "/")
	if len(words) == 4 {
		splits := strings.SplitAfter(link, w.regionName+"/"+w.name+"/")
		//log.Debugf("splits: %v", splits)
		if len(splits) != 2 {
			return true, splits[1]
		}
	} else if len(words) == 3 {
		splits := strings.SplitAfter(link, w.name+"/")
		//log.Debugf("splits: %v", splits)
		if len(splits) == 2 {
			return true, splits[1]
		}
	}
	return false, ""
}

func (w *watcher) withinPolicyHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	log.Debugf("withinPolicyHandler: %v", p)
	if p.Within == StrStack {
		return w.withinStackHandler(p)
	} else if p.Within == StrService {
		return w.withinServiceHandler(p)
	} else if p.Within == StrLinked {
		return w.withinLinkedHandler(p)
	}

	return nil, fmt.Errorf("invalid option for within")
}

func (w *watcher) groupByHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	log.Debugf("groupByHandler")

	betweenGroupByRulesMap := make(map[string]Rule)
	groupByMap := w.getContainersGroupedBy(p.Between.GroupBy)
	for labelValue, localAllMap := range groupByMap {
		local := localAllMap["local"]
		all := localAllMap["all"]

		if len(local) > 0 {
			ruleName := fmt.Sprintf("between.%v.%v", p.Between.GroupBy, labelValue)
			isStateful := false
			isDstSystem := false
			isSrcSystem := false
			r, err := w.buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = p.Action
			betweenGroupByRulesMap[ruleName] = *r
		}
	}
	return betweenGroupByRulesMap, nil
}

func (w *watcher) betweenPolicyHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	log.Debugf("betweenPolicyHandler")

	if p.Between.GroupBy != "" {
		return w.groupByHandler(p)
	}

	return nil, nil
}

func (w *watcher) translatePolicy(np *NetworkPolicy) error {

	w.ipsets = make(map[string]map[string]bool)
	w.ipsetsNamesMap = make(map[string]string)
	w.rules = make(map[int]map[string]Rule)

	index := 0

	if np.Rules != nil && len(np.Rules) > 0 {

		r, err := w.defaultSystemStackPolicies()
		if err != nil {
			log.Errorf("error translating default system Rules: %v", err)
			return err
		}
		w.rules[index] = r
		index++

		for _, p := range np.Rules {
			log.Debugf("Working on: p:%#v", p)

			// within Handler
			if p.Within != "" {
				r, err := w.withinPolicyHandler(p)
				if err != nil {
					log.Errorf("error: %v", err)
				} else {
					w.rules[index] = r
				}
				index++
				continue
			}

			// between Handler
			if p.Between != nil {
				r, err := w.betweenPolicyHandler(p)
				if err != nil {
					log.Errorf("error: %v", err)
				} else {
					w.rules[index] = r
				}
				index++
				continue
			}

		}

		r, err = w.defaultPolicyAction(np.DefaultAction)
		if err != nil {
			log.Errorf("error translating default NetworkPolicy action: %v", err)
			return err
		}
		w.rules[index] = r
		index++
	} else {
		// Optimize for defaultPolicyAction: allow
		if np.DefaultAction == ActionDeny {

			r, err := w.defaultSystemStackPolicies()
			if err != nil {
				log.Errorf("error translating default system Rules: %v", err)
				return err
			}
			w.rules[index] = r
			index++

			r, err = w.defaultPolicyAction(np.DefaultAction)
			if err != nil {
				log.Errorf("error translating default NetworkPolicy action: %v", err)
				return err
			}
			w.rules[index] = r
			index++
		}
	}

	log.Debugf("w.rules: %#v", w.rules)
	log.Debugf("w.ipsets: %#v", w.ipsets)

	return nil
}

func (w *watcher) fetchInfoFromMetadata() error {
	regionName, err := w.c.GetRegionName()
	if err != nil {
		log.Debugf("couldn't get region name from metadata: %v", err)
	}
	log.Debugf("regionName: %v", regionName)

	environments, err := w.c.GetEnvironments()
	if err != nil {
		log.Errorf("error fetching environments: %v", err)
		return err
	}

	version, err := w.c.GetName()
	if err != nil {
		log.Errorf("Error getting current environment version from metadata: %v", err)
		return err
	}
	log.Debugf("version: %v", version)

	name, err := w.c.GetName()
	if err != nil {
		log.Errorf("Error getting current environment name from metadata: %v", err)
		return err
	}
	log.Debugf("name: %v", name)

	stacks, err := w.c.GetStacks()
	if err != nil {
		log.Errorf("Error getting stacks from metadata: %v", err)
		return err
	}

	services, err := w.c.GetServices()
	if err != nil {
		log.Errorf("Error getting services from metadata: %v", err)
		return err
	}

	containers, err := w.c.GetContainers()
	if err != nil {
		log.Errorf("Error getting containers from metadata: %v", err)
		return err
	}

	containersMapByUUID := make(map[string]*metadata.Container)
	for index, aContainer := range containers {
		key := aContainer.UUID
		containersMapByUUID[key] = &containers[index]
	}

	selfHost, err := w.c.GetSelfHost()
	if err != nil {
		log.Errorf("Couldn't get self host from metadata: %v", err)
		return err
	}

	servicesMapByName := make(map[string]*metadata.Service)
	for _, aStack := range stacks {
		if aStack.System {
			continue
		}
		for index, aService := range aStack.Services {
			key := aStack.Name + "/" + aService.Name
			servicesMapByName[key] = &aStack.Services[index]
			if regionName != "" {
				regionKey := regionName + "/" + name + "/" + aStack.Name + "/" + aService.Name
				servicesMapByName[regionKey] = &aStack.Services[index]
			}
		}
	}

	if regionName != "" {
		for _, aEnv := range environments {
			for _, aStack := range aEnv.Stacks {
				if aStack.System {
					continue
				}
				for index, aService := range aStack.Services {
					key := aEnv.RegionName + "/" + aEnv.Name + "/" + aStack.Name + "/" + aService.Name
					servicesMapByName[key] = &aStack.Services[index]
					if aEnv.RegionName == regionName {
						localEnvKey := aEnv.Name + "/" + aStack.Name + "/" + aService.Name
						servicesMapByName[localEnvKey] = &aStack.Services[index]
					}
				}
			}
		}
	}
	log.Debugf("servicesMapByName: %v", servicesMapByName)

	w.selfHost = &selfHost
	w.stacks = stacks
	w.services = services
	w.containers = containers
	w.containersMapByUUID = containersMapByUUID
	w.servicesMapByName = servicesMapByName
	w.name = name
	w.regionName = regionName
	w.environments = environments

	if err = w.fetchNetworkInfo(); err != nil {
		log.Errorf("error fetching network info: %v", err)
		return err
	}

	return nil
}

func (w *watcher) onChange(version string) error {
	log.Debugf("onChange version: %v", version)
	var err error

	err = w.fetchInfoFromMetadata()
	if err != nil {
		log.Errorf("error fetching information from metadata: %v", err)
		return err
	}

	log.Debugf("Policy: %#v", w.defaultNetwork.Policy)

	curNetworkPolicy, err := NewNetworkPolicy(w.defaultNetwork)
	if err != nil {
		log.Errorf("error creating network policy: %v", err)
		return err
	}

	err = w.translatePolicy(curNetworkPolicy)
	if err != nil {
		log.Errorf("Error translating policy: %v", err)
		return err
	}

	// Need to process ipsets first as we reference
	// the set names later in the iptables rules.

	if !reflect.DeepEqual(w.appliedIPsets, w.ipsets) {
		log.Infof("Applying new ipsets")

		err := w.refreshIpsets()
		if err != nil {
			log.Errorf("error refreshing ipsets: %v", err)
			return err
		}

	} else {
		log.Debugf("No change in ipsets")
	}

	if !reflect.DeepEqual(w.appliedRules, w.rules) {
		log.Infof("Applying new rules")

		err := w.applyIptablesRules(w.rules)
		if err != nil {
			log.Errorf("Error applying iptables rules: %v", err)
			return err
		}

		w.appliedRules = w.rules
	} else {
		log.Debugf("No change in applied rules")
	}

	if !reflect.DeepEqual(w.appliedIPsets, w.ipsets) {
		if err := w.cleanupIpsets(); err != nil {
			log.Errorf("Error cleaning ipsets: %v", err)
		}
		w.appliedIPsets = w.ipsets
	}

	w.appliednp = curNetworkPolicy

	if log.GetLevelString() == "debug" {
		w.printIpsetsMapping()
	}

	return nil
}

func (w *watcher) printIpsetsMapping() {
	log.Debugf("ipsets names mapping: ")
	for k, v := range w.ipsetsNamesMap {
		log.Debugf("%v -> %v", k, v)
	}
}

func (w *watcher) refreshIpsets() error {
	log.Debugf("refreshing ipsets")

	var result error
	for ipsetName, ipset := range w.ipsets {
		oldipset := w.appliedIPsets[ipsetName]
		if !reflect.DeepEqual(ipset, oldipset) {
			log.Debugf("refreshing ipset: %v", ipsetName)
			tmpIPSetName := "TMP-" + ipsetName
			if existsIPSet(tmpIPSetName) {
				deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpIPSetName)
				if err := executeCommand(deleteCmdStr); err != nil {
					log.Errorf("error executing '%v': %v", deleteCmdStr, err)
					result = multierror.Append(result, err)
				}
			}
			if err := createIPSet(tmpIPSetName, ipset); err != nil {
				log.Errorf("error creating ipset: %v", err)
				result = multierror.Append(result, err)
				continue
			}
			if existsIPSet(ipsetName) {
				swapCmdStr := fmt.Sprintf("ipset swap %s %s", tmpIPSetName, ipsetName)
				if err := executeCommand(swapCmdStr); err != nil {
					log.Errorf("error executing '%v': %v", swapCmdStr, err)
					result = multierror.Append(result, err)
				}

				deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpIPSetName)
				if err := executeCommand(deleteCmdStr); err != nil {
					log.Errorf("error executing '%v': %v", deleteCmdStr, err)
					result = multierror.Append(result, err)
				}
			} else {
				renameCmdStr := fmt.Sprintf("ipset rename %s %s", tmpIPSetName, ipsetName)
				if err := executeCommand(renameCmdStr); err != nil {
					log.Errorf("error executing '%v': %v", renameCmdStr, err)
					result = multierror.Append(result, err)
				}
			}

		}
	}

	return result
}

func (w *watcher) cleanupIpsets() error {
	log.Debugf("ipsets cleanup")

	var result error
	for ipsetName := range w.appliedIPsets {
		_, existsInNew := w.appliedIPsets[ipsetName]
		if !existsInNew {
			log.Debugf("ipset: %v doesn't exist in new map, hence deleting ", ipsetName)
			deleteCmdStr := fmt.Sprintf("ipset destroy %s", ipsetName)
			if err := executeCommand(deleteCmdStr); err != nil {
				log.Errorf("error executing '%v': %v", deleteCmdStr, err)
				result = multierror.Append(result, err)
			}
		}
	}

	cmd := "ipset -L | grep -B5 'References: 0' | grep 'Name: RNCH-'  | awk '{print $2}'"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		log.Errorf("Failed to execute command: %s", cmd)
		return err
	}

	if len(out) > 0 {
		staleIPSets := strings.Split(string(out), "\n")
		log.Debugf("staleIPSets: %v", staleIPSets)

		if staleIPSets != nil && len(staleIPSets) > 0 {
			for _, ipset := range staleIPSets {
				if ipset == "" {
					continue
				}
				deleteCmdStr := fmt.Sprintf("ipset destroy %s", ipset)
				if err := executeCommand(deleteCmdStr); err != nil {
					log.Errorf("error executing '%v': %v", deleteCmdStr, err)
					result = multierror.Append(result, err)
				}
			}
		}
	}

	return result
}

func (w *watcher) applyIptablesRules(rulesMap map[int]map[string]Rule) error {
	buf := &bytes.Buffer{}
	buf.WriteString("*filter\n")
	buf.WriteString(fmt.Sprintf(":%s -\n", cattleNetworkPolicyChainName))

	for i := 0; i < len(rulesMap); i++ {
		rules, ok := rulesMap[i]
		if !ok {
			log.Errorf("not expecting error here for i: %v", i)
			continue
		}

		for ruleName, rule := range rules {
			log.Debugf("ruleName: %v, rule: %v", ruleName, rule)
			buf.Write(rule.iptables(w.defaultNetwork.DefaultPolicyAction))
		}
	}

	buf.WriteString("\nCOMMIT\n")

	if log.GetLevelString() == "debug" {
		fmt.Printf("Applying rules\n%s", buf)
	}

	cmd := exec.Command("iptables-restore", "-n")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = buf
	if err := cmd.Run(); err != nil {
		log.Errorf("Failed to apply rules\n%s", buf)
		return err
	}

	if err := w.insertBaseRules(); err != nil {
		return errors.Wrap(err, "Applying base iptables rules")
	}

	return nil
}

func (w *watcher) run(args ...string) error {
	log.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (w *watcher) insertBaseRules() error {
	checkRule := fmt.Sprintf("iptables -w -C %v -d %v -s %v -j %v",
		hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
	if executeCommandNoStderr(checkRule) != nil {
		addRule := fmt.Sprintf("iptables -w -I %v -d %v -s %v -j %v",
			hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
		return executeCommand(addRule)
	}
	return nil
}

func (w *watcher) deleteBaseRules() error {
	checkRule := fmt.Sprintf("iptables -w -C %v -d %v -s %v -j %v",
		hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
	if executeCommandNoStderr(checkRule) == nil {
		delRule := fmt.Sprintf("iptables -w -D %v -d %v -s %v -j %v",
			hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
		return executeCommand(delRule)
	}
	return nil
}

func (w *watcher) flushAndDeleteChain() error {
	checkRule := fmt.Sprintf("iptables -w -L %v", cattleNetworkPolicyChainName)
	if executeCommandNoStderr(checkRule) == nil {
		if err := w.run("iptables", "-w", "-F", cattleNetworkPolicyChainName); err != nil {
			log.Errorf("Error flushing the chain: %v", cattleNetworkPolicyChainName)
			return err
		}

		if err := w.run("iptables", "-X", cattleNetworkPolicyChainName); err != nil {
			log.Errorf("Error deleting the chain: %v", cattleNetworkPolicyChainName)
			return err
		}
	}

	return nil
}

func (w *watcher) cleanup() error {
	log.Debugf("Doing cleanup")
	// delete the base Rule
	if err := w.deleteBaseRules(); err != nil {
		log.Errorf("error deleting base rules: %v", err)
		return err
	}

	// Flush and delete the chain
	if err := w.flushAndDeleteChain(); err != nil {
		log.Errorf("error flusing and deleting chain: %v", err)
		return err
	}

	// remove the ipsets
	if err := w.cleanupIpsets(); err != nil {
		log.Errorf("Error cleaning ipsets: %v", err)
		return err
	}

	return nil
}

func existsIPSet(name string) bool {
	checkCmdStr := fmt.Sprintf("ipset list %s -name", name)
	err := executeCommandNoStdoutNoStderr(checkCmdStr)

	return err == nil
}

func createIPSet(name string, ips map[string]bool) error {
	var result error
	createStr := fmt.Sprintf("ipset create %s iphash", name)
	if err := executeCommand(createStr); err != nil {
		return err
	}

	for ip := range ips {
		addIPStr := fmt.Sprintf("ipset add %s %s", name, ip)
		if err := executeCommand(addIPStr); err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}
