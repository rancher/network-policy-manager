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

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/hashstructure"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher-metadata/metadata"
)

const (
	// TODO: Having contention with hostports iptables rules logic
	// Discuss with @ibuildthecloud, fix it for 1.5
	//hookToChain = "CATTLE_FORWARD"
	hookToChain                  = "FORWARD"
	cattleNetworkPolicyChainName = "CATTLE_NETWORK_POLICY"
	cattleNetworkPolicyChainNameOut = "CATTLE_NETWORK_POLICY_OUT"
	ipsetNameMaxLength           = 26
)

type watcher struct {
	c                   metadata.Client
	lastApplied         time.Time
	doCleanup           bool
	shutdownInProgress  bool
	signalCh            chan os.Signal
	exitCh              chan int
	defaultNetwork      *metadata.Network
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
}

// Rule is used to store the info need to be a iptables rule
type Rule struct {
	dst        string
	src        string
	ports      []string
	isStateful bool
	action     string
	system     bool
	chain			 string
}

func setupKernelParameters() error {
	cmd := "sysctl -w net.bridge.bridge-nf-call-iptables=1"
	return executeCommandNoStdoutNoStderr(cmd)
}

func (rule *Rule) iptables(defaultPolicyAction string) []byte {
	buf := &bytes.Buffer{}
	var ruleTarget string
	chain := cattleNetworkPolicyChainName
	if(rule.chain != ""){
		chain = rule.chain
	}

	// TODO: Check for ports etc

	if rule.isStateful {
		buf.WriteString(fmt.Sprintf("-A %v ", chain))
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
		buf.WriteString(fmt.Sprintf("-A %v ", chain))
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
		buf.WriteString(fmt.Sprintf("-A %v ", chain))
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
		logrus.Errorf("Error setting up needed kernel parameters: %v", err)
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

	if err := w.insertChainOut(); err != nil {
		return errors.Wrap(err, "Applying base iptables chain out")
	}


	go w.shutdown()
	go c.OnChange(5, w.onChangeNoError)
	return nil
}

func (w *watcher) shutdown() {
	<-w.signalCh
	logrus.Infof("Got shutdown signal")

	w.shutdownInProgress = true

	// This is probably a good place to add clean up logic
	if w.doCleanup {
		w.cleanup()
	}

	w.exitCh <- 0
}

func (w *watcher) onChangeNoError(version string) {
	logrus.Debugf("onChangeNoError version: %v", version)
	if w.shutdownInProgress {
		logrus.Infof("Shutdown in progress, no more processing")
		return
	}

	if err := w.onChange(version); err != nil {
		logrus.Errorf("Failed to apply network NetworkPolicy: %v", err)
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

func (w *watcher) getDefaultNetwork() (*metadata.Network, error) {
	networks, err := w.c.GetNetworks()
	if err != nil {
		return nil, err
	}

	for _, n := range networks {
		if n.Default {
			return &n, nil
		}
	}

	return nil, fmt.Errorf("Couldn't find default network")
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
	logrus.Debugf("getting containers grouped by: %v", label)
	groupByMap := make(map[string]map[string]map[string]bool)

	for _, aContainer := range w.containers {
		if aContainer.System {
			continue
		}
		if aContainer.NetworkUUID == w.defaultNetwork.UUID {
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

	logrus.Debugf("groupByMap: %v", groupByMap)
	return groupByMap
}

// This function returns IP addresses of local and all containers of the stack
// on the default network
func (w *watcher) getInfoFromStack(stack metadata.Stack) (map[string]bool, map[string]bool) {
	local := make(map[string]bool)
	all := make(map[string]bool)
	for _, aService := range stack.Services {
		for _, aContainer := range aService.Containers {
			if aContainer.NetworkUUID == w.defaultNetwork.UUID {
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
	logrus.Debugf("getInfoFromService service: %v", service)
	local := make(map[string]bool)
	all := make(map[string]bool)

	// This means it's a sidekick service, it will handled as part of the
	// primary service, so skipping here.
	if service.Name != service.PrimaryServiceName {
		logrus.Debugf("service: %v is sidekick, skipping", service.Name)
		return local, all
	}

	for _, aContainer := range service.Containers {
		if aContainer.NetworkUUID == w.defaultNetwork.UUID {
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
		logrus.Debugf("aSKServiceNameLowerCase: %v", aSKServiceNameLowerCase)
		fullSKServiceName := service.StackName + "/" + aSKServiceNameLowerCase
		sidekickService, found := w.servicesMapByName[fullSKServiceName]
		if !found {
			logrus.Errorf("unable to find sidekick service: %v", fullSKServiceName)
			continue
		}

		for _, aContainer := range sidekickService.Containers {
			if aContainer.NetworkUUID == w.defaultNetwork.UUID {
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
	logrus.Debugf("getInfoFromLinkedContainers")

	var dst, src map[string]bool
	linkedToLocal := make(map[string]bool)
	linkedToAll := make(map[string]bool)
	linkedFromLocal := make(map[string]bool)
	linkedFromAll := make(map[string]bool)

	linkedToContainer, ok := w.containersMapByUUID[linkedToContainerUUID]
	if !ok {
		logrus.Errorf("error finding container by name: %v", linkedToContainerUUID)
		return dst, src
	}
	logrus.Debugf("linkedToContainer: %+v", linkedToContainer)

	if linkedToContainer.PrimaryIp != "" {
		if linkedToContainer.HostUUID == w.selfHost.UUID {
			linkedToLocal[linkedToContainer.PrimaryIp] = true
		}
		linkedToAll[linkedToContainer.PrimaryIp] = true
	}

	for _, linkedFromContainer := range linkedFromContainersMap {
		logrus.Debugf("linkedFromContainer: %+v", linkedFromContainer)
		if linkedFromContainer.PrimaryIp != "" {
			if linkedFromContainer.HostUUID == w.selfHost.UUID {
				linkedFromLocal[linkedFromContainer.PrimaryIp] = true
			}
			linkedFromAll[linkedFromContainer.PrimaryIp] = true
		}
	}

	logrus.Debugf("linkedToLocal: %v", linkedToLocal)
	logrus.Debugf("linkedToAll: %v", linkedToAll)
	logrus.Debugf("linkedFromLocal: %v", linkedFromLocal)
	logrus.Debugf("linkedFromAll: %v", linkedFromAll)

	if len(linkedToLocal) > 0 {
		dst = linkedToLocal
		src = linkedFromAll
	} else {
		if len(linkedFromLocal) > 0 {
			dst = linkedToAll
			src = linkedFromLocal
		}
	}

	logrus.Debugf("dst: %v", dst)
	logrus.Debugf("src: %v", src)
	return dst, src
}

//This function returns IP addresses of external services defined in the stack
func (w *watcher) getExtInfoFromStack(stack metadata.Stack) (map[string]bool, map[string]bool) {
	local := make(map[string]bool)
	all := make(map[string]bool)
	for _, aService := range stack.Services {
		if aService.Kind == "externalService" {
			for _, extIP := range aService.ExternalIps {
				if extIP != "" {
					local[extIP] = true
				}
			}
		}
		for _, aContainer := range aService.Containers {
			if aContainer.NetworkUUID == w.defaultNetwork.UUID {
				if aContainer.HostUUID == w.selfHost.UUID {
					if aContainer.PrimaryIp != "" {
						all[aContainer.PrimaryIp] = true
					}
				}
			}
		}

	}
	return local, all
}

// This function returns IP addresses of dst and src containers of the linkedTo service
// on the default network
func (w *watcher) getInfoFromLinkedServices(
	linkedTo string, linkedFromMap map[string]*metadata.Service) (
	map[string]bool, map[string]bool) {
	logrus.Debugf("getInfoFromLinkedServices")

	var dst, src map[string]bool

	linkedToService, ok := w.servicesMapByName[linkedTo]
	if !ok {
		logrus.Errorf("error finding service by name: %v", linkedTo)
		return nil, nil
	}
	linkedToLocal, linkedToAll := w.getInfoFromService(*linkedToService)
	logrus.Debugf("linkedToLocal: %v", linkedToLocal)
	logrus.Debugf("linkedToAll: %v", linkedToAll)

	linkedFromAll := make(map[string]bool)
	for _, aLinkedFromService := range linkedFromMap {
		fromLocal, fromAll := w.getInfoFromService(*aLinkedFromService)
		logrus.Debugf("fromLocal: %v", fromLocal)
		logrus.Debugf("fromAll: %v", fromAll)

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

	logrus.Debugf("dst: %v", dst)
	logrus.Debugf("src: %v", src)
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
		if aContainer.NetworkUUID == w.defaultNetwork.UUID {
			if aContainer.HostUUID == w.selfHost.UUID {
				if aContainer.PrimaryIp != "" {
					all[aContainer.PrimaryIp] = true
				}
			}
		}
	}

	logrus.Debugf("all local containers: %v", all)
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

	logrus.Debugf("defPolicyActionMap: %v", defPolicyActionMap)
	return defPolicyActionMap, nil
}

func (w *watcher) defaultPolicyActionOut(action string) (map[string]Rule, error) {
	defPolicyActionMap := make(map[string]Rule)

	ruleName := "all.local.containers.out"
	all := w.getAllLocalContainers()
	isStateful := false
	r, err := w.buildAndProcessRuleWithSrcDstExt(isStateful, ruleName, nil, all)
	if err != nil {
		return nil, err
	}
	r.action = action
	defPolicyActionMap[ruleName] = *r

	logrus.Debugf("defPolicyActionMap: %v", defPolicyActionMap)
	return defPolicyActionMap, nil
}

func (w *watcher) defaultSystemStackPolicies() (map[string]Rule, error) {
	defSysRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		if !stack.System {
			continue
		}

		local, all := w.getInfoFromStack(stack)
		if len(all) > 0 {
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
		if len(local) > 0 {
			ruleName := fmt.Sprintf("ex.fr.system.stack.%v", stack.Name)
			isStateful := false
			r, err := w.buildAndProcessRuleWithSrcDstExt(isStateful, ruleName, nil, local)
			if err != nil {
				return nil, err
			}
			r.action = ActionAllow
			defSysRulesMap[ruleName] = *r
		}
	}

	logrus.Debugf("defSysRulesMap: %v", defSysRulesMap)
	return defSysRulesMap, nil
}

// This function generates ipsets of ips within stacks
func (w *watcher) withinStackAnalyzer() (map[string]Rule, error){
	logrus.Debugf("withinStackAnalyzer")
	withinStackRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		if stack.System {
			continue
		}
		local,all := w.getExtInfoFromStack(stack)
		if len(local) > 0 && len(all) > 0 {
			ruleName := fmt.Sprintf("within.stack.ex.%v", stack.Name)
			isStateful := false
			r, err := w.buildAndProcessRuleWithSrcDstExt(isStateful, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = ActionAllow

			withinStackRulesMap[ruleName] = *r
		} else {
			logrus.Debugf("stack: %v doesn't have any local containers, skipping", stack.Name)
			continue
		}
	}

	logrus.Debugf("withinStackRulesMap: %v", withinStackRulesMap)
	return withinStackRulesMap, nil

}

func (w *watcher) withinStackHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinStackHandler")
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
			logrus.Debugf("stack: %v doesn't have any local containers, skipping", stack.Name)
			continue
		}
	}

	logrus.Debugf("withinStackRulesMap: %v", withinStackRulesMap)
	return withinStackRulesMap, nil
}

func (w *watcher) buildAndProcessRuleWithSrcDstExt(isStateful bool, ruleName string, local, all map[string]bool) (*Rule, error) {
	var err error
	var srcSetName, dstSetName, hashedDstSetName, hashedSrcSetName string

	// process external ips, defined in the stack
	if local != nil {
		dstSetName = fmt.Sprintf("dst.e.%v", ruleName)
		hashedDstSetName, err = w.generateHash(dstSetName)
		if err != nil {
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}
		hashedDstSetName = "RNCH-UE-" + hashedDstSetName


		if len(hashedDstSetName) > ipsetNameMaxLength {
			logrus.Errorf("length of ipset names exceeded %v. hashedDstSetName: %v", ipsetNameMaxLength, hashedDstSetName)
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

	// process container ips, defined in the stack
	if all != nil {

		srcSetName = fmt.Sprintf("src.e.%v", ruleName)
		hashedSrcSetName, err = w.generateHash(srcSetName)
		if err != nil {
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}
		hashedSrcSetName = "RNCH-UE-" + hashedSrcSetName

		if len(hashedSrcSetName) > ipsetNameMaxLength {
			logrus.Errorf("length of ipset names exceeded %v. hashedSrcSetName: %v", ipsetNameMaxLength, hashedSrcSetName)
			hashedSrcSetName = hashedSrcSetName[0 : ipsetNameMaxLength-1]
		}
		if existingSet, exists := w.ipsets[hashedSrcSetName]; exists {
			if !reflect.DeepEqual(existingSet, all) {
				logrus.Errorf("%v: mismatch existingSet: %v all:%v", hashedSrcSetName, existingSet, all)
			}
		} else {
			w.ipsets[hashedSrcSetName] = all
			w.ipsetsNamesMap[hashedSrcSetName] = srcSetName
		}
	}
	logrus.Debugf("dst: %v (%v) src: %v (%v)", hashedDstSetName, dstSetName, hashedSrcSetName, srcSetName)

	r := &Rule{dst: hashedDstSetName,
		src:        hashedSrcSetName,
		isStateful: isStateful,
		chain: cattleNetworkPolicyChainNameOut,
	}

	return r, nil
}

func (w *watcher) buildAndProcessRuleWithSrcDst(isStateful, isDstSystem, isSrcSystem bool, ruleName string, local, all map[string]bool) (*Rule, error) {
	var err error
	var srcSetName, dstSetName, hashedDstSetName, hashedSrcSetName string

	if local != nil {
		dstSetName = fmt.Sprintf("dst.%v", ruleName)
		hashedDstSetName, err = w.generateHash(dstSetName)
		if err != nil {
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}

		if isDstSystem {
			hashedDstSetName = "RNCH-S-" + hashedDstSetName
		} else {
			hashedDstSetName = "RNCH-U-" + hashedDstSetName
		}

		if len(hashedDstSetName) > ipsetNameMaxLength {
			logrus.Errorf("length of ipset names exceeded %v. hashedDstSetName: %v", ipsetNameMaxLength, hashedDstSetName)
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
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}
		if isSrcSystem {
			hashedSrcSetName = "RNCH-S-" + hashedSrcSetName
		} else {
			hashedSrcSetName = "RNCH-U-" + hashedSrcSetName
		}
		if len(hashedSrcSetName) > ipsetNameMaxLength {
			logrus.Errorf("length of ipset names exceeded %v. hashedSrcSetName: %v", ipsetNameMaxLength, hashedSrcSetName)
			hashedSrcSetName = hashedSrcSetName[0 : ipsetNameMaxLength-1]
		}
		if existingSet, exists := w.ipsets[hashedSrcSetName]; exists {
			if !reflect.DeepEqual(existingSet, all) {
				logrus.Errorf("%v: mismatch existingSet: %v all:%v", hashedSrcSetName, existingSet, all)
			}
		} else {
			w.ipsets[hashedSrcSetName] = all
			w.ipsetsNamesMap[hashedSrcSetName] = srcSetName
		}
	}

	logrus.Debugf("dst: %v (%v) src: %v (%v)", hashedDstSetName, dstSetName, hashedSrcSetName, srcSetName)

	r := &Rule{dst: hashedDstSetName,
		src:        hashedSrcSetName,
		isStateful: isStateful,
	}

	return r, nil
}

func (w *watcher) withinServiceHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinServiceHandler")
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
			logrus.Debugf("service: %v doesn't have any local containers, skipping", service.Name)
			continue
		}
	}

	logrus.Debugf("withinServiceRulesMap: %v", withinServiceRulesMap)
	return withinServiceRulesMap, nil
}

func (w *watcher) withinLinkedHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinLinkedHandler")
	withinLinkedRulesMap := make(map[string]Rule)

	linkedMappings := buildLinkedMappings(w.services)

	for linkedTo, linkedFromMap := range linkedMappings {
		logrus.Debugf("linkedTo: %v, linkedFromMap: %v", linkedTo, linkedFromMap)

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
			logrus.Debugf("linked service: %v doesn't have any local containers, skipping", linkedTo)
			continue
		}
	}

	// Process links of standalone containers
	linkedContainersMap := buildLinkedMappingsForContainers(w.containers)
	for linkedToContainerUUID, linkedFromContainersMap := range linkedContainersMap {
		logrus.Debugf("linkedToContainerUUID: %v, linkedFromContainersMap: %v", linkedToContainerUUID, linkedFromContainersMap)

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

	logrus.Debugf("withinLinkedRulesMap: %v", withinLinkedRulesMap)
	return withinLinkedRulesMap, nil
}

func buildLinkedMappingsForContainers(
	containers []metadata.Container) map[string]map[string]*metadata.Container {
	logrus.Debugf("buildLinkedMappingsForContainers")

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

	logrus.Debugf("linkedContainersMap: %v", linkedContainersMap)
	return linkedContainersMap
}

func buildLinkedMappings(services []metadata.Service) map[string]map[string]*metadata.Service {
	logrus.Debugf("buildLinkedMappings")

	linkedServicesMap := make(map[string]map[string]*metadata.Service)

	for index, service := range services {
		if service.System || len(service.Links) == 0 {
			continue
		}
		//logrus.Debugf("service: %v", service)
		logrus.Debugf("service.Links: %v", service.Links)
		for linkedService := range service.Links {
			linkedServiceLowerCase := strings.ToLower(linkedService)
			if _, found := linkedServicesMap[linkedServiceLowerCase]; !found {
				linkedServicesMap[linkedServiceLowerCase] = make(map[string]*metadata.Service)
			}
			sKey := service.StackName + "/" + service.Name
			linkedServicesMap[linkedServiceLowerCase][sKey] = &services[index]
		}
	}

	logrus.Debugf("linkedServicesMap: %v", linkedServicesMap)
	return linkedServicesMap
}

func (w *watcher) withinPolicyHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinPolicyHandler: %v", p)
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
	logrus.Debugf("groupByHandler")

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
	logrus.Debugf("betweenPolicyHandler")

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
			logrus.Errorf("error translating default system Rules: %v", err)
			return err
		}
		w.rules[index] = r
		index++

		for _, p := range np.Rules {
			logrus.Debugf("Working on: p:%#v", p)

			// within Handler
			if p.Within != "" {
				r, err := w.withinPolicyHandler(p)
				if err != nil {
					logrus.Errorf("error: %v", err)
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
					logrus.Errorf("error: %v", err)
				} else {
					w.rules[index] = r
				}
				index++
				continue
			}

		}

		r,err = w.withinStackAnalyzer()
		if err != nil {
			logrus.Errorf("error translating default Stack Analyzer action: %v", err)
			return err
		}
		w.rules[index] = r
		index++

		r, err = w.defaultPolicyAction(np.DefaultAction)
		if err != nil {
			logrus.Errorf("error translating default NetworkPolicy action: %v", err)
			return err
		}
		w.rules[index] = r
		index++

		r, err = w.defaultPolicyActionOut(np.DefaultAction)
		if err != nil {
			logrus.Errorf("error translating default NetworkPolicy action: %v", err)
			return err
		}
		w.rules[index] = r
		index++
	} else {
		// Optimize for defaultPolicyAction: allow
		if np.DefaultAction == ActionDeny {

			r, err := w.defaultSystemStackPolicies()
			if err != nil {
				logrus.Errorf("error translating default system Rules: %v", err)
				return err
			}
			w.rules[index] = r
			index++

			r, err = w.defaultPolicyAction(np.DefaultAction)
			if err != nil {
				logrus.Errorf("error translating default NetworkPolicy action: %v", err)
				return err
			}
			w.rules[index] = r
			index++
		}
	}

	logrus.Debugf("w.rules: %#v", w.rules)
	logrus.Debugf("w.ipsets: %#v", w.ipsets)

	return nil
}

func (w *watcher) fetchInfoFromMetadata() error {
	stacks, err := w.c.GetStacks()
	if err != nil {
		logrus.Errorf("Error getting stacks from metadata: %v", err)
		return err
	}

	services, err := w.c.GetServices()
	if err != nil {
		logrus.Errorf("Error getting services from metadata: %v", err)
		return err
	}

	containers, err := w.c.GetContainers()
	if err != nil {
		logrus.Errorf("Error getting containers from metadata: %v", err)
		return err
	}

	containersMapByUUID := make(map[string]*metadata.Container)
	for index, aContainer := range containers {
		key := aContainer.UUID
		containersMapByUUID[key] = &containers[index]
	}

	selfHost, err := w.c.GetSelfHost()
	if err != nil {
		logrus.Errorf("Couldn't get self host from metadata: %v", err)
		return err
	}

	defaultNetwork, err := w.getDefaultNetwork()
	if err != nil {
		logrus.Errorf("Error while finding default network: %v", err)
		return err
	}
	logrus.Debugf("defaultNetwork: %#v", defaultNetwork)

	defaultSubnet, err := getBridgeSubnet(defaultNetwork)
	if err != nil {
		logrus.Errorf("Error while finding default subnet: %v", err)
		return err
	}
	logrus.Debugf("defaultSubnet: %#v", defaultSubnet)

	servicesMapByName := make(map[string]*metadata.Service)
	for _, aStack := range stacks {
		if aStack.System {
			continue
		}
		for index, aService := range aStack.Services {
			key := aStack.Name + "/" + aService.Name
			servicesMapByName[key] = &aStack.Services[index]
		}
	}
	logrus.Debugf("servicesMapByName: %v", servicesMapByName)

	w.defaultNetwork = defaultNetwork
	w.defaultSubnet = defaultSubnet
	w.selfHost = &selfHost
	w.stacks = stacks
	w.services = services
	w.containers = containers
	w.containersMapByUUID = containersMapByUUID
	w.servicesMapByName = servicesMapByName

	return nil
}

func (w *watcher) onChange(version string) error {
	logrus.Debugf("onChange version: %v", version)
	var err error

	err = w.fetchInfoFromMetadata()
	if err != nil {
		logrus.Errorf("error fetching information from metadata: %v", err)
		return err
	}

	logrus.Debugf("Policy: %#v", w.defaultNetwork.Policy)

	curNetworkPolicy, err := NewNetworkPolicy(w.defaultNetwork)
	if err != nil {
		logrus.Errorf("error creating network policy: %v", err)
		return err
	}

	err = w.translatePolicy(curNetworkPolicy)
	if err != nil {
		logrus.Errorf("Error translating policy: %v", err)
		return err
	}

	// Need to process ipsets first as we reference
	// the set names later in the iptables rules.

	if !reflect.DeepEqual(w.appliedIPsets, w.ipsets) {
		logrus.Infof("Applying new ipsets")

		err := w.refreshIpsets()
		if err != nil {
			logrus.Errorf("error refreshing ipsets: %v", err)
			return err
		}

	} else {
		logrus.Debugf("No change in ipsets")
	}

	if !reflect.DeepEqual(w.appliedRules, w.rules) {
		logrus.Infof("Applying new rules")

		err := w.applyIptablesRules(w.rules)
		if err != nil {
			logrus.Errorf("Error applying iptables rules: %v", err)
			return err
		}

		w.appliedRules = w.rules
	} else {
		logrus.Debugf("No change in applied rules")
	}

	if !reflect.DeepEqual(w.appliedIPsets, w.ipsets) {
		if err := w.cleanupIpsets(); err != nil {
			logrus.Errorf("Error cleaning ipsets: %v", err)
		}
		w.appliedIPsets = w.ipsets
	}

	w.appliednp = curNetworkPolicy

	if logrus.GetLevel() == logrus.DebugLevel {
		w.printIpsetsMapping()
	}

	return nil
}

func (w *watcher) printIpsetsMapping() {
	logrus.Debugf("ipsets names mapping: ")
	for k, v := range w.ipsetsNamesMap {
		logrus.Debugf("%v -> %v", k, v)
	}
}

func (w *watcher) refreshIpsets() error {
	logrus.Debugf("refreshing ipsets")

	var result error
	for ipsetName, ipset := range w.ipsets {
		oldipset := w.appliedIPsets[ipsetName]
		if !reflect.DeepEqual(ipset, oldipset) {
			logrus.Debugf("refreshing ipset: %v", ipsetName)
			tmpIPSetName := "TMP-" + ipsetName
			if existsIPSet(tmpIPSetName) {
				deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpIPSetName)
				if err := executeCommand(deleteCmdStr); err != nil {
					logrus.Errorf("error executing '%v': %v", deleteCmdStr, err)
					result = multierror.Append(result, err)
				}
			}
			if err := createIPSet(tmpIPSetName, ipset); err != nil {
				logrus.Errorf("error creating ipset: %v", err)
				result = multierror.Append(result, err)
				continue
			}
			if existsIPSet(ipsetName) {
				swapCmdStr := fmt.Sprintf("ipset swap %s %s", tmpIPSetName, ipsetName)
				if err := executeCommand(swapCmdStr); err != nil {
					logrus.Errorf("error executing '%v': %v", swapCmdStr, err)
					result = multierror.Append(result, err)
				}

				deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpIPSetName)
				if err := executeCommand(deleteCmdStr); err != nil {
					logrus.Errorf("error executing '%v': %v", deleteCmdStr, err)
					result = multierror.Append(result, err)
				}
			} else {
				renameCmdStr := fmt.Sprintf("ipset rename %s %s", tmpIPSetName, ipsetName)
				if err := executeCommand(renameCmdStr); err != nil {
					logrus.Errorf("error executing '%v': %v", renameCmdStr, err)
					result = multierror.Append(result, err)
				}
			}

		}
	}

	return result
}

func (w *watcher) cleanupIpsets() error {
	logrus.Debugf("ipsets cleanup")

	var result error
	for ipsetName := range w.appliedIPsets {
		_, existsInNew := w.appliedIPsets[ipsetName]
		if !existsInNew {
			logrus.Debugf("ipset: %v doesn't exist in new map, hence deleting ", ipsetName)
			deleteCmdStr := fmt.Sprintf("ipset destroy %s", ipsetName)
			if err := executeCommand(deleteCmdStr); err != nil {
				logrus.Errorf("error executing '%v': %v", deleteCmdStr, err)
				result = multierror.Append(result, err)
			}
		}
	}

	cmd := "ipset -L | grep -B5 'References: 0' | grep 'Name: RNCH-'  | awk '{print $2}'"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		logrus.Errorf("Failed to execute command: %s", cmd)
		return err
	}

	if len(out) > 0 {
		staleIPSets := strings.Split(string(out), "\n")
		logrus.Debugf("staleIPSets: %v", staleIPSets)

		if staleIPSets != nil && len(staleIPSets) > 0 {
			for _, ipset := range staleIPSets {
				if ipset == "" {
					continue
				}
				deleteCmdStr := fmt.Sprintf("ipset destroy %s", ipset)
				if err := executeCommand(deleteCmdStr); err != nil {
					logrus.Errorf("error executing '%v': %v", deleteCmdStr, err)
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
			logrus.Errorf("not expecting error here for i: %v", i)
			continue
		}

		for ruleName, rule := range rules {
			logrus.Debugf("ruleName: %v, rule: %v", ruleName, rule)
			buf.Write(rule.iptables(w.defaultNetwork.DefaultPolicyAction))
		}
	}

	buf.WriteString("\nCOMMIT\n")

	if logrus.GetLevel() == logrus.DebugLevel {
		fmt.Printf("Applying rules\n%s", buf)
	}

	cmd := exec.Command("iptables-restore", "-n")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = buf
	if err := cmd.Run(); err != nil {
		logrus.Errorf("Failed to apply rules\n%s", buf)
		return err
	}

	if err := w.insertBaseRules(); err != nil {
		return errors.Wrap(err, "Applying base iptables rules")
	}

	return nil
}

func (w *watcher) run(args ...string) error {
	logrus.Debugf("Running %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (w *watcher) insertBaseRules() error {
	err := w.deleteBaseRules()
	err = w.deleteBaseRulesOut()
	err = w.insertBaseRulesOut()
	checkRule := fmt.Sprintf("iptables -w -C %v -d %v -s %v -j %v",
		hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
	if executeCommandNoStderr(checkRule) != nil {
		addRule := fmt.Sprintf("iptables -w -I %v -d %v -s %v -j %v",
			hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
		err = executeCommand(addRule)
	}
	return err
}

func (w *watcher) insertBaseRulesOut() error {
	var err error
	checkRule := fmt.Sprintf("iptables -w -C %v ! -d %v -s %v -j %v",
		hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainNameOut)
	if executeCommandNoStderr(checkRule) != nil {
		addRule := fmt.Sprintf("iptables -w -I %v ! -d %v -s %v -j %v",
			hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainNameOut)
			err = executeCommand(addRule)
	}
	checkRuleDNS := fmt.Sprintf("iptables -w -C %v -d %v -s %v -j %v",
	cattleNetworkPolicyChainNameOut, "169.254.169.250", w.defaultSubnet, "ACCEPT")
	if executeCommandNoStderr(checkRuleDNS) != nil {
		addRule := fmt.Sprintf("iptables -w -I %v 1 -d %v -s %v -j %v",
		cattleNetworkPolicyChainNameOut, "169.254.169.250", w.defaultSubnet, "ACCEPT")
		err = executeCommand(addRule)
		//addRule = fmt.Sprintf("iptables -w -I %v -s %v -j %v",
		//cattleNetworkPolicyChainNameOut, w.defaultSubnet, "DROP")
		//err = executeCommand(addRule)
	}
	return err
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

func (w *watcher) deleteBaseRulesOut() error {
	checkRule := fmt.Sprintf("iptables -w -C %v ! -d %v -s %v -j %v",
		hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainNameOut)
	if executeCommandNoStderr(checkRule) == nil {
		delRule := fmt.Sprintf("iptables -w -D %v ! -d %v -s %v -j %v",
			hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainNameOut)
		return executeCommand(delRule)
	}
	return nil
}

func (w *watcher) flushAndDeleteChain() error {
	checkRule := fmt.Sprintf("iptables -w -L %v", cattleNetworkPolicyChainName)
	if executeCommandNoStderr(checkRule) == nil {
		if err := w.run("iptables", "-w", "-F", cattleNetworkPolicyChainName); err != nil {
			logrus.Errorf("Error flushing the chain: %v", cattleNetworkPolicyChainName)
			return err
		}

		if err := w.run("iptables", "-X", cattleNetworkPolicyChainName); err != nil {
			logrus.Errorf("Error deleting the chain: %v", cattleNetworkPolicyChainName)
			return err
		}
	}

	return nil
}

func (w *watcher) flushAndDeleteChainOut() error {
	checkRule := fmt.Sprintf("iptables -w -L %v", cattleNetworkPolicyChainNameOut)
	if executeCommandNoStderr(checkRule) == nil {
		if err := w.run("iptables", "-w", "-F", cattleNetworkPolicyChainNameOut); err != nil {
			logrus.Errorf("Error flushing the chain: %v", cattleNetworkPolicyChainNameOut)
			return err
		}

		if err := w.run("iptables", "-X", cattleNetworkPolicyChainNameOut); err != nil {
			logrus.Errorf("Error deleting the chain: %v", cattleNetworkPolicyChainNameOut)
			return err
		}
	}

	return nil
}

func (w *watcher) insertChainOut() error {
	checkRule := fmt.Sprintf("iptables -w -L %v", cattleNetworkPolicyChainNameOut)
	if executeCommandNoStderr(checkRule) == nil {
		return nil
	}
	if err := w.run("iptables", "-N", cattleNetworkPolicyChainNameOut); err != nil {
		logrus.Errorf("Error inserting the chain out: %v", cattleNetworkPolicyChainNameOut)
		return err
	}
	return nil
}

func (w *watcher) cleanup() error {
	logrus.Debugf("Doing cleanup")
	// delete the base Rule
	if err := w.deleteBaseRules(); err != nil {
		logrus.Errorf("error deleting base rules: %v", err)
		return err
	}

	// delete the base Rule Out
	if err := w.deleteBaseRulesOut(); err != nil {
		logrus.Errorf("error deleting base rules: %v", err)
		return err
	}

	// Flush and delete the chain
	if err := w.flushAndDeleteChain(); err != nil {
		logrus.Errorf("error flusing and deleting chain: %v", err)
		return err
	}

	// Flush and delete the chain Out
	if err := w.flushAndDeleteChainOut(); err != nil {
		logrus.Errorf("error flusing and deleting chain: %v", err)
		return err
	}

	// remove the ipsets
	if err := w.cleanupIpsets(); err != nil {
		logrus.Errorf("Error cleaning ipsets: %v", err)
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
