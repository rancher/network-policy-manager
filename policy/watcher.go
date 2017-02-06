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
	ipsetNameMaxLength           = 31
)

type watcher struct {
	c                  metadata.Client
	lastApplied        time.Time
	shutdownInProgress bool
	signalCh           chan os.Signal
	exitCh             chan int
	defaultNetwork     *metadata.Network
	defaultSubnet      string
	stacks             []metadata.Stack
	services           []metadata.Service
	containers         []metadata.Container
	appliedIPsets      map[string]map[string]bool
	appliedRules       map[int]map[string]Rule
	ipsets             map[string]map[string]bool
	ipsetsNamesMap     map[string]string
	rules              map[int]map[string]Rule
	selfHost           *metadata.Host
	appliednp          *NetworkPolicy
	np                 *NetworkPolicy
}

// Rule is used to store the info need to be a iptables rule
type Rule struct {
	dst      string
	src      string
	ports    []string
	stateful bool
	action   string
	system   bool
}

func setupKernelParameters() error {
	cmd := "sysctl -w net.bridge.bridge-nf-call-iptables=1"
	return executeCommandNoStdoutNoStderr(cmd)
}

func (rule *Rule) iptables(defaultPolicyAction string) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("-A %v ", cattleNetworkPolicyChainName))
	if rule.dst != "" {
		buf.WriteString(fmt.Sprintf("-m set --match-set %v dst ", rule.dst))
	}

	if rule.src != "" {
		buf.WriteString(fmt.Sprintf("-m set --match-set %v src ", rule.src))
	}

	// TODO: Check for ports/ stateful etc

	var ruleTarget string
	if rule.action == ActionAllow {
		ruleTarget = "RETURN"
	} else {
		ruleTarget = "DROP"
	}

	buf.WriteString(fmt.Sprintf("-j %v\n", ruleTarget))

	return buf.Bytes()
}

// Watch is used to monitor metadata for changes
func Watch(c metadata.Client, exitCh chan int) error {
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
		exitCh:             exitCh,
		signalCh:           sCh,
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
	w.cleanup()

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
					aLabelValueMap["local"][aContainer.PrimaryIp] = true
				}
				aLabelValueMap["all"][aContainer.PrimaryIp] = true
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
					local[aContainer.PrimaryIp] = true
				}
				all[aContainer.PrimaryIp] = true
			}
		}
	}

	return local, all
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
				all[aContainer.PrimaryIp] = true
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
	isDstSystem := false
	isSrcSystem := false
	r, err := w.buildAndProcessRuleWithSrcDst(isDstSystem, isSrcSystem, ruleName, all, nil)
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

		_, all := w.getInfoFromStack(stack)

		ruleName := fmt.Sprintf("from.system.stack.%v", stack.Name)
		isDstSystem := true
		isSrcSystem := true
		r, err := w.buildAndProcessRuleWithSrcDst(isDstSystem, isSrcSystem, ruleName, nil, all)
		if err != nil {
			return nil, err
		}
		r.action = ActionAllow
		defSysRulesMap[ruleName] = *r
	}

	logrus.Debugf("defSysRulesMap: %v", defSysRulesMap)
	return defSysRulesMap, nil
}

func (w *watcher) withinStackHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinStackHandler")
	withinRulesMap := make(map[string]Rule)
	for _, stack := range w.stacks {
		if stack.System {
			continue
		}
		local, all := w.getInfoFromStack(stack)
		ruleName := fmt.Sprintf("within.%v", stack.Name)
		if len(local) > 0 {
			isDstSystem := false
			isSrcSystem := false
			if stack.System {
				isDstSystem = true
				isSrcSystem = true
			}
			r, err := w.buildAndProcessRuleWithSrcDst(isDstSystem, isSrcSystem, ruleName, local, all)
			if err != nil {
				return nil, err
			}
			r.action = p.Action

			withinRulesMap[ruleName] = *r
		} else {
			logrus.Debugf("stack: %v doesn't have any local containers, skipping", stack.Name)
			continue
		}
	}

	logrus.Debugf("withinRulesMap: %v", withinRulesMap)
	return withinRulesMap, nil
}

func (w *watcher) buildAndProcessRuleWithSrcDst(isDstSystem, isSrcSystem bool, ruleName string, local, all map[string]bool) (*Rule, error) {
	var err error
	var dstSetName, srcSetName string

	if local != nil {
		dstSet := fmt.Sprintf("dst.%v", ruleName)
		dstSetName, err = w.generateHash(dstSet)
		if err != nil {
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}

		if isDstSystem {
			dstSetName = "RNCH-S-" + dstSetName
		} else {
			dstSetName = "RNCH-U-" + dstSetName
		}

		if len(dstSetName) > ipsetNameMaxLength {
			logrus.Errorf("length of ipset names exceeded %v. dstSetName: %v", ipsetNameMaxLength, dstSetName)
			dstSetName = dstSetName[0 : ipsetNameMaxLength-1]
		}
		if existingSet, exists := w.ipsets[dstSetName]; exists {
			if !reflect.DeepEqual(existingSet, local) {
				return nil, fmt.Errorf("%v: mismatch existingSet: %v local:%v", dstSetName, existingSet, local)
			}
		} else {
			w.ipsets[dstSetName] = local
			w.ipsetsNamesMap[dstSetName] = dstSet
		}
	}

	if all != nil {

		srcSet := fmt.Sprintf("src.%v", ruleName)
		srcSetName, err = w.generateHash(srcSet)
		if err != nil {
			logrus.Errorf("coudln't generate hash: %v", err)
			return nil, err
		}
		if isSrcSystem {
			srcSetName = "RNCH-S-" + srcSetName
		} else {
			srcSetName = "RNCH-U-" + srcSetName
		}
		if len(srcSetName) > ipsetNameMaxLength {
			logrus.Errorf("length of ipset names exceeded %v. srcSetName: %v", ipsetNameMaxLength, srcSetName)
			srcSetName = srcSetName[0 : ipsetNameMaxLength-1]
		}
		if existingSet, exists := w.ipsets[srcSetName]; exists {
			if !reflect.DeepEqual(existingSet, all) {
				logrus.Errorf("%v: mismatch existingSet: %v all:%v", srcSetName, existingSet, all)
			}
		} else {
			w.ipsets[srcSetName] = all
			w.ipsetsNamesMap[srcSetName] = srcSet
		}
	}

	logrus.Debugf("dstSetName: %v srcSetName: %v", dstSetName, srcSetName)

	r := &Rule{dst: dstSetName,
		src: srcSetName,
	}

	return r, nil
}

func (w *watcher) withinServiceHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinServiceHandler")

	return nil, nil
}

func (w *watcher) withinLinkHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinLinkHandler")

	return nil, nil
}

func (w *watcher) withinPolicyHandler(p NetworkPolicyRule) (map[string]Rule, error) {
	logrus.Debugf("withinPolicyHandler")
	if p.Within == StrStack {
		return w.withinStackHandler(p)
	} else if p.Within == StrService {
		return w.withinServiceHandler(p)
	} else if p.Within == StrLinked {
		w.withinLinkHandler(p)
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

		ruleName := fmt.Sprintf("between.%v.%v", p.Between.GroupBy, labelValue)
		if len(local) > 0 {
			isDstSystem := false
			isSrcSystem := false
			r, err := w.buildAndProcessRuleWithSrcDst(isDstSystem, isSrcSystem, ruleName, local, all)
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

		r, err = w.defaultPolicyAction(np.DefaultAction)
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

	containers, err := w.c.GetContainers()
	if err != nil {
		logrus.Errorf("Error getting containers from metadata: %v", err)
		return err
	}

	selfHost, err := w.c.GetSelfHost()
	if err != nil {
		logrus.Errorf("Couldn't get containers from metadata: %v", err)
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

	w.defaultNetwork = defaultNetwork
	w.defaultSubnet = defaultSubnet
	w.selfHost = &selfHost
	w.stacks = stacks
	w.containers = containers

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

	for ipsetName, ipset := range w.ipsets {
		oldipset := w.appliedIPsets[ipsetName]
		if !reflect.DeepEqual(ipset, oldipset) {
			logrus.Debugf("refreshing ipset: %v", ipsetName)
			tmpIPSetName := "TMP-" + ipsetName
			createIPSet(tmpIPSetName, ipset)
			if existsIPSet(ipsetName) {
				swapCmdStr := fmt.Sprintf("ipset swap %s %s", tmpIPSetName, ipsetName)
				executeCommand(swapCmdStr)

				deleteCmdStr := fmt.Sprintf("ipset destroy %s", tmpIPSetName)
				executeCommand(deleteCmdStr)
			} else {
				renameCmdStr := fmt.Sprintf("ipset rename %s %s", tmpIPSetName, ipsetName)
				executeCommand(renameCmdStr)
			}

		}
	}

	return nil
}

func (w *watcher) cleanupIpsets() error {
	logrus.Debugf("ipsets cleanup")

	for ipsetName := range w.appliedIPsets {
		_, existsInNew := w.appliedIPsets[ipsetName]
		if !existsInNew {
			logrus.Debugf("ipset: %v doesn't exist in new map, hence deleting ", ipsetName)
			deleteCmdStr := fmt.Sprintf("ipset destroy %s", ipsetName)
			executeCommand(deleteCmdStr)
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
				err := executeCommand(deleteCmdStr)
				if err != nil {
					logrus.Errorf("error while running cmd=%v :%v", deleteCmdStr, err)
					return err
				}
			}
		}
	}

	return nil
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
	checkRule := fmt.Sprintf("iptables -w -C %v -d %v -s %v -j %v",
		hookToChain, w.defaultSubnet, w.defaultSubnet, cattleNetworkPolicyChainName)
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

func (w *watcher) cleanup() error {
	logrus.Debugf("Doing cleanup")
	// delete the base Rule
	if err := w.deleteBaseRules(); err != nil {
		logrus.Errorf("error deleting base rules: %v", err)
		return err
	}

	// Flush and delete the chain
	if err := w.flushAndDeleteChain(); err != nil {
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
	err := executeCommandNoStderr(checkCmdStr)

	return err == nil
}

func createIPSet(name string, ips map[string]bool) {
	createStr := fmt.Sprintf("ipset create %s iphash", name)
	executeCommand(createStr)

	for ip := range ips {
		addIPStr := fmt.Sprintf("ipset add %s %s", name, ip)
		executeCommand(addIPStr)
	}
}
