package policy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/leodotcloud/log"
	"github.com/rancher/go-rancher-metadata/metadata"
	//"gopkg.in/yaml.v2"
)

const (
	// ActionAllow action for the policy
	ActionAllow string = "allow"
	// ActionDeny action for the policy
	ActionDeny string = "deny"
)

// StrStack for 'stack' string
// StrService for 'service' string
// StrLink for 'link' string
const (
	StrStack   string = "stack"
	StrService string = "service"
	StrLinked  string = "linked"
)

// NetworkPolicy ...
type NetworkPolicy struct {
	DefaultAction string
	Rules         []NetworkPolicyRule
}

// NetworkPolicyRule  ...
type NetworkPolicyRule struct {
	metadata.NetworkPolicyRule
}

// NewNetworkPolicy takes in the metadata type and converts to local type
func NewNetworkPolicy(network *metadata.Network) (*NetworkPolicy, error) {
	np := NetworkPolicy{}
	if network.DefaultPolicyAction == ActionDeny {
		np.DefaultAction = ActionDeny
	} else {
		np.DefaultAction = ActionAllow
	}

	for _, mr := range network.Policy {
		r := NetworkPolicyRule{mr}
		np.Rules = append(np.Rules, r)
	}

	if err := np.Validate(); err != nil {
		log.Errorf("error validating policy: %#v", np)
		log.Errorf("error: %v", err)
		return nil, err
	}

	return &np, nil
}

// ParseNetworkPolicyStr is used to parse the input yaml representation of the network policy and perform basic validations
func ParseNetworkPolicyStr(npStr string) (*NetworkPolicy, error) {
	log.Debugf("Parsing Network policy: %v", npStr)
	if npStr == "" {
		return nil, fmt.Errorf("empty policy string provided")
	}

	np := NetworkPolicy{}
	np.DefaultAction = ActionAllow

	var arr []NetworkPolicyRule

	err := json.Unmarshal([]byte(npStr), &arr)
	if err != nil {
		log.Errorf("got error: %v, while unmarshaling: %v", err, npStr)
		return nil, err
	}
	np.Rules = append(arr)

	log.Debugf("%v", spew.Sprintf("parsed np: %#+v", np))

	if err := np.Validate(); err != nil {
		log.Errorf("error validating policy: %v", npStr)
		log.Errorf("error: %v", err)
		return nil, err
	}

	return &np, nil
}

// Validate runs basic validations on the network policy
func (np *NetworkPolicy) Validate() error {
	for _, rule := range np.Rules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate runs basic validations on the policy
func (rule *NetworkPolicyRule) Validate() error {
	log.Debugf("validating rule: %v", spew.Sprintf("%#+v", rule))
	if rule.Within == "" &&
		rule.Between == nil &&
		rule.To == nil &&
		rule.From == nil {
		return fmt.Errorf("a valid policy needs 'within' or  'to' & 'from' or 'between'")
	}

	if rule.Within != "" {
		if rule.Within != StrStack &&
			rule.Within != StrService &&
			rule.Within != StrLinked {
			return fmt.Errorf("when using 'within': one of [stack, service, linked] should be specified, but got: %v", rule.Within)
		}

		if rule.From != nil ||
			rule.To != nil ||
			rule.Ports != nil ||
			rule.Between != nil {
			return fmt.Errorf("when using 'within': 'between' or 'from' & 'to' or 'ports' are not allowed")
		}
	} else if rule.Between != nil {
		if rule.From != nil ||
			rule.To != nil ||
			rule.Ports != nil ||
			rule.Within != "" {
			return fmt.Errorf("when using 'between': 'within' or 'from' & 'to' or 'ports' are not allowed")
		}

		if rule.Between.Selector == "" &&
			rule.Between.GroupBy == "" {
			return fmt.Errorf("when using 'between': one of [selector, groupBy] should be specified")
		}

	} else if rule.To == nil || rule.From == nil {
		return fmt.Errorf("a policy needs both 'from' & 'to' to be valid")
	}

	if rule.Action != ActionAllow && rule.Action != ActionDeny {
		return fmt.Errorf("a policy action has be either 'allow' or 'deny' but got: %v", rule.Action)
	}

	if len(rule.Ports) > 0 {
		for _, rule := range rule.Ports {
			portSplits := strings.Split(rule, "/")
			portNumberStr := portSplits[0]
			portNumber, err := strconv.Atoi(portNumberStr)
			if err != nil {
				return fmt.Errorf("valid port range: 1 - 65535, but specified: %v", portNumberStr)
			}
			if !(0 < portNumber && portNumber < 65536) {
				return fmt.Errorf("valid port range: 1 - 65535 but specified: %v", portNumber)
			}
			if len(portSplits) > 1 {
				portTypeStr := portSplits[1]
				if portTypeStr != "tcp" && portTypeStr != "udp" {
					return fmt.Errorf("port type can only be either 'tcp' or 'udp' but got: %v", portTypeStr)
				}
			}
		}
	}

	if rule.From != nil {
		if rule.From.Selector == "" {
			return fmt.Errorf("'from' needs atleast one of: [selector]")
		}

	}

	if rule.To != nil {
		if rule.To.Selector == "" {
			return fmt.Errorf("'to' needs atleast one of: [selector]")
		}
	}

	// TODO: Check if more than one from/to are specified

	return nil
}
