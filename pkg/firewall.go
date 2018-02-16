package pkg

import (
	"fmt"
	"strings"
	"strconv"
)

type Firewall struct {
	Rules          []Rule
	PortMapping    map[string]string
	AddressMapping map[string]string
}

func (fw Firewall) IsValidPortMapping(port string) bool {
	return port != "" && (fw.PortMapping[port] != "" || !fw.IsValidPort(port))
}

func (fw Firewall) IsValidPort(ports string) bool {
	for _, port := range strings.Split(ports, ",") {
		if _, err := strconv.Atoi(port); err == nil {
			return false
		}

	}
	return true
}

func (from Firewall) MergeInto(fw *Firewall) {
	fw.Rules = append(fw.Rules, from.Rules...)
}

func (fw Firewall) String() string {
	return fmt.Sprint(fw.PortMapping)
}
func (fw Firewall) GroupByDest() map[string][]Rule {
	var groups = make(map[string][]Rule)

	for _, rule := range fw.Rules {
		if groups[rule.Destination] == nil {
			groups[rule.Destination] = make([]Rule, 0)
		}
		groups[rule.Destination] = append(groups[rule.Destination], rule)

	}
	return groups

}
func (fw Firewall) Map(mapping map[string]string) {
	for i := 0; i < len(fw.Rules); i++ {
		var rule = &fw.Rules[i]
		if mapping[rule.Source] != "" {
			rule.Source = mapping[rule.Source]

		}
		if mapping[rule.Destination] != "" {
			rule.Destination = mapping[rule.Destination]
		}
	}
}

type Rule struct {
	Source      string
	Destination string
	Ports       string
	Deny        bool
	Description string
	Order       int
}

func (rule Rule) String() string {
	return fmt.Sprintf("source:%s -> dest:%s (%s) - %s", rule.Source, rule.Destination, rule.Ports, rule.Description)
}
