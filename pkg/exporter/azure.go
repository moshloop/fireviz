package exporter

import (
	"encoding/json"
	"os"

	"fmt"

	"github.com/moshloop/fireviz/pkg"
)

type ARMTemplate struct {
	Schema    string        `json:"$schema"`
	Version   string        `json:"contentVersion"`
	Resources []interface{} `json:"resources"`
}

type ID struct {
	ID string `json:"id"`
}

func (id ID) String() string {
	return id.ID
}
func NewID(id string) ID {
	return ID{
		ID: fmt.Sprintf("[resourceId('Microsoft.Network/applicationSecurityGroups', '%v')]", id),
	}
}

func (t ARMTemplate) YAML() string {
	t.Schema = "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
	t.Version = "1.0.0.0"
	data, _ := json.MarshalIndent(t, "", "    ")
	return string(data)
}

func (t ARMTemplate) append(group interface{}) ARMTemplate {
	t.Resources = append(t.Resources, group)
	return t
}

type ApplicationSecurityGroup struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Location   string `json:"location,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
}

type NetworkSecurityGroup struct {
	APIVersion string                    `json:"apiVersion,omitempty"`
	Location   string                    `json:"location,omitempty"`
	Name       string                    `json:"name,omitempty"`
	Properties NetworkSecurityProperties `json:"properties,omitempty"`
	Tags       NetworkSecurityTags       `json:"tags,omitempty"`
	Type       string                    `json:"type,omitempty"`
}

func (nsg NetworkSecurityGroup) append(rule NetworkSecurityRule) NetworkSecurityGroup {
	for _, rule2 := range nsg.Properties.SecurityRules {
		if rule2.Name == rule.Name {
			pkg.LogError("Skipping duplicate rule: " + rule.Name)
			return nsg
		}
	}
	nsg.Properties.SecurityRules = append(nsg.Properties.SecurityRules, rule)
	return nsg
}

type NetworkSecurityRule struct {
	Name       string                        `json:"name,omitempty"`
	Properties NetworkSecurityRuleProperties `json:"properties,omitempty"`
}

func (rule NetworkSecurityRule) appendDestination(id ID) NetworkSecurityRule {
	rule.Properties.DestinationApplicationSecurityGroups = append(rule.Properties.DestinationApplicationSecurityGroups, id)
	return rule
}

func (rule NetworkSecurityRule) appendSource(id ID) NetworkSecurityRule {
	rule.Properties.SourceApplicationSecurityGroups = append(rule.Properties.SourceApplicationSecurityGroups, id)
	return rule
}

type NetworkSecurityTags struct {
	DisplayName string `json:"displayName,omitempty"`
}

type NetworkSecurityProperties struct {
	SecurityRules []NetworkSecurityRule `json:"securityRules,omitempty"`
}
type NetworkSecurityRuleProperties struct {
	Access                               string `json:"access,omitempty"`
	Description                          string `json:"description,omitempty"`
	DestinationAddressPrefix             string `json:"destinationAddressPrefix,omitempty"`
	DestinationPortRange                 string `json:"destinationPortRange,omitempty"`
	DestinationApplicationSecurityGroups []ID   `json:"destinationApplicationSecurityGroups,omitempty"`
	Direction                            string `json:"direction,omitempty"`
	Priority                             int    `json:"priority,omitempty"`
	Protocol                             string `json:"protocol,omitempty"`
	SourceAddressPrefix                  string `json:"sourceAddressPrefix,omitempty"`
	SourcePortRange                      string `json:"sourcePortRange,omitempty"`
	SourceApplicationSecurityGroups      []ID   `json:"sourceApplicationSecurityGroups,omitempty"`
}

func ExportAzure(fw pkg.Firewall, location string, name string) {
	var template = ARMTemplate{}
	for _, group := range fw.ListGroups() {
		template = template.append(ApplicationSecurityGroup{
			Name:       group,
			Type:       "Microsoft.Network/applicationSecurityGroups",
			APIVersion: "2017-10-01",
			Location:   location,
		})
	}

	for group, rules := range fw.GroupByDest() {
		nsg := NetworkSecurityGroup{
			Type:       "Microsoft.Network/networkSecurityGroups",
			Name:       group,
			Location:   location,
			APIVersion: "2017-09-01",
			Properties: NetworkSecurityProperties{},
		}
		priority := 100

		for _, rule := range rules {
			if rule.Ports == "" {
				pkg.LogError("Missing ports: %+v", rule)
				continue
			}
			priority = priority + 1
			nsgRule := NetworkSecurityRule{
				rule.ID(),
				NetworkSecurityRuleProperties{
					Direction:            "inbound",
					Priority:             priority,
					Access:               "Allow",
					SourcePortRange:      "*",
					DestinationPortRange: rule.Ports,
					Protocol:             "tcp",
					Description:          rule.Description,
				},
			}
			nsgRule = nsgRule.appendDestination(NewID(rule.Destination))
			nsgRule = nsgRule.appendSource(NewID(rule.Source))
			nsg = nsg.append(nsgRule)

		}
		template = template.append(nsg)
	}

	os.Stdout.WriteString(template.YAML())

}
