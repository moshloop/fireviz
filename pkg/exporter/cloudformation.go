package exporter

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/moshloop/fireviz/pkg"
)

type Template struct {
	Resources map[string]interface{}
}

func (t Template) YAML() string {

	data, _ := json.MarshalIndent(t, "", "    ")
	data, _ = yaml.JSONToYAML(data)
	return string(data)
}
func (t Template) append(key string, group *SecurityGroup) Template {
	if t.Resources == nil {
		t.Resources = make(map[string]interface{})
	}
	t.Resources[key] = group
	return t
}

type SecurityGroupEgress struct {
	CidrIP                     string `json:",omitempty"`
	CidrIpv6                   string `json:",omitempty"`
	Description                string `json:",omitempty"`
	DestinationPrefixListID    string `json:",omitempty"`
	DestinationSecurityGroupId string `json:",omitempty"`
	FromPort                   int    `json:",omitempty"`
	IPProtocol                 string `json:",omitempty"`
	ToPort                     string `json:",omitempty"`
}
type SecurityGroupIngress struct {
	CidrIP      string `json:",omitempty"`
	CidrIpv6    string `json:",omitempty"`
	Description string `json:",omitempty"`
	FromPort    int    `json:",omitempty"`

	ToPort                     int    `json:",omitempty"`
	IPProtocol                 string `json:",omitempty"`
	SourceSecurityGroupID      string `json:",omitempty"`
	SourceSecurityGroupName    string `json:",omitempty"`
	SourceSecurityGroupOwnerID string `json:",omitempty"`
}

type Properties struct {
	GroupDescription     string                 `json:",omitempty"`
	GroupName            string                 `json:",omitempty"`
	SecurityGroupEgress  []SecurityGroupEgress  `json:",omitempty"`
	SecurityGroupIngress []SecurityGroupIngress `json:",omitempty"`
	VpcID                string                 `json:",omitempty"`
}
type SecurityGroup struct {
	Type       string     `json:",omitempty"`
	Properties Properties `json:",omitempty"`
}

func ExportCloudFormation(fw pkg.Firewall, vpc string) {
	var template = Template{}
	for group, rules := range fw.GroupByDest() {

		var sg = SecurityGroup{
			Type: "AWS::EC2::SecurityGroup",
			Properties: Properties{
				GroupName:        group,
				GroupDescription: group,
				VpcID:            vpc,
			},
		}
		for _, rule := range rules {
			var from, _ = strconv.Atoi(rule.Ports)
			var to, _ = strconv.Atoi(rule.Ports)
			var ingress = SecurityGroupIngress{
				IPProtocol:              "tcp",
				FromPort:                from,
				ToPort:                  to,
				Description:             rule.Description,
				SourceSecurityGroupName: rule.Source,
			}
			sg.Properties.SecurityGroupIngress = append(sg.Properties.SecurityGroupIngress, ingress)
		}

		template = template.append(group, &sg)
	}
	os.Stdout.WriteString("AWSTemplateFormatVersion: 2010-09-09\n" + template.YAML() + "\n")
}
