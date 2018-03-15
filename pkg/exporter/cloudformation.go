package exporter

import (
	"encoding/json"
	"strconv"

	"os"

	"fmt"

	"strings"

	"github.com/ghodss/yaml"
	"github.com/moshloop/fireviz/pkg"
)

type Template struct {
	AWSTemplateFormatVersion string
	Resources                map[string]interface{}
}

func (t Template) YAML() string {
	t.AWSTemplateFormatVersion = "2010-09-09"
	data, _ := json.MarshalIndent(t, "", "    ")
	data, _ = yaml.JSONToYAML(data)

	return strings.Replace(string(data), "'", "", -1)
}

func (t Template) append(key string, group interface{}) Template {
	if t.Resources == nil {
		t.Resources = make(map[string]interface{})
	}
	t.Resources[key] = group
	return t
}

type SecurityGroupEgressProperties struct {
	GroupName                  string `json:",omitempty"`
	CidrIP                     string `json:",omitempty"`
	CidrIpv6                   string `json:",omitempty"`
	Description                string `json:",omitempty"`
	DestinationPrefixListId    string `json:",omitempty"`
	DestinationSecurityGroupId string `json:",omitempty"`
	FromPort                   int    `json:",omitempty"`
	IPProtocol                 string `json:",omitempty"`
	ToPort                     string `json:",omitempty"`
}
type SecurityGroupIngressProperties struct {
	GroupId                    string `json:",omitempty"`
	CidrIP                     string `json:",omitempty"`
	CidrIpv6                   string `json:",omitempty"`
	Description                string `json:",omitempty"`
	FromPort                   int    `json:",omitempty"`
	ToPort                     int    `json:",omitempty"`
	IpProtocol                 string `json:",omitempty"`
	SourceSecurityGroupId      string `json:",omitempty"`
	SourceSecurityGroupName    string `json:",omitempty"`
	SourceSecurityGroupOwnerID string `json:",omitempty"`
}

type SecurityGroupIngress struct {
	Type       string                         `json:",omitempty"`
	DependsOn  string                         `json:",omitempty"`
	Properties SecurityGroupIngressProperties `json:",omitempty"`
}

type SecurityGroupEgress struct {
	Type       string                        `json:",omitempty"`
	Properties SecurityGroupEgressProperties `json:",omitempty"`
}

type Properties struct {
	GroupDescription string `json:",omitempty"`
	GroupName        string `json:",omitempty"`
	VpcId            string `json:",omitempty"`
}
type SecurityGroup struct {
	Type       string     `json:",omitempty"`
	Properties Properties `json:",omitempty"`
}

func ExportCloudFormation(fw pkg.Firewall, vpc string) {
	var template = Template{}
	for _, group := range fw.ListGroups() {
		template = template.append(pkg.ToId(group), &SecurityGroup{
			Type: "AWS::EC2::SecurityGroup",
			Properties: Properties{
				GroupName:        group,
				GroupDescription: group,
				VpcId:            vpc,
			},
		})

	}
	for group, rules := range fw.GroupByDest() {
		for _, rule := range rules {
			if rule.Ports == "" {
				pkg.LogError("Missing ports: %+v", rule)
				continue
			}

			var from, _ = strconv.Atoi(rule.Ports)
			var to, _ = strconv.Atoi(rule.Ports)
			var proto = "tcp"
			if rule.Ports == "*" {
				from = 1
				to = 65535
			}
			if rule.Ports == "IPIP" {
				proto = "94"
			}

			var ingress = SecurityGroupIngressProperties{
				GroupId:               fmt.Sprintf("!GetAtt \"%s.GroupId\"", rule.DestinationID()),
				IpProtocol:            proto,
				FromPort:              from,
				ToPort:                to,
				Description:           rule.Description,
				SourceSecurityGroupId: fmt.Sprintf("!Ref \"%s\"", rule.SourceID()),
			}
			template = template.append(group+"Ingress"+rule.SourceID()+strings.Replace(rule.Ports, "*", "ALL", -1), &SecurityGroupIngress{
				Type:       "AWS::EC2::SecurityGroupIngress",
				DependsOn:  rule.DestinationID(),
				Properties: ingress,
			})
		}
	}

	os.Stdout.WriteString(template.YAML())

}

func remove(s []string, i int) []string {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}
