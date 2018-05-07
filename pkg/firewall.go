package pkg

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
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

		if groups[rule.DestinationID()] == nil {
			groups[rule.DestinationID()] = make([]Rule, 0)
		}
		groups[rule.DestinationID()] = append(groups[rule.DestinationID()], rule)

	}
	return groups

}

func (fw Firewall) GroupBySource() map[string][]Rule {
	var groups = make(map[string][]Rule)

	for _, rule := range fw.Rules {

		if groups[rule.SourceID()] == nil {
			groups[rule.SourceID()] = make([]Rule, 0)
		}
		groups[rule.SourceID()] = append(groups[rule.SourceID()], rule)

	}
	return groups

}
func (fw Firewall) ListGroups() []string {
	var set = make(map[string]bool)

	for _, rule := range fw.Rules {
		set[rule.Destination] = true
		if rule.SourceCidr == "" {
			set[rule.Source] = true
		}
	}

	var list = []string{}
	for k, _ := range set {
		list = append(list, k)
	}
	return list
}

func (fw Firewall) Map(mapping map[string]string) {
	for i := 0; i < len(fw.Rules); i++ {
		var rule = &fw.Rules[i]
		if mapping[rule.Source] == "ignore" {
			//delete element by replacing current element
			fw.Rules[i] = fw.Rules[len(fw.Rules)-1]
			fw.Rules = fw.Rules[:len(fw.Rules)]
			// reprocess
			i--
			continue
		}
		if mapping[rule.Source] != "" {
			rule.SourceCidr = mapping[rule.Source]

		}
		if mapping[rule.Destination] != "" {
			rule.Destination = mapping[rule.Destination]
		}
	}
}

type Rule struct {
	SourceCidr  string
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

func (rule Rule) ID() string {
	return rule.DestinationID() + "Ingress" + ToId(rule.Source) + ToId(rule.Ports)
}

func (rule Rule) DestinationID() string {
	return ToId(rule.Destination)
}

func (rule Rule) SourceID() string {
	return ToId(rule.Source)
}

func ToId(name string) string {
	key := strings.Replace(name, "-", "", -1)
	key = strings.Replace(key, "_", "", -1)
	key = strings.Replace(key, "*", "A", -1)
	key = strings.Replace(key, "/", "", -1)
	key = strings.Replace(key, ".", "", -1)
	key = strings.Replace(key, ",", "", -1)
	return strings.Replace(key, " ", "", -1)

}
func Parse(cmd *cobra.Command, args []string) Firewall {
	var list = make([]Firewall, 0)
	for _, file := range args {
		list = append(list, ParseGraphviz(file))
	}

	var main = list[0]
	for _, fw := range list[1:] {
		fw.MergeInto(&main)
	}

	var mappingFile = cmd.Flag("mapping").Value.String()
	var mapping = make(map[string]string)

	if mappingFile != "" {
		println("Mapping addresses using " + mappingFile)
		source, err := ioutil.ReadFile(mappingFile)
		if err != nil {
			panic(err)
		}
		if err = yaml.Unmarshal(source, &mapping); err != nil {
			println(err)
		}

	}

	mappings, err := cmd.Flags().GetStringSlice("map")
	if err != nil {
		panic(err)
	}
	if mappings != nil {
		for _, entry := range mappings {
			mapping[strings.Split(entry, "=")[0]] = strings.Split(entry, "=")[1]
		}

	}
	main.Map(mapping)
	return main
}
