package cmd

import (
	"io/ioutil"
	_ "reflect"

	"strings"

	"github.com/moshloop/fireviz/pkg"
	"github.com/moshloop/fireviz/pkg/exporter"
	"github.com/moshloop/fireviz/pkg/graphviz"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var Export = cobra.Command{
	Use:  "export [graphviz files]",
	Args: cobra.MinimumNArgs(1),
	Run:  export,
}

func export(cmd *cobra.Command, args []string) {
	var list = make([]pkg.Firewall, 0)
	for _, file := range args {
		list = append(list, graphviz.Parse(file))
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

	if cmd.Flag("cloudformation").Value.String() == "true" {
		if vpc := cmd.Flag("vpc").Value.String(); vpc == "" {
			print("Must specify --vpc")

		} else {
			exporter.ExportCloudFormation(main, vpc)
		}
	} else if cmd.Flag("azure").Value.String() == "true" {
		if location := cmd.Flag("location").Value.String(); location == "" {
			print("Must specify --location")
		} else if name := cmd.Flag("name").Value.String(); name == "" {
			print("Must specify a network security group name using --name")
		} else {
			exporter.ExportAzure(main, location, name)
		}
	}

}

func init() {

	Export.Flags().Bool("cloudformation", false, "Export cloudformation scripts")
	Export.Flags().Bool("azure", false, "Export Azure ARM templates")
	Export.Flags().Bool("csv", false, "Export CSV rules")
	Export.Flags().String("mapping", "", "path to a YAML file with address mappings")
	Export.Flags().StringSlice("map", nil, "Map a group to a CIDR value, or use 'ignore")
	Export.Flags().String("vpc", "", "The VPC id to use for security groups")
	Export.Flags().String("name", "", "The name of the azure network security group")
	Export.Flags().String("location", "", "The Azure location to use ARM templates")

}
