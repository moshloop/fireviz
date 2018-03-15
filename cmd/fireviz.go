package cmd

import (
	"io/ioutil"
	_ "reflect"

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
	if mappingFile != "" {
		println("Mapping addresses using " + mappingFile)
		var mapping = make(map[string]string)
		source, err := ioutil.ReadFile(mappingFile)
		if err != nil {
			panic(err)
		}
		if err = yaml.Unmarshal(source, &mapping); err != nil {
			println(err)
		}
		main.Map(mapping)

	}

	if cmd.Flag("cloudformation").Value.String() == "true" {
		if vpc := cmd.Flag("vpc").Value.String(); vpc == "" {
			print("Must specify --vpc")

		} else {
			exporter.ExportCloudFormation(main, vpc)
		}
	}
}

func init() {

	Export.Flags().Bool("cloudformation", true, "Export cloudformation scripts")
	Export.Flags().Bool("csv", false, "Export CSV rules")
	Export.Flags().String("mapping", "", "path to a YAML file with address mappings")
	Export.Flags().String("vpc", "", "The VPC id to use for security groups")

}
