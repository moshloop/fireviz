package main

import (
	"io/ioutil"
	_ "reflect"

	"github.com/moshloop/fireviz/pkg"
	"github.com/moshloop/fireviz/pkg/exporter"
	"github.com/moshloop/fireviz/pkg/graphviz"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func main() {

	println("fireviz " + pkg.VERSION)
	var cmd = cobra.Command{
		Use: "fireviz",
	}
	var export = cobra.Command{
		Use:  "export [graphviz files]",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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

		},
	}
	export.Flags().Bool("cloudformation", true, "Export cloudformation scripts")
	export.Flags().Bool("csv", false, "Export CSV rules")
	export.Flags().String("mapping", "", "path to a YAML file with address mappings")
	export.Flags().String("vpc", "", "The VPC id to use for security groups")
	cmd.AddCommand(&export)

	var list = cobra.Command{
		Use:  "list",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var list = make(map[string]bool)
			for _, file := range args {
				for dest, _ := range graphviz.Parse(file).GroupByDest() {
					list[dest] = true
				}
			}

			for dest, _ := range list {
				println(dest)
			}
		},
	}

	cmd.AddCommand(&list)

	//cmd.Args().
	cmd.Execute()

}
