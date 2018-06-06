package cmd

import (
	"github.com/moshloop/fireviz/pkg"
	"github.com/spf13/cobra"
)

var (
	List = cobra.Command{
		Use:  "list",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var list = make(map[string]bool)
			for _, file := range args {
				for dest, _ := range pkg.ParseGraphviz(file).GroupByDest() {
					list[dest] = true
				}
			}

			for dest, _ := range list {
				println(dest)
			}
		},
	}
)
