package main

import (
	"github.com/moshloop/fireviz/cmd"
	"github.com/moshloop/fireviz/pkg"
	"github.com/spf13/cobra"
)

func main() {
	pkg.LogError("fireviz " + pkg.VERSION)
	var rootCmd = &cobra.Command{
		Use: "fireviz",
		Run: func(cmd *cobra.Command, args []string) {},
	}
	rootCmd.AddCommand(&cmd.Export, &cmd.List)
	rootCmd.Execute()

}
