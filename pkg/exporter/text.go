package exporter

import "github.com/moshloop/fireviz/pkg"

func ExportText(main pkg.Firewall) {
	for group, rules := range main.GroupByDest() {
		println(group)
		for _, rule := range rules {
			println("\t" + rule.String())
		}
	}
}
