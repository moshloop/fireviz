package exporter

import "github.com/moshloop/fireviz/pkg"

type Exporter interface {
	Export(firewall *pkg.Firewall) error
}
