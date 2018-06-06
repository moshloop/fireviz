package cmd

import (
	"fmt"
	"net"

	"strings"

	"time"

	"syscall"

	. "github.com/moshloop/fireviz/pkg"
	. "github.com/sparrc/go-ping"
	"github.com/spf13/cobra"
)

var (
	Ping = cobra.Command{
		Use:  "ping",
		Args: cobra.MinimumNArgs(1),
		Run:  ping,
	}
)

func icmp(host string) (int, string) {
	pinger, err := NewPinger(host)
	if err != nil {
		panic(err)
	}
	pinger.Count = 1
	pinger.SetPrivileged(true)
	pinger.Run()                 // blocks until finished
	stats := pinger.Statistics() // get send/receive/rtt stats
	return stats.PacketsRecv, fmt.Sprintf("%0.0f", stats.AvgRtt.Seconds())
}

func ping(cmd *cobra.Command, args []string) {
	TICK := "✓"
	BLOCKED := "❌"
	CLOSED := "❓"
	var fw = Parse(cmd, args)
	source := ToId(cmd.Flag("source").Value.String())
	domain := cmd.Flag("domain").Value.String()
	Timeout, _ := time.ParseDuration(cmd.Flag("timeout").Value.String())

	rules := fw.GroupBySource()[source]

	for _, rule := range rules {
		dest := strings.ToLower(rule.Destination + "." + domain)
		ips, err := net.LookupIP(dest)
		if err != nil {
			println(fmt.Sprintf("Could not lookup %s -> %v", dest, err))
			continue
		}
		for _, ip := range ips {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(dest, rule.Ports), Timeout)
			//recv, rtt := icmp(dest)
			if conn != nil {
				defer conn.Close()
			}
			result := TICK

			if err != nil {
				switch t := err.(type) {
				case *net.OpError:
					if t.Timeout() {
						result = BLOCKED
					} else {
						result = CLOSED
					}

				case syscall.Errno:
					if t == syscall.ECONNREFUSED {
						result = CLOSED
					}
				}
			}
			println(fmt.Sprintf("%s   %s (%s):%s", result, dest, ip, rule.Ports))

		}
	}
}

func init() {
	Ping.Flags().String("source", "", "The name of group where to run ping tests from")
	Ping.Flags().String("domain", "", "The domain suffix to use for looking up IP addresses")
	Ping.Flags().String("mapping", "", "path to a YAML file with address mappings")
	Ping.Flags().StringSlice("map", nil, "Map a group to a CIDR value, or use 'ignore")
	Ping.Flags().String("timeout", "1s", "Connection timeout")
}
