package graphviz

import (
	"fmt"
	"io/ioutil"
	_ "reflect"
	"strconv"
	"strings"

	"github.com/gonum/gonum/graph/formats/dot"
	. "github.com/gonum/gonum/graph/formats/dot/ast"
	"github.com/logrusorgru/aurora"
	"github.com/moshloop/fireviz/pkg"
	. "github.com/moshloop/fireviz/pkg"
)

func Parse(file string) pkg.Firewall {
	source, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	LogInfo("%s", aurora.Blue(file))

	graph, err := dot.ParseBytes(source)
	if err != nil {
		panic(err)
	}
	var fw = Firewall{}
	for _, g := range graph.Graphs {
		if fw.PortMapping == nil {
			fw.PortMapping = parse_Ports(g.Stmts)
		}
		parse_Stmt(g.Stmts, &fw)

	}
	return fw
}

func parse(graphs []*Graph) {

}

func ToName(name string) string {
	return strings.TrimSpace(strings.Trim(name, "\""))
}

func parse_Stmt(stmts []Stmt, fw *Firewall) {

	for _, stmt := range stmts {
		switch stmt.(type) {
		case *Subgraph:
			//ignore legend/port mapping as it is parsed in phase 1
			if stmt.(*Subgraph).ID == "cluster_ports" {
				continue
			} else {
				parse_Stmt(stmt.(*Subgraph).Stmts, fw)
			}
		case *NodeStmt:
			//node := stmt.(*ast.NodeStmt)
			//println(node.Node.ID)
		case *AttrStmt:
			//attr := stmt.(*ast.AttrStmt)
			//println(attr.String())
		case *EdgeStmt:
			var edges = stmt.(*EdgeStmt)
			//TODO support entire subgraphs as source/dest
			var from = edges.From.(*Node)
			var to = edges.To.Vertex.(*Node)
			for _, port := range ToPorts(fw, edges) {
				var rule = Rule{Source: ToName(from.ID), Destination: ToName(to.ID), Ports: port}
				rule.Description = fmt.Sprintf("From %s to %s", ToName(from.ID), ToName(to.ID))
				fw.Rules = append(fw.Rules, rule)
			}
		default:
			//println(reflect.TypeOf(stmt).String())
		}
	}
}

func ToPorts(fw *Firewall, node *EdgeStmt) []string {
	val := FindPortsByAttribute(fw, node.Attrs)
	if val != "" {
		var mapped = fw.PortMapping[val]
		if mapped != "" {
			return strings.Split(mapped, ",")
		} else {
			return strings.Split(val, ",")
		}
	}

	return []string{}

}
func FindPortsByAttribute(fw *Firewall, attrs []*Attr) string {
	var label, color = "", ""

	for _, attr := range attrs {
		switch attr.Key {
		case "port", "ports":
			return ToName(attr.Val)
		case "color":
			color = ToName(attr.Val)
		case "label", "xlabel", "taillabel", "headlabel", "":
			label = ToName(attr.Val)
		case "style":
			if attr.Val == "invis" {
				return ""
			}
		}
	}
	label = strings.TrimSuffix(label, ",")

	if fw.IsValidPortMapping(color) {
		return color
	} else if fw.IsValidPortMapping(label) {
		return label
	}
	LogError("Missing port info: %s, valid labels are %s ", attrs, fw.PortMapping)
	return ""

}

func parse_Ports(stmts []Stmt) map[string]string {
	var PortMapping map[string]string

	for _, stmt := range stmts {
		switch stmt.(type) {
		case *Subgraph:
			if stmt.(*Subgraph).ID != "cluster_ports" {
				continue
			}

			for _, port := range stmt.(*Subgraph).Stmts {
				var name = ""
				var color = ""
				switch port.(type) {
				case *Subgraph:
					name = port.(*Subgraph).ID
				case *NodeStmt:
					name = port.(*NodeStmt).Node.ID
					for _, attr := range port.(*NodeStmt).Attrs {
						if attr.Key == "color" {
							color = attr.Val
						}
					}
				default:
					continue
				}
				var fields = strings.Split(ToName(name), ":")
				if len(fields) != 2 {
					LogError("Invalid port mapping " + name)
					continue
				}
				var key = fields[0]
				var value = fields[1]
				if strings.Contains(value, "-") {
					value = parse_PortRange(value)

				}
				if PortMapping == nil {
					PortMapping = make(map[string]string)
				}
				if color != "" {
					PortMapping[color] = value
				}
				PortMapping[key] = value
			}
		}
	}
	return PortMapping

}
func parse_PortRange(value string) string {
	var upper = strings.Split(value, "-")[1]
	var lower = strings.Split(value, "-")[0]
	var start, _ = strconv.Atoi(lower)
	var end, _ = strconv.Atoi(upper)
	if end < start {
		LogError("Invalid port range:  " + value)
		return ""
	}
	for i := start + 1; i <= end; i++ {
		value = value + "," + strconv.Itoa(i)
	}
	return value
}
