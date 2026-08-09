package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// load reads, validates and expands the manifest. Validation errors are
// reported in full rather than one at a time, because a course author editing a
// hundred-AS lab should see every problem in a single pass.
func load(opts *Options) (*model.Topology, error) {
	l, err := manifest.Load(opts.Manifest)
	if err != nil {
		return nil, err
	}
	diags := l.Validate()
	if diags.HasErrors() {
		return nil, diags.Err()
	}
	for _, d := range diags.Items {
		if d.Sev == manifest.SevWarning {
			fmt.Fprintln(os.Stderr, d.String())
		}
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		return nil, err
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning: "+w)
	}
	return res.Topology, nil
}

func newValidateCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Check a lab manifest and report every problem at once",
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := manifest.Load(opts.Manifest)
			if err != nil {
				return err
			}
			diags := l.Validate()
			if len(diags.Items) > 0 {
				fmt.Fprint(cmd.ErrOrStderr(), diags.String())
			}
			if diags.HasErrors() {
				return fmt.Errorf("%d error(s) found", len(diags.Errors()))
			}
			// Expansion is part of validation: it catches cross-references that
			// only resolve once templates are instantiated.
			res, err := expand.Expand(l.Lab)
			if err != nil {
				return err
			}
			s := res.Topology.Stats()
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s is valid: %d ASes, %d devices (%d routers, %d hosts, %d switches), %d links (%d inter-AS), %d services\n",
				l.Lab.Metadata.Name, s.ASes, s.Devices, s.Routers, s.Hosts, s.Switches, s.Links, s.InterAS, s.Services)
			return nil
		},
	}
}

func newInspectCmd(opts *Options) *cobra.Command {
	var (
		showLinks   bool
		showIfaces  bool
		showAddr    bool
		filterAS    int
		filterOwner string
	)
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show the expanded topology",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := load(opts)
			if err != nil {
				return err
			}
			if opts.JSON {
				return emitJSON(cmd.OutOrStdout(), top, showLinks, showIfaces)
			}
			out := cmd.OutOrStdout()
			s := top.Stats()
			fmt.Fprintf(out, "lab %s  hash %s\n", top.Name, top.Hash)
			fmt.Fprintf(out, "  %d ASes, %d devices, %d links (%d inter-AS, %d cross-node)\n\n",
				s.ASes, s.Devices, s.Links, s.InterAS, s.CrossNode)

			if showLinks {
				w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "LINK\tSUBNET\tBW\tDELAY\tREL\tVNI\tOWNER")
				for _, l := range top.Links {
					if filterAS > 0 && l.A.Device.ASN != filterAS && l.B.Device.ASN != filterAS {
						continue
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
						shortLink(l), dash(l.Subnet), dash(l.Props.Bandwidth),
						dash(l.Props.Delay), dash(string(l.Rel)), l.VNI, l.Owner)
				}
				return w.Flush()
			}

			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "DEVICE\tKIND\tAS\tROLE\tNODE\tOWNER\tIFACES\tCONTAINER")
			for _, d := range top.SortedDevices() {
				if filterAS > 0 && d.ASN != filterAS {
					continue
				}
				if filterOwner != "" && d.Owner != filterOwner {
					continue
				}
				role := ""
				if as, ok := top.ASes[d.ASN]; ok {
					role = string(as.Role)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
					d.ID, d.Kind, asLabel(d.ASN), role, dash(d.Node), dash(d.Owner), len(d.Ifaces), d.Container)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if showIfaces || showAddr {
				fmt.Fprintln(out)
				iw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(iw, "DEVICE\tIFACE\tROLE\tADDR4\tADDR6\tVLAN\tOWNER\tPEER")
				for _, d := range top.SortedDevices() {
					if filterAS > 0 && d.ASN != filterAS {
						continue
					}
					for _, i := range d.Ifaces {
						peer := ""
						if i.Peer != nil {
							peer = i.Peer.Device.ID + ":" + i.Peer.Name
						}
						vlan := ""
						if i.VLAN > 0 {
							vlan = fmt.Sprint(i.VLAN)
						} else if i.Trunk {
							vlan = "trunk"
						}
						fmt.Fprintf(iw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
							d.ID, i.Name, i.Role, dash(i.Addr4), dash(i.Addr6), dash(vlan), i.Owner, dash(peer))
					}
				}
				return iw.Flush()
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showLinks, "links", false, "list links instead of devices")
	cmd.Flags().BoolVar(&showIfaces, "ifaces", false, "also list interfaces")
	cmd.Flags().BoolVar(&showAddr, "addresses", false, "also list interface addresses")
	cmd.Flags().IntVar(&filterAS, "as", 0, "restrict output to one AS")
	cmd.Flags().StringVar(&filterOwner, "owner", "", "restrict output to one owner group")
	return cmd
}

func newGraphCmd(opts *Options) *cobra.Command {
	var (
		format string
		asOnly bool
	)
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Render the topology as a graph",
		RunE: func(cmd *cobra.Command, _ []string) error {
			top, err := load(opts)
			if err != nil {
				return err
			}
			switch format {
			case "dot":
				return writeDot(cmd.OutOrStdout(), top, asOnly)
			case "mermaid":
				return writeMermaid(cmd.OutOrStdout(), top, asOnly)
			default:
				return fmt.Errorf("unknown format %q (dot, mermaid)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "dot", "output format: dot or mermaid")
	cmd.Flags().BoolVar(&asOnly, "as-level", false, "draw the AS-level graph only")
	return cmd
}

func writeDot(w interface{ Write([]byte) (int, error) }, top *model.Topology, asOnly bool) error {
	var b strings.Builder
	b.WriteString("graph twinet {\n  rankdir=LR;\n  node [shape=box, fontname=\"Helvetica\"];\n")
	if asOnly {
		for _, asn := range top.SortedASNs() {
			as := top.ASes[asn]
			b.WriteString(fmt.Sprintf("  as%d [label=\"AS%d\\n%s\", style=filled, fillcolor=\"%s\"];\n",
				asn, asn, as.Role, roleColour(as.Role)))
		}
		seen := map[string]bool{}
		for _, l := range top.Links {
			if !l.InterAS {
				continue
			}
			a, bb := l.A.Device.ASN, l.B.Device.ASN
			if a > bb {
				a, bb = bb, a
			}
			key := fmt.Sprintf("%d-%d", a, bb)
			if seen[key] {
				continue
			}
			seen[key] = true
			b.WriteString(fmt.Sprintf("  as%d -- as%d [label=%q];\n", a, bb, l.Rel))
		}
	} else {
		for _, asn := range top.SortedASNs() {
			b.WriteString(fmt.Sprintf("  subgraph cluster_as%d {\n    label=\"AS%d\";\n", asn, asn))
			for _, d := range top.ASes[asn].Devices {
				b.WriteString(fmt.Sprintf("    %q [label=%q, shape=%s];\n", d.ID, d.Name, dotShape(d.Kind)))
			}
			b.WriteString("  }\n")
		}
		for _, l := range top.Links {
			style := ""
			if l.InterAS {
				style = ", style=bold"
			}
			b.WriteString(fmt.Sprintf("  %q -- %q [label=%q%s];\n",
				l.A.Device.ID, l.B.Device.ID, dash(l.Props.Delay), style))
		}
	}
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

func writeMermaid(w interface{ Write([]byte) (int, error) }, top *model.Topology, asOnly bool) error {
	var b strings.Builder
	b.WriteString("graph LR\n")
	if asOnly {
		seen := map[string]bool{}
		for _, l := range top.Links {
			if !l.InterAS {
				continue
			}
			a, bb := l.A.Device.ASN, l.B.Device.ASN
			if a > bb {
				a, bb = bb, a
			}
			key := fmt.Sprintf("%d-%d", a, bb)
			if seen[key] {
				continue
			}
			seen[key] = true
			b.WriteString(fmt.Sprintf("  AS%d ---|%s| AS%d\n", a, l.Rel, bb))
		}
	} else {
		for _, l := range top.Links {
			b.WriteString(fmt.Sprintf("  %s --- %s\n",
				mermaidID(l.A.Device.ID), mermaidID(l.B.Device.ID)))
		}
	}
	_, err := w.Write([]byte(b.String()))
	return err
}

func emitJSON(w interface{ Write([]byte) (int, error) }, top *model.Topology, links, ifaces bool) error {
	type ifaceOut struct {
		Name  string `json:"name"`
		Role  string `json:"role"`
		Addr4 string `json:"addr4,omitempty"`
		Addr6 string `json:"addr6,omitempty"`
		MAC   string `json:"mac,omitempty"`
		VLAN  int    `json:"vlan,omitempty"`
		Trunk bool   `json:"trunk,omitempty"`
		Owner string `json:"owner"`
		Peer  string `json:"peer,omitempty"`
	}
	type devOut struct {
		ID        string     `json:"id"`
		Kind      string     `json:"kind"`
		AS        int        `json:"as,omitempty"`
		Node      string     `json:"node,omitempty"`
		Owner     string     `json:"owner,omitempty"`
		Container string     `json:"container"`
		Image     string     `json:"image"`
		Ifaces    []ifaceOut `json:"ifaces,omitempty"`
	}
	type linkOut struct {
		ID      string `json:"id"`
		A       string `json:"a"`
		B       string `json:"b"`
		Subnet  string `json:"subnet,omitempty"`
		Rel     string `json:"rel,omitempty"`
		InterAS bool   `json:"inter_as,omitempty"`
		VNI     uint32 `json:"vni"`
		Owner   string `json:"owner"`
		model.LinkProps
	}
	out := struct {
		Lab     string      `json:"lab"`
		Hash    string      `json:"hash"`
		Stats   model.Stats `json:"stats"`
		Devices []devOut    `json:"devices,omitempty"`
		Links   []linkOut   `json:"links,omitempty"`
	}{Lab: top.Name, Hash: top.Hash, Stats: top.Stats()}

	for _, d := range top.SortedDevices() {
		do := devOut{ID: d.ID, Kind: string(d.Kind), AS: d.ASN, Node: d.Node,
			Owner: d.Owner, Container: d.Container, Image: d.Image}
		if ifaces {
			for _, i := range d.Ifaces {
				io := ifaceOut{Name: i.Name, Role: string(i.Role), Addr4: i.Addr4, Addr6: i.Addr6,
					MAC: i.MAC, VLAN: i.VLAN, Trunk: i.Trunk, Owner: string(i.Owner)}
				if i.Peer != nil {
					io.Peer = i.Peer.Device.ID + ":" + i.Peer.Name
				}
				do.Ifaces = append(do.Ifaces, io)
			}
		}
		out.Devices = append(out.Devices, do)
	}
	if links {
		for _, l := range top.Links {
			out.Links = append(out.Links, linkOut{
				ID: l.ID, A: l.A.Device.ID + ":" + l.A.Name, B: l.B.Device.ID + ":" + l.B.Name,
				Subnet: l.Subnet, Rel: string(l.Rel), InterAS: l.InterAS, VNI: l.VNI,
				Owner: string(l.Owner), LinkProps: l.Props,
			})
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func shortLink(l *model.Link) string {
	return fmt.Sprintf("%s:%s -- %s:%s", l.A.Device.ID, l.A.Name, l.B.Device.ID, l.B.Name)
}

func asLabel(asn int) string {
	if asn == 0 {
		return "-"
	}
	return fmt.Sprint(asn)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func dotShape(k model.DeviceKind) string {
	switch k {
	case model.KindRouter:
		return "box3d"
	case model.KindSwitch:
		return "component"
	case model.KindService:
		return "cylinder"
	default:
		return "box"
	}
}

func roleColour(r model.ASRole) string {
	switch r {
	case model.RoleStudent:
		return "lightblue"
	case model.RoleIXP:
		return "lightyellow"
	default:
		return "lightgrey"
	}
}

func mermaidID(s string) string {
	return strings.NewReplacer("/", "_", ":", "_", "-", "_", ".", "_").Replace(s)
}

func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}
