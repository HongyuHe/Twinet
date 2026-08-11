package expand

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
)

// The topology hash answers one question: is this the lab the work was done
// against? Save records it, restore refuses an archive whose hash does not
// match, and preserved state is keyed by it.
//
// It used to be a hand-written list of fields. That list omitted the business
// relationship on inter-AS links, the shared-segment name, the IPv6 subnet,
// loss, MTU, and every interface role. So a course author could invert a
// provider into a customer -- changing which routes are exported, which is the
// entire subject of the assignment and the thing the rubric checks -- and the
// hash would not move. Submissions graded against the old policy were accepted
// against the new one, and nothing anywhere reported a mismatch.
//
// The list did not omit those fields on purpose. It was written once, correctly,
// and then the model grew. Any hand-written list has this failure mode, and it
// fails silently and in the direction of accepting work that should be refused.
//
// So the hash is taken structurally: walk the compiled topology and write every
// exported field. Adding a field to the model changes the hash automatically.
// The only things skipped are named below, each because including it would make
// the hash wrong rather than more complete.
func canonicalise(w io.Writer, top *model.Topology) {
	for _, d := range top.SortedDevices() {
		fmt.Fprintf(w, "device %s\n", d.ID)
		writeStruct(w, "  ", reflect.ValueOf(*d))
		for _, i := range d.Ifaces {
			fmt.Fprintf(w, "  iface %s\n", i.Name)
			writeStruct(w, "    ", reflect.ValueOf(*i))
		}
	}
	links := append([]*model.Link(nil), top.Links...)
	sort.Slice(links, func(a, b int) bool { return links[a].ID < links[b].ID })
	for _, l := range links {
		fmt.Fprintf(w, "link %s\n", l.ID)
		writeStruct(w, "  ", reflect.ValueOf(*l))
	}
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		fmt.Fprintf(w, "as %d\n", asn)
		writeStruct(w, "  ", reflect.ValueOf(*as))
	}
	// Services are walked here, and not reached through the device that hosts
	// them, because their configuration decides how the network behaves and
	// the device does not carry it.
	//
	// The RPKI validator is the clearest case. Which ASes are deliberately
	// left without a ROA, and which have a deliberately wrong one, is the
	// entire content of that exercise -- the student's task is to notice
	// exactly those and drop the routes. Both lists live in the service's
	// spec. Without this, a course author could move an AS from "valid" to
	// "not found", inverting the expected answer, and the hash would not
	// move: work done against one exercise would be accepted and graded
	// against a different one, with nothing anywhere reporting a mismatch.
	// The lab's own declarations are hashed as well, because some of them
	// decide how the network behaves and never appear in a device, a link or
	// an AS.
	//
	// The RPKI trust anchor is the case that proved it. Which ASes are
	// deliberately left without a ROA, and which hold one for somebody else's
	// prefix, is the entire content of that exercise -- the student's job is
	// to notice exactly those. Both lists live on the lab. Without this, a
	// course author could move an AS from "valid" to "not found", inverting
	// the expected answer, and the hash would not move: work done against one
	// exercise would be accepted and graded against a different one, with
	// nothing anywhere reporting a mismatch.
	//
	// It is a structural walk with named exclusions rather than a list of the
	// fields that matter, for the same reason the rest of this file is: a list
	// of what matters is correct when written and silently wrong afterwards.
	if top.Lab != nil {
		writeString(w, "lab\n")
		writeStruct(w, "  ", reflect.ValueOf(*top.Lab))
	}

	names := make([]string, 0, len(top.Services))
	for n := range top.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "service %s\n", n)
		writeStruct(w, "  ", reflect.ValueOf(*top.Services[n]))
	}
}

// skipped names fields that must not contribute to the hash.
//
// Every entry is either a back-pointer, which would make the walk infinite, or
// a value that legitimately differs between two deployments of the same lab.
// Nothing is skipped merely because writing it was inconvenient.
var skipped = map[string]string{
	// Back-references. The object they point at is written in its own right,
	// so following them would recurse forever and add nothing.
	"Device":   "back-reference to the owning device",
	"Link":     "back-reference; the link is hashed separately",
	"Peer":     "back-reference; the peer interface is hashed under its own device",
	"A":        "endpoint back-reference; interfaces are hashed under their devices",
	"B":        "endpoint back-reference; interfaces are hashed under their devices",
	"Ifaces":   "hashed explicitly, in order, by the caller",
	"Devices":  "the AS's device list repeats what is already hashed per device",
	"Routers":  "as above",
	"Hosts":    "as above",
	"Switches": "as above",
	"Services": "as above",

	// Deployment facts, not topology. Two clusters running the same lab must
	// agree on the hash, or a submission could never be graded anywhere but
	// the machine it was made on.
	"Node":   "which cluster machine holds the device; placement is not topology",
	"Labels": "container labels carry the node and lab name, which vary by deployment",

	// Lab fields that describe the deployment rather than the exercise. The
	// same lab must hash identically on a laptop and on a twelve-node cluster,
	// or a submission could only ever be graded on the machine it was made on.
	"Placement": "which machines run the lab, and how many; not part of the exercise",
	"Dir":       "the directory the manifest was read from",
	"Access":    "how students reach their devices: ports and keys, not topology",
}

// writeString ignores the error deliberately: the writer is a hash, which
// cannot fail, and threading an error through every branch of a tree walk to
// satisfy that would obscure what the walk does.
func writeString(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
}

func writeStruct(w io.Writer, indent string, v reflect.Value) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, ok := skipped[f.Name]; ok {
			continue
		}
		fmt.Fprintf(w, "%s%s=", indent, f.Name)
		writeValue(w, v.Field(i))
		fmt.Fprintln(w)
	}
}

func writeValue(w io.Writer, v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			writeString(w, "nil")
			return
		}
		writeValue(w, v.Elem())
	case reflect.Struct:
		writeString(w, "{")
		writeStructInline(w, v)
		writeString(w, "}")
	case reflect.Slice, reflect.Array:
		writeString(w, "[")
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				writeString(w, ",")
			}
			writeValue(w, v.Index(i))
		}
		writeString(w, "]")
	case reflect.Map:
		// Sorted, so that Go's randomised map order does not make the hash of
		// one topology differ from run to run -- which would reject every
		// archive, including correct ones.
		keys := v.MapKeys()
		sort.Slice(keys, func(a, b int) bool {
			return fmt.Sprint(keys[a].Interface()) < fmt.Sprint(keys[b].Interface())
		})
		writeString(w, "{")
		for i, k := range keys {
			if i > 0 {
				writeString(w, ",")
			}
			fmt.Fprintf(w, "%v:", k.Interface())
			writeValue(w, v.MapIndex(k))
		}
		writeString(w, "}")
	default:
		fmt.Fprintf(w, "%v", v.Interface())
	}
}

func writeStructInline(w io.Writer, v reflect.Value) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, ok := skipped[f.Name]; ok {
			continue
		}
		if i > 0 {
			writeString(w, ",")
		}
		fmt.Fprintf(w, "%s=", f.Name)
		writeValue(w, v.Field(i))
	}
}

// TopologyHash returns the identity of a compiled topology.
func TopologyHash(top *model.Topology) string {
	h := sha256.New()
	canonicalise(h, top)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
