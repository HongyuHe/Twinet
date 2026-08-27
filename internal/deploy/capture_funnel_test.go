package deploy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// The guard is only worth what the paths through it are worth.
//
// Three separate call sites read a container and wrote the result into the
// state store on their own, and each of them was written by somebody who had
// the whole of their own path in their head and none of the others. That is
// how a fourth gets written, so this asks the source directly: reading a
// container is allowed in a few named places, and writing what was read is
// allowed in exactly one.
//
// If a new caller belongs here, adding it to a list is the smallest possible
// price for the reader who has to work out, a year from now, which paths can
// destroy a term's work.
func TestOnlyTheGuardedFunnelWritesACapture(t *testing.T) {
	readers := map[string]bool{
		// Reads what a set of devices' namespaces and filesystems hold, then
		// hands the whole batch to the funnel.
		"captureSelected": true,
		// Reads one device before its container is replaced.
		"captureBeforeReplace": true,
		// Reads each candidate before its container is deleted.
		"PruneOrphans": true,
	}
	writers := map[string]bool{"storeCaptured": true}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fun := call.Fun.(type) {
					case *ast.Ident:
						if fun.Name == "Capture" {
							found["read"] = append(found["read"], fn.Name.Name)
						}
					case *ast.SelectorExpr:
						if fun.Sel.Name == "Put" {
							found["write"] = append(found["write"], fn.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
	for _, check := range []struct {
		what    string
		allowed map[string]bool
		why     string
	}{
		{"read", readers, "reads a container's state"},
		{"write", writers, "writes captured state into the store"},
	} {
		for _, name := range unique(found[check.what]) {
			if !check.allowed[name] {
				t.Errorf("%s %s outside the guarded funnel: an empty namespace read here "+
					"goes into the store without anything establishing that it is the one "+
					"the saved state came out of", name, check.why)
			}
		}
		if len(found[check.what]) == 0 {
			t.Errorf("nothing in this package %s any more, so this test is watching "+
				"the wrong thing", check.why)
		}
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range in {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
