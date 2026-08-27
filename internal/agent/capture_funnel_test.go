package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// The other half of the same question, asked of the package that captures most
// often.
//
// Reading a container and writing what was read into the state store is guarded
// inside the deployment engine, and the guard is only worth what the paths
// through it are worth. The agent had one path that read containers itself and
// wrote the results straight into the store -- the export that hands a device to
// another node -- and it looked exactly like the code beside it. So the reading
// is checked here too: the agent may read a container directly only where it is
// verifying something, and everything that means to keep what it read goes
// through the engine's capture API.
func TestTheAgentOnlyReadsAContainerDirectlyToVerify(t *testing.T) {
	// verifyRestoredState compares what came back against what was replayed.
	// It never writes what it read.
	allowed := map[string]bool{"verifyRestoredState": true}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
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
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "Capture" {
						return true
					}
					pkgName, ok := selector.X.(*ast.Ident)
					if !ok || pkgName.Name != "deploy" {
						return true
					}
					seen[fn.Name.Name] = true
					return true
				})
			}
		}
	}
	if len(seen) == 0 {
		t.Error("nothing in this package reads a container directly any more, so this " +
			"test is watching the wrong thing")
	}
	for name := range seen {
		if !allowed[name] {
			t.Errorf("%s reads a container directly: if what it reads is going to be "+
				"kept, it has to go through the engine's capture API, which is where the "+
				"check that the namespace is the one the saved state came out of lives",
				name)
		}
	}
}
