// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreTestsUseSharedSetup(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read store package: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || function.Name.Name == "openTestStoreWithMigrations" {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, ok := call.Fun.(*ast.Ident)
				if !ok || name.Name != "Open" {
					return true
				}
				position := fset.Position(call.Pos())
				t.Errorf("%s: direct Open bypasses shared store test setup; use newTestStore for ordinary tests or openTestStoreWithMigrations for migration, upgrade, reopen, and persistence coverage", filepath.ToSlash(position.String()))
				return true
			})
		}
	}
}
