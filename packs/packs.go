// SPDX-License-Identifier: FSL-1.1-ALv2

// Package packs embeds the rule packs that ship inside the binary.
// The baseline pack is the zero-config default: the engine always loads
// it, so the runtime triages incidents with no rules configuration at all.
package packs

import (
	"embed"
	"io/fs"
)

//go:embed baseline
var baseline embed.FS

// BaselineFS returns the baseline pack rooted at its pack.yaml.
func BaselineFS() fs.FS {
	sub, err := fs.Sub(baseline, "baseline")
	if err != nil {
		// Unreachable: "baseline" is embedded at compile time.
		panic(err)
	}
	return sub
}
