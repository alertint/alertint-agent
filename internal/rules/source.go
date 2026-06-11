// SPDX-License-Identifier: FSL-1.1-ALv2

package rules

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleSource supplies one rule pack to the engine. The engine merges packs
// from all sources in priority order (higher priority wins on conflicting
// rule ids and template names).
//
// EmbeddedSource is the only implementation today. A future FeedSource
// (HTTPS fetch → ed25519 signature verification via VerifyPackSignature →
// local cache → hot reload) implements the same interface; the engine does
// not change.
type RuleSource interface {
	// Name identifies the source in logs and error messages.
	Name() string
	// Priority orders sources; higher values override lower ones.
	Priority() int
	// Load reads and parses the pack. It does not validate rules — the
	// engine validates after merging so error reporting is uniform.
	Load(ctx context.Context) (*Pack, error)
}

// PackMeta is the pack.yaml header.
type PackMeta struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Updated     string `yaml:"updated"`
	Description string `yaml:"description,omitempty"`
}

// FlapConfig holds generic flap-detection thresholds shipped as pack
// content: an alert that transitions firing→resolved at least
// MinTransitions times within WindowSeconds is considered flapping.
type FlapConfig struct {
	WindowSeconds  int `yaml:"window_seconds"`
	MinTransitions int `yaml:"min_transitions"`
}

// PackDefaults carries tunables that are content, not engine mechanism.
type PackDefaults struct {
	Flap FlapConfig `yaml:"flap"`
}

// Pack is one parsed rule pack: metadata, defaults, rules, and prompt
// templates (keyed by file basename without extension).
type Pack struct {
	Meta      PackMeta
	Defaults  PackDefaults
	Rules     []Rule
	Templates map[string]string
}

// packManifest is the on-disk shape of pack.yaml.
type packManifest struct {
	PackMeta `yaml:",inline"`

	Defaults PackDefaults `yaml:"defaults"`
}

// ruleFile is the on-disk shape of each rules/*.yaml file.
type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// EmbeddedSource loads a pack from an fs.FS with the standard pack layout:
//
//	pack.yaml            metadata + defaults
//	rules/*.yaml         rule lists, loaded in lexical order
//	templates/*.md       LLM prompt templates
type EmbeddedSource struct {
	fsys     fs.FS
	name     string
	priority int
}

// NewEmbeddedSource wraps fsys as a RuleSource. The embedded baseline pack
// uses priority 0 so every other source can override it.
func NewEmbeddedSource(fsys fs.FS, name string, priority int) *EmbeddedSource {
	return &EmbeddedSource{fsys: fsys, name: name, priority: priority}
}

func (s *EmbeddedSource) Name() string  { return s.name }
func (s *EmbeddedSource) Priority() int { return s.priority }

// Load implements RuleSource.
func (s *EmbeddedSource) Load(_ context.Context) (*Pack, error) {
	manifestBytes, err := fs.ReadFile(s.fsys, "pack.yaml")
	if err != nil {
		return nil, fmt.Errorf("pack %s: read pack.yaml: %w", s.name, err)
	}
	var manifest packManifest
	if err := yaml.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("pack %s: parse pack.yaml: %w", s.name, err)
	}

	pack := &Pack{
		Meta:      manifest.PackMeta,
		Defaults:  manifest.Defaults,
		Templates: map[string]string{},
	}

	ruleFiles, err := fs.Glob(s.fsys, "rules/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("pack %s: list rules: %w", s.name, err)
	}
	sort.Strings(ruleFiles)
	for _, rf := range ruleFiles {
		b, err := fs.ReadFile(s.fsys, rf)
		if err != nil {
			return nil, fmt.Errorf("pack %s: read %s: %w", s.name, rf, err)
		}
		var parsed ruleFile
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true) // unknown fields are schema drift; fail loud
		if err := dec.Decode(&parsed); err != nil {
			return nil, fmt.Errorf("pack %s: parse %s: %w", s.name, rf, err)
		}
		pack.Rules = append(pack.Rules, parsed.Rules...)
	}

	templateFiles, err := fs.Glob(s.fsys, "templates/*.md")
	if err != nil {
		return nil, fmt.Errorf("pack %s: list templates: %w", s.name, err)
	}
	for _, tf := range templateFiles {
		b, err := fs.ReadFile(s.fsys, tf)
		if err != nil {
			return nil, fmt.Errorf("pack %s: read %s: %w", s.name, tf, err)
		}
		key := strings.TrimSuffix(path.Base(tf), ".md")
		pack.Templates[key] = strings.TrimSpace(string(b))
	}

	return pack, nil
}
