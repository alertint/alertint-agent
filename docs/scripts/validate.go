// Command validate checks the docs tree against the conventions documented
// in docs/README.md:
//
//   - every page in a section directory has frontmatter with the required
//     fields (title, description, section, order, slug)
//   - slugs are unique across the whole tree
//   - the frontmatter section matches a section title in meta.yaml, and the
//     file lives in the directory named by that section's id
//   - each page has exactly one H1, and it matches the frontmatter title
//   - fenced code blocks declare a language
//
// Usage: go run ./docs/scripts [docs-dir]   (default: ./docs)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type section struct {
	ID    string `yaml:"id"`
	Title string `yaml:"title"`
	Order int    `yaml:"order"`
}

type meta struct {
	SiteTitle string    `yaml:"site_title"`
	Sections  []section `yaml:"sections"`
}

type frontmatter struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Section     string `yaml:"section"`
	Order       int    `yaml:"order"`
	Slug        string `yaml:"slug"`
}

// Directories under docs/ that hold tooling rather than pages.
var skipDirs = map[string]bool{
	"assets":  true,
	"scripts": true,
}

func main() {
	docsDir := "docs"
	if len(os.Args) > 1 {
		docsDir = os.Args[1]
	}

	errs := run(docsDir)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "docs validate:", e)
		}
		fmt.Fprintf(os.Stderr, "docs validate: %d problem(s) found\n", len(errs))
		os.Exit(1)
	}
}

func run(docsDir string) []string {
	m, errs := loadMeta(filepath.Join(docsDir, "meta.yaml"))
	if m == nil {
		return errs
	}

	titleByDir := make(map[string]string, len(m.Sections))
	for _, s := range m.Sections {
		titleByDir[s.ID] = s.Title
	}

	slugSeen := make(map[string]string) // slug -> first file that used it
	pages := 0

	walkErr := filepath.WalkDir(docsDir, func(path string, d os.DirEntry, err error) error { // #nosec G703 -- docs dir comes from the CLI argument; this is a repo-local lint tool
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(docsDir, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			if rel != "." && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Pages live in section directories; top-level files (README.md,
		// meta.yaml, legacy docs pending migration) are not rendered.
		if filepath.Ext(path) != ".md" || !strings.Contains(rel, string(filepath.Separator)) {
			return nil
		}
		pages++
		errs = append(errs, checkPage(path, rel, titleByDir, slugSeen)...)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr.Error())
	}
	if len(errs) == 0 {
		_, _ = fmt.Fprintf(os.Stdout, "docs validate: OK (%d pages, %d sections)\n", pages, len(m.Sections))
	}
	return errs
}

func loadMeta(path string) (*meta, []string) {
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- path is derived from the docs dir argument, not untrusted input
	if err != nil {
		return nil, []string{err.Error()}
	}
	var m meta
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", path, err)}
	}

	var errs []string
	ids := make(map[string]bool)
	orders := make(map[int]string)
	for _, s := range m.Sections {
		switch {
		case s.ID == "":
			errs = append(errs, fmt.Sprintf("%s: section with empty id", path))
		case ids[s.ID]:
			errs = append(errs, fmt.Sprintf("%s: duplicate section id %q", path, s.ID))
		default:
			ids[s.ID] = true
		}
		if s.Title == "" {
			errs = append(errs, fmt.Sprintf("%s: section %q has no title", path, s.ID))
		}
		if prev, dup := orders[s.Order]; dup {
			errs = append(errs, fmt.Sprintf("%s: sections %q and %q share order %d", path, prev, s.ID, s.Order))
		} else {
			orders[s.Order] = s.ID
		}
	}
	if len(m.Sections) == 0 {
		errs = append(errs, fmt.Sprintf("%s: no sections defined", path))
	}
	return &m, errs
}

func checkPage(path, rel string, titleByDir map[string]string, slugSeen map[string]string) []string {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from walking the docs tree
	if err != nil {
		return []string{err.Error()}
	}

	fm, body, err := splitFrontmatter(string(raw))
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", path, err)}
	}

	var errs []string
	for field, value := range map[string]string{
		"title":       fm.Title,
		"description": fm.Description,
		"section":     fm.Section,
		"slug":        fm.Slug,
	} {
		if value == "" {
			errs = append(errs, fmt.Sprintf("%s: missing required frontmatter field %q", path, field))
		}
	}
	if fm.Order <= 0 {
		errs = append(errs, fmt.Sprintf("%s: frontmatter \"order\" must be a positive integer", path))
	}

	if fm.Slug != "" {
		if first, dup := slugSeen[fm.Slug]; dup {
			errs = append(errs, fmt.Sprintf("%s: slug %q already used by %s", path, fm.Slug, first))
		} else {
			slugSeen[fm.Slug] = path
		}
	}

	dir := strings.SplitN(rel, string(filepath.Separator), 2)[0]
	sectionTitle, known := titleByDir[dir]
	if !known {
		errs = append(errs, fmt.Sprintf("%s: directory %q is not a section id in meta.yaml", path, dir))
	} else if fm.Section != "" && fm.Section != sectionTitle {
		errs = append(errs, fmt.Sprintf("%s: frontmatter section %q does not match meta.yaml title %q for directory %q", path, fm.Section, sectionTitle, dir))
	}

	errs = append(errs, checkBody(path, fm.Title, body)...)
	return errs
}

func splitFrontmatter(content string) (frontmatter, string, error) {
	var fm frontmatter
	rest, ok := strings.CutPrefix(content, "---\n")
	if !ok {
		return fm, "", fmt.Errorf("missing frontmatter (file must start with ---)")
	}
	yamlPart, body, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return fm, "", fmt.Errorf("unterminated frontmatter (no closing ---)")
	}
	if err := yaml.Unmarshal([]byte(yamlPart), &fm); err != nil {
		return fm, "", fmt.Errorf("invalid frontmatter YAML: %v", err)
	}
	return fm, body, nil
}

var fenceRe = regexp.MustCompile("^\\s*(`{3,}|~{3,})\\s*(\\S*)")

func checkBody(path, title, body string) []string {
	var errs []string
	var h1s []string
	inFence := false
	for i, line := range strings.Split(body, "\n") {
		if m := fenceRe.FindStringSubmatch(line); m != nil {
			if !inFence && m[2] == "" {
				errs = append(errs, fmt.Sprintf("%s: code block at body line %d does not declare a language", path, i+1))
			}
			inFence = !inFence
			continue
		}
		if !inFence && strings.HasPrefix(line, "# ") {
			h1s = append(h1s, strings.TrimSpace(strings.TrimPrefix(line, "# ")))
		}
	}
	switch {
	case len(h1s) == 0:
		errs = append(errs, fmt.Sprintf("%s: no H1 heading", path))
	case len(h1s) > 1:
		errs = append(errs, fmt.Sprintf("%s: %d H1 headings, expected exactly one", path, len(h1s)))
	case h1s[0] != title:
		errs = append(errs, fmt.Sprintf("%s: H1 %q does not match frontmatter title %q", path, h1s[0], title))
	}
	return errs
}
