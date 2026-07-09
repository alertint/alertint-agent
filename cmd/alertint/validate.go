// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/alertint/alertint-agent/internal/config"
)

// runValidate implements `alertint validate <config>`: an nginx -t style
// dry-run of the strict config loader. It parses with unknown-key rejection
// and runs the full validation minus environment-coupled filesystem checks,
// so a pod-destined config validates cleanly on a laptop or CI runner.
// Exit is 0 when the config is valid, 1 otherwise. No environment variables
// are read; secret presence is a serve-time concern.
func runValidate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to alertint YAML config (alternative to the positional argument)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := strings.TrimSpace(*cfgPath)
	rest := fs.Args()
	if path == "" && len(rest) > 0 {
		path = rest[0]
		rest = rest[1:]
	}
	if len(rest) > 0 {
		return fmt.Errorf("validate: unexpected extra arguments: %s", strings.Join(rest, " "))
	}
	if path == "" {
		return errors.New("validate: config path required: alertint validate <config.yaml>")
	}

	cfg, err := config.LoadOffline(path)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings() {
		_, _ = fmt.Fprintf(stdout, "warning: %s\n", w)
	}
	_, _ = fmt.Fprintf(stdout, "configuration %s is valid\n", path)
	return nil
}
