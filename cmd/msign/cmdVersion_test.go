//go:build showversion
// +build showversion

package main

import (
	"bytes"
	"strings"
	"testing"
)

// Minimal test to assert --short version flag prints git hash (ldflag injected variable or default)
func TestVersionShort(t *testing.T) {
	// Ensure githash has some default value
	if githash == "" {
		t.Fatalf("expected githash to be set (even default 'not set')")
	}

	// Build command tree (rootCmd is global)
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version", "--short"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute version --short failed: %v", err)
	}

	out := strings.TrimSpace(buf.String())
	if out == "" {
		t.Fatalf("expected output, got empty string")
	}
	// Should contain (or equal) githash substring; default may have spaces
	if !strings.Contains(githash, strings.TrimSpace(out)) && !strings.Contains(out, strings.TrimSpace(githash)) {
		// Accept either equality or containment to be resilient if build metadata formatting changes
		t.Fatalf("unexpected short version output: %q (githash=%q)", out, githash)
	}
}
