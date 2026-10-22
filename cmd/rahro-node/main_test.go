package main

import "testing"

// TestParseEnrollArgs guards the flag-ordering bug: the connection code is the
// first positional, and flags after it (-panel, -insecure, -out) must parse.
func TestParseEnrollArgs(t *testing.T) {
	e, err := parseEnrollArgs([]string{"CODE123", "-panel", "https://p:2053", "-insecure", "-out", "/tmp/n.json"})
	if err != nil {
		t.Fatalf("valid args rejected: %v", err)
	}
	if e.code != "CODE123" {
		t.Errorf("code = %q", e.code)
	}
	if e.panel != "https://p:2053" {
		t.Errorf("panel = %q", e.panel)
	}
	if !e.insecure {
		t.Error("insecure flag not parsed")
	}
	if e.out != "/tmp/n.json" {
		t.Errorf("out = %q", e.out)
	}
}

func TestParseEnrollArgsDefaults(t *testing.T) {
	e, err := parseEnrollArgs([]string{"CODE", "-panel", "https://p:2053"})
	if err != nil {
		t.Fatal(err)
	}
	if e.insecure {
		t.Error("insecure should default false")
	}
	if e.out != "rahro-node.json" {
		t.Errorf("default out = %q", e.out)
	}
}

func TestParseEnrollArgsErrors(t *testing.T) {
	// No code.
	if _, err := parseEnrollArgs([]string{"-panel", "https://p:2053"}); err == nil {
		t.Error("missing code should error")
	}
	// No panel.
	if _, err := parseEnrollArgs([]string{"CODE"}); err == nil {
		t.Error("missing -panel should error")
	}
	// Empty.
	if _, err := parseEnrollArgs(nil); err == nil {
		t.Error("no args should error")
	}
}
