package main

import "testing"

func TestEnvOr(t *testing.T) {
	t.Setenv("SCANNER_TEST_KEY", "set")
	if got := envOr("SCANNER_TEST_KEY", "fallback"); got != "set" {
		t.Fatalf("envOr with value set = %q, want %q", got, "set")
	}
	if got := envOr("SCANNER_TEST_UNSET_KEY", "fallback"); got != "fallback" {
		t.Fatalf("envOr with unset key = %q, want %q", got, "fallback")
	}
}
