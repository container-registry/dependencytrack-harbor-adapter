package main

import "testing"

// The scanner identity is what Harbor stores against every report and shows in
// the scanner list. Changing it after registration makes Harbor treat this as a
// different scanner, so it is pinned by a test rather than left to a rename.
func TestScannerIdentity(t *testing.T) {
	if scannerName != "Dependency-Track" {
		t.Fatalf("scannerName = %q, want %q", scannerName, "Dependency-Track")
	}
	if scannerVendor != "container-registry.com" {
		t.Fatalf("scannerVendor = %q, want %q", scannerVendor, "container-registry.com")
	}
}
