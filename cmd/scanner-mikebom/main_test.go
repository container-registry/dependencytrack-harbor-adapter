package main

import "testing"

func TestScannerIdentity(t *testing.T) {
	if scannerName != "mikebom" {
		t.Fatalf("scannerName = %q, want %q", scannerName, "mikebom")
	}
	if scannerVendor != "Kusari" {
		t.Fatalf("scannerVendor = %q, want %q", scannerVendor, "Kusari")
	}
}
