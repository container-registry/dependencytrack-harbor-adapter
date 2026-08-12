package main

import "testing"

func TestScannerIdentity(t *testing.T) {
	if scannerName != "waybill" {
		t.Fatalf("scannerName = %q, want %q", scannerName, "waybill")
	}
	if scannerVendor != "Kusari" {
		t.Fatalf("scannerVendor = %q, want %q", scannerVendor, "Kusari")
	}
}
