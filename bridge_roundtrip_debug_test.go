//go:build cgobridge_test

package main

import "testing"

// TestBridgeRoundTrip drives the real plugin->host C callback bridge via the
// build-tagged debug driver and asserts the host buffer-release contract.
func TestBridgeRoundTrip(t *testing.T) {
	calls, frees, err := debugBridgeRoundTrip()
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if calls != 1 {
		t.Fatalf("host call count = %d, want 1", calls)
	}
	if frees != 1 {
		t.Fatalf("host free count = %d, want 1", frees)
	}
}
