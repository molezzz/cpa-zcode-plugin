package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// decodeSystem reads one prepared payload's system array back as raw JSON so
// tests can assert on the exact wire shape the gateway's integrity precheck
// reads.
func decodeSystem(t *testing.T, payload []byte) []map[string]any {
	t.Helper()
	var body struct {
		System []map[string]any `json:"system"`
	}
	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&body); err != nil {
		t.Fatalf("prepared payload is not valid JSON: %v", err)
	}
	return body.System
}

func TestInjectOfficialSystemPrefixAbsentSystem(t *testing.T) {
	payload, _, envErr := prepareUpstreamPayload(
		[]byte(`{"model":"GLM-5.3-Flash","max_tokens":16,"messages":[{"role":"user","content":"Reply with OK."}]}`),
		"", []string{"GLM-5.3-Flash"}, requestIdentity{DeviceID: "d", SessionID: "s"}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the payload: %s", envErr)
	}
	system := decodeSystem(t, payload)
	if len(system) != 2 {
		t.Fatalf("system blocks = %d, want 2 (the official prefix alone)", len(system))
	}
	if got := system[0]["text"]; got != officialSystemPrefixBlock1 {
		t.Errorf("system[0] = %q, want the official block 1", got)
	}
	if got := system[1]["text"]; got != officialSystemPrefixBlock2 {
		t.Errorf("system[1] = %q, want the official block 2", got)
	}
}

func TestInjectOfficialSystemPrefixStringSystem(t *testing.T) {
	payload, _, envErr := prepareUpstreamPayload(
		[]byte(`{"model":"GLM-5.3-Flash","system":"You are Claude Code.","messages":[]}`),
		"", []string{"GLM-5.3-Flash"}, requestIdentity{}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the payload: %s", envErr)
	}
	system := decodeSystem(t, payload)
	if len(system) != 3 {
		t.Fatalf("system blocks = %d, want 3 (official prefix + caller string)", len(system))
	}
	if got, _ := system[0]["text"].(string); got != officialSystemPrefixBlock1 {
		t.Errorf("system[0] = %q, want the official block 1", got)
	}
	if got, _ := system[0]["text"].(string); got != officialSystemPrefixBlock1 {
		t.Errorf("system[0] = %q, want the official block 1", got)
	}
	if got, _ := system[2]["text"].(string); got != "You are Claude Code." {
		t.Errorf("system[2] = %q, want the caller's string preserved as a block", got)
	}
	if got, _ := system[2]["type"].(string); got != "text" {
		t.Errorf("system[2] type = %q, want text", got)
	}
}

func TestInjectOfficialSystemPrefixArraySystemPrepends(t *testing.T) {
	payload, _, envErr := prepareUpstreamPayload(
		[]byte(`{"model":"GLM-5.3-Flash","system":[{"type":"text","text":"caller block"}],"messages":[]}`),
		"", []string{"GLM-5.3-Flash"}, requestIdentity{}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the payload: %s", envErr)
	}
	system := decodeSystem(t, payload)
	if len(system) != 3 {
		t.Fatalf("system blocks = %d, want 3 (official prefix prepended to caller block)", len(system))
	}
	if got, _ := system[0]["text"].(string); got != officialSystemPrefixBlock1 {
		t.Errorf("system[0] = %q, want the official block 1 first", got)
	}
	if got, _ := system[1]["text"].(string); got != officialSystemPrefixBlock2 {
		t.Errorf("system[1] = %q, want the official block 2 second", got)
	}
	if got, _ := system[2]["text"].(string); got != "caller block" {
		t.Errorf("system[2] = %q, want the caller block after the prefix", got)
	}
}

func TestInjectOfficialSystemPrefixAlreadyOfficial(t *testing.T) {
	official := []map[string]any{
		{"type": "text", "text": officialSystemPrefixBlock1},
		{"type": "text", "text": officialSystemPrefixBlock2},
	}
	raw, err := json.Marshal(map[string]any{"model": "GLM-5.3-Flash", "system": official, "messages": []any{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload, _, envErr := prepareUpstreamPayload(raw, "", []string{"GLM-5.3-Flash"}, requestIdentity{}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the payload: %s", envErr)
	}
	system := decodeSystem(t, payload)
	if len(system) != 2 {
		t.Fatalf("system blocks = %d, want 2 (already-official system must not be duplicated)", len(system))
	}
}

func TestInjectOfficialSystemPrefixDisabled(t *testing.T) {
	payload, _, envErr := prepareUpstreamPayload(
		[]byte(`{"model":"GLM-5.3-Flash","system":"caller","messages":[]}`),
		"", []string{"GLM-5.3-Flash"}, requestIdentity{}, false)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the payload: %s", envErr)
	}
	var body struct {
		System json.RawMessage `json:"system"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if string(body.System) != `"caller"` {
		t.Errorf("system = %s, want the caller's untouched string when injection is off", body.System)
	}
}

func TestInjectOfficialSystemPrefixConfigDefault(t *testing.T) {
	cfg := normalizeConfig(Config{})
	if !cfg.IsInjectOfficialSystemPrefixEnabled() {
		t.Error("injection must default to enabled: the gateway rejects requests without the prefix")
	}
	off := false
	cfg.InjectOfficialSystemPrefix = &off
	if cfg.IsInjectOfficialSystemPrefixEnabled() {
		t.Error("explicit inject_official_system_prefix: false must disable the injection")
	}
}

// The gateway rejects caller content placed BEFORE the official blocks, so the
// injected prefix must always lead. This guards the ordering invariant the
// differential verification established (issue #16 tests Y1/W3).
func TestInjectOfficialSystemPrefixAlwaysLeads(t *testing.T) {
	caller := []map[string]any{
		{"type": "text", "text": "first caller block"},
		{"type": "text", "text": "second caller block"},
	}
	raw, err := json.Marshal(map[string]any{"model": "GLM-5.3-Flash", "system": caller, "messages": []any{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload, _, envErr := prepareUpstreamPayload(raw, "", []string{"GLM-5.3-Flash"}, requestIdentity{}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the payload: %s", envErr)
	}
	system := decodeSystem(t, payload)
	if got, _ := system[0]["text"].(string); got != officialSystemPrefixBlock1 {
		t.Errorf("system[0] = %q, want official block 1 leading", got)
	}
	if got, _ := system[2]["text"].(string); got != "first caller block" {
		t.Errorf("system[2] = %q, want the first caller block after the prefix", got)
	}
}
