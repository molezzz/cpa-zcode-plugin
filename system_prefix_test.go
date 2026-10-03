package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"
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

// The injected text is the fingerprint the gateway matches on, so an edit to
// either constant is a protocol change, not a refactor. These are the exact
// lengths of the official client's own blocks as captured in mitmproxy session
// 20261002-194452_2344fd and re-verified 2026-10-03; the 2026-10-03 matrix
// showed block 2's 1200-byte prefix is refused while a 1250-byte one is
// admitted, so a silent truncation could move the plugin from admitted to
// refused without any local signal. Block 2 carries two multi-byte em-dashes,
// so its byte and character counts differ.
func TestOfficialSystemPrefixBlocksMatchCapture(t *testing.T) {
	if got := len(officialSystemPrefixBlock1); got != 42 {
		t.Errorf("official block 1 is %d bytes, want the captured 42", got)
	}
	if got := len(officialSystemPrefixBlock2); got != 2317 {
		t.Errorf("official block 2 is %d bytes, want the captured 2317", got)
	}
	if got := utf8.RuneCountInString(officialSystemPrefixBlock2); got != 2313 {
		t.Errorf("official block 2 is %d characters, want the captured 2313", got)
	}
	const opener = "You are ZCode, an interactive coding agent"
	if officialSystemPrefixBlock1 != opener {
		t.Errorf("official block 1 = %q, want %q", officialSystemPrefixBlock1, opener)
	}
}

// The gateway recognizes block 1 followed by block 2 as one run and refuses
// either alone or the reversed pair, so the order leadsWithOfficialPrefix
// checks is load-bearing for the de-duplication decision it makes: a reversed
// official-shaped caller is a caller, not a caller to leave untouched.
func TestLeadsWithOfficialPrefixRequiresOrder(t *testing.T) {
	block1 := map[string]any{"type": "text", "text": officialSystemPrefixBlock1}
	block2 := map[string]any{"type": "text", "text": officialSystemPrefixBlock2}

	if !leadsWithOfficialPrefix([]any{block1, block2}) {
		t.Error("blocks 1 then 2 must be recognized as the official prefix")
	}
	for name, system := range map[string][]any{
		"reversed":       {block2, block1},
		"block 1 alone":  {block1},
		"block 2 alone":  {block2},
		"caller leading": {map[string]any{"type": "text", "text": "caller"}, block1, block2},
	} {
		if leadsWithOfficialPrefix(system) {
			t.Errorf("%s must not be recognized as the official prefix", name)
		}
	}
}

// The gateway recognizes the official prefix as one contiguous run of text,
// so caller content before it separates the run from the blocks that form it.
// The injected prefix must therefore always lead (issue #16 test Y1; measured
// again in the 2026-10-03 matrix, case F9).
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
