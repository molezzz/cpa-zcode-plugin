package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func decodeDoc(t *testing.T, doc []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode doc: %v", err)
	}
	return out
}

func TestPatchCreatesNamespaceOnEmptyDoc(t *testing.T) {
	out, err := patchZcodeNamespace(nil, func(zcode map[string]any) error {
		zcode["schema_version"] = 1
		return nil
	})
	if err != nil {
		t.Fatalf("patchZcodeNamespace: %v", err)
	}
	doc := decodeDoc(t, out)
	zcode, ok := doc["zcode"].(map[string]any)
	if !ok {
		t.Fatalf("zcode namespace missing: %v", doc)
	}
	if zcode["schema_version"] != json.Number("1") {
		t.Fatalf("schema_version = %v", zcode["schema_version"])
	}
}

func TestPatchPreservesUnknownOuterFields(t *testing.T) {
	doc := []byte(`{
		"type": "zcode",
		"label": "Z.AI user",
		"host_future_field": {"nested": [1, 2, {"deep": true}]},
		"zcode": {"schema_version": 1, "jwt": {"token": "secret", "status": "active"}}
	}`)
	out, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		jwt := zcode["jwt"].(map[string]any)
		jwt["status"] = "invalid"
		return nil
	})
	if err != nil {
		t.Fatalf("patchZcodeNamespace: %v", err)
	}
	result := decodeDoc(t, out)
	if result["host_future_field"] == nil {
		t.Fatal("unknown outer field dropped")
	}
	if result["label"] != "Z.AI user" {
		t.Fatal("outer label dropped")
	}
	zcode := result["zcode"].(map[string]any)
	jwt := zcode["jwt"].(map[string]any)
	if jwt["status"] != "invalid" {
		t.Fatalf("jwt status not updated: %v", jwt)
	}
	if jwt["token"] != "secret" {
		t.Fatal("jwt token clobbered")
	}
}

func TestPatchPreservesBigNumberPrecision(t *testing.T) {
	doc := []byte(`{"host_numbers": {"big": 123456789012345678901234567890, "precise": 0.30000000000000004, "exp": 1e100}, "zcode": {}}`)
	out, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		return nil
	})
	if err != nil {
		t.Fatalf("patchZcodeNamespace: %v", err)
	}
	// 数值必须逐字保留，不得经过 float64。
	for _, number := range []string{
		"123456789012345678901234567890",
		"0.30000000000000004",
		"1e100",
	} {
		if !bytes.Contains(out, []byte(number)) {
			t.Fatalf("number %s not preserved byte-exact in %s", number, out)
		}
	}
}

func TestPatchPreservesUnknownZcodeKeys(t *testing.T) {
	doc := []byte(`{"zcode": {"future_plugin_field": [1, 2], "known": "old"}}`)
	out, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		zcode["known"] = "new"
		return nil
	})
	if err != nil {
		t.Fatalf("patchZcodeNamespace: %v", err)
	}
	zcode := decodeDoc(t, out)["zcode"].(map[string]any)
	if zcode["future_plugin_field"] == nil {
		t.Fatal("unknown zcode key dropped")
	}
	if zcode["known"] != "new" {
		t.Fatal("known key not updated")
	}
}

func TestPatchRejectsNonObjectNamespace(t *testing.T) {
	doc := []byte(`{"zcode": "not-an-object"}`)
	if _, err := patchZcodeNamespace(doc, func(zcode map[string]any) error { return nil }); err == nil {
		t.Fatal("non-object zcode namespace must error instead of being clobbered")
	}
}

func TestPatchRejectsNonObjectDoc(t *testing.T) {
	if _, err := patchZcodeNamespace([]byte(`[1,2,3]`), func(map[string]any) error { return nil }); err == nil {
		t.Fatal("non-object document must error")
	}
}

func TestPatchCallbackErrorLeavesDocUntouched(t *testing.T) {
	doc := []byte(`{"zcode": {"a": 1}}`)
	want := append([]byte(nil), doc...)
	var errTestFailure = errors.New("callback failed")
	if _, err := patchZcodeNamespace(doc, func(map[string]any) error {
		return errTestFailure
	}); err == nil {
		t.Fatal("callback error must propagate")
	}
	if !bytes.Equal(doc, want) {
		t.Fatal("input doc was mutated")
	}
}
