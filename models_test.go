package main

import (
	"strings"
	"testing"
)

func TestStaticModelsNormalizeIDs(t *testing.T) {
	cfg := defaultConfig()
	cfg.Models = []string{" GLM-5.2 ", "", "GLM-5.2", "GLM-5-Turbo", "  "}
	models := staticModels(cfg)
	ids := make([]string, 0, len(models))
	for _, model := range models {
		ids = append(ids, model.ID)
	}
	if strings.Join(ids, ",") != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("ids = %v, want trimmed dedup in order", ids)
	}
}

func TestStaticModelsShape(t *testing.T) {
	cfg := defaultConfig()
	cfg.Models = []string{"GLM-5.2"}
	models := staticModels(cfg)
	if len(models) != 1 {
		t.Fatalf("models = %d, want 1", len(models))
	}
	model := models[0]
	if model.Object != "model" {
		t.Errorf("object = %q", model.Object)
	}
	if model.OwnedBy != pluginID {
		t.Errorf("owned_by = %q, want %q", model.OwnedBy, pluginID)
	}
	if !model.UserDefined {
		t.Error("config-provided models must be marked UserDefined")
	}
	if len(model.SupportedGenerationMethods) == 0 {
		t.Error("supported generation methods missing")
	}
	if model.ContextLength != 0 || model.MaxCompletionTokens != 0 {
		t.Error("token limits must stay unset until verified upstream")
	}
}

func TestStaticModelsNeverEmpty(t *testing.T) {
	cfg := defaultConfig()
	cfg.Models = nil
	if models := staticModels(cfg); len(models) == 0 {
		t.Fatal("static fallback vanished with empty config")
	}
}

func TestNormalizeModelIDsEdgeCases(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{"", "   "}, nil},
		{[]string{"A", "A", "A"}, []string{"A"}},
		{[]string{" a ", "b", "a"}, []string{"a", "b"}},
	}
	for _, tc := range cases {
		got := normalizeModelIDs(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("normalizeModelIDs(%v) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("normalizeModelIDs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}
