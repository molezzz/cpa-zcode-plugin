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

// TestStaticModelsCoverTheOfficialStartPlanCatalog covers the fallback the
// host falls back to whenever the dynamic catalog is unusable — unlogged in, a
// discovery failure inside its cooldown, or an identity the plugin cannot key a
// cache under.
//
// The official client's Start Plan provider declares
// ["GLM-5.3-Flash","GLM-5.2","GLM-5-Turbo"] (docs/ZCode
// config/provider/zcode-builtin.json), and the balance endpoint declares the
// same model through its capabilities. That dynamic path is a supplement, not a
// replacement: when the quota cache has no positive reading, a static list
// without GLM-5.3-Flash leaves the account with no way to reach the model the
// Start Plan actually pays for. The static list is therefore the floor, not an
// optional extra, and it must cover that model in both the default snapshot and
// the empty-configuration fallback.
func TestStaticModelsCoverTheOfficialStartPlanCatalog(t *testing.T) {
	want := []string{"GLM-5.3-Flash", "GLM-5.2", "GLM-5-Turbo"}
	cases := []struct {
		name string
		cfg  Config
	}{
		{name: "default snapshot", cfg: defaultConfig()},
		{name: "empty configuration falls back to the defaults", cfg: func() Config { cfg := defaultConfig(); cfg.Models = nil; return cfg }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := make([]string, 0, len(staticModels(tc.cfg)))
			for _, model := range staticModels(tc.cfg) {
				ids = append(ids, model.ID)
			}
			if strings.Join(ids, ",") != strings.Join(want, ",") {
				t.Fatalf("static catalog = %v, want %v", ids, want)
			}
		})
	}
}

// TestNormalizeRequestModelReachesTheStartPlanModelInOfficialCasing covers the
// other half of the same gap: a caller or a balance capability may spell the
// Start Plan model in lower case, and the upstream's model router is
// case-sensitive. Without canonicalization the request would leave the plugin
// with an id the upstream does not recognize.
func TestNormalizeRequestModelReachesTheStartPlanModelInOfficialCasing(t *testing.T) {
	catalog := defaultConfig().Models
	cases := []struct {
		in   string
		want string
	}{
		{"glm-5.3-flash", "GLM-5.3-Flash"},
		{"GLM-5.3-FLASH", "GLM-5.3-Flash"},
		{"zcode/GLM-5.3-Flash", "GLM-5.3-Flash"},
	}
	for _, tc := range cases {
		if got := normalizeRequestModel(tc.in, catalog); got != tc.want {
			t.Errorf("normalizeRequestModel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
