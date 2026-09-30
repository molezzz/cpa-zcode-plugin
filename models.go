package main

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const pluginID = "zcode"

// staticModels builds the always-available model catalog from the config
// snapshot. Dynamic discovery (later milestone) may only extend this list.
func staticModels(cfg Config) []pluginapi.ModelInfo {
	ids := normalizeModelIDs(cfg.Models)
	if len(ids) == 0 {
		ids = defaultConfig().Models
	}
	models := make([]pluginapi.ModelInfo, 0, len(ids))
	for _, id := range ids {
		models = append(models, pluginapi.ModelInfo{
			ID:                         id,
			Object:                     "model",
			OwnedBy:                    pluginID,
			DisplayName:                id,
			Name:                       id,
			SupportedGenerationMethods: []string{"chat"},
			UserDefined:                true,
		})
	}
	return models
}

// normalizeModelIDs trims whitespace, drops empties, and de-duplicates while
// preserving the first occurrence order.
func normalizeModelIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
