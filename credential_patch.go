package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// zcodeNamespace is the only key of the host-owned auth document this plugin
// is allowed to write.
const zcodeNamespace = "zcode"

// patchZcodeNamespace decodes the host auth document losslessly, hands the
// plugin-owned zcode namespace to fn for mutation, and re-encodes the whole
// document. Unknown fields anywhere in the document survive the round trip,
// and numeric literals keep their exact text (including big integers beyond
// float64 range) because values are decoded as json.Number. Note that Go
// re-encoding may normalize object key order; only values are guaranteed
// byte-identical. An empty document starts a fresh one containing only the
// namespace. The input document is never mutated; when fn returns an error no
// output is produced.
func patchZcodeNamespace(doc []byte, fn func(zcode map[string]any) error) ([]byte, error) {
	root := map[string]any{}
	if len(bytes.TrimSpace(doc)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(doc))
		dec.UseNumber()
		if err := dec.Decode(&root); err != nil {
			return nil, fmt.Errorf("decode auth document: %w", err)
		}
	}
	if root == nil {
		// The document decoded to JSON null; treat it as absent.
		root = map[string]any{}
	}
	switch ns := root[zcodeNamespace].(type) {
	case nil:
		ns = map[string]any{}
		root[zcodeNamespace] = ns
	case map[string]any:
		// keep existing namespace content, including unknown keys
	default:
		return nil, fmt.Errorf("zcode namespace is %T, want object", root[zcodeNamespace])
	}
	namespace := root[zcodeNamespace].(map[string]any)
	if err := fn(namespace); err != nil {
		return nil, err
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("encode auth document: %w", err)
	}
	return out, nil
}
