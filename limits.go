package main

import (
	"fmt"
	"io"
)

// readLimited reads at most limit bytes and rejects larger payloads instead of
// silently truncating upstream responses.
func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("response limit must be positive, got %d", limit)
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return data, nil
}

// truncateForLog bounds a value before it may reach host logs or error envelopes.
func truncateForLog(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
