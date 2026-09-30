package main

import (
	"strings"
	"testing"
)

func TestReadLimitedReturnsExactData(t *testing.T) {
	data, err := readLimited(strings.NewReader("hello"), 10)
	if err != nil {
		t.Fatalf("readLimited: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q", data)
	}
}

func TestReadLimitedRejectsOversized(t *testing.T) {
	if _, err := readLimited(strings.NewReader("0123456789"), 4); err == nil {
		t.Fatal("oversized payload must error, not truncate")
	}
}

func TestReadLimitedAcceptsExactLimit(t *testing.T) {
	data, err := readLimited(strings.NewReader("0123"), 4)
	if err != nil {
		t.Fatalf("exact limit must be accepted: %v", err)
	}
	if string(data) != "0123" {
		t.Fatalf("data = %q", data)
	}
}

func TestTruncateForLog(t *testing.T) {
	if got := truncateForLog("abcdef", 4); got != "abcd" {
		t.Fatalf("truncate = %q", got)
	}
	if got := truncateForLog("ab", 4); got != "ab" {
		t.Fatalf("short value must pass through, got %q", got)
	}
}
