package helpers

import (
	"testing"
	"time"
)

func TestGenerateUUID(t *testing.T) {
	id1 := GenerateUUID()
	id2 := GenerateUUID()
	if len(id1) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%s)", len(id1), id1)
	}
	if id1 == id2 {
		t.Fatalf("expected unique UUIDs, got duplicates")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello…"},
		{"", 5, ""},
	}

	for _, tt := range tests {
		res := Truncate(tt.input, tt.maxLen)
		if res != tt.expected {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, res, tt.expected)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		res := HumanBytes(tt.input)
		if res != tt.expected {
			t.Errorf("HumanBytes(%d) = %q, want %q", tt.input, res, tt.expected)
		}
	}
}

func TestFormatTimestamp(t *testing.T) {
	raw := "2026-06-09T14:12:23Z"
	expected := "2026-06-09 14:12:23"
	res := FormatTimestamp(raw)
	if res != expected {
		t.Errorf("FormatTimestamp(%q) = %q, want %q", raw, res, expected)
	}
}

func TestParseSentryTimestamp(t *testing.T) {
	// Unix float timestamp
	sec := 1700000000.5
	ts := ParseSentryTimestamp(sec)
	if ts.Unix() != 1700000000 {
		t.Errorf("ParseSentryTimestamp(float) unexpected unix sec: %d", ts.Unix())
	}

	// RFC3339 string
	str := "2026-01-01T12:00:00Z"
	ts2 := ParseSentryTimestamp(str)
	if ts2.Year() != 2026 || ts2.Month() != time.January {
		t.Errorf("ParseSentryTimestamp(string) unexpected: %v", ts2)
	}
}
