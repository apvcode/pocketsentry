package helpers

import (
	"crypto/rand"
	"fmt"
	"time"
)

// GenerateUUID generates a random UUID v4 formatted as 32 hex characters
// (no dashes), which is the format Sentry uses for event IDs.
func GenerateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x%04x%04x%04x%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Truncate shortens a string to at most n characters, appending "…" if cut.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// FormatTimestamp converts an RFC3339 timestamp into a shorter, more readable
// format for the dashboard (e.g. "2026-06-09 14:12:23").
func FormatTimestamp(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.Format("2006-01-02 15:04:05")
}

// HumanBytes formats byte counts into human-readable strings (KB, MB, GB, etc.).
func HumanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ParseSentryTimestamp converts float64 (unix seconds) or string (RFC3339) to time.Time
func ParseSentryTimestamp(v interface{}) time.Time {
	if f, ok := v.(float64); ok {
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC()
	}
	if s, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
