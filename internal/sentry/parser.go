package sentry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pocketsentry/pocketsentry/internal/models"
)

// ParseSentryEvent unmarshals a JSON blob into a SentryEvent and resolves
// the message field.
func ParseSentryEvent(data []byte) (models.SentryEvent, error) {
	var ev models.SentryEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return ev, fmt.Errorf("unmarshal event: %w", err)
	}
	ev.Message = ev.ExtractMessage()
	return ev, nil
}

// ParseEnvelope handles the Sentry envelope format (NDJSON) and returns the event ID, item Type, and its raw JSON payload.
func ParseEnvelope(raw []byte) (string, string, []byte, error) {
	lines := SplitEnvelopeLines(raw)
	if len(lines) == 0 {
		return "", "", nil, fmt.Errorf("empty envelope")
	}

	var envelopeHeader struct {
		EventID string `json:"event_id"`
	}
	_ = json.Unmarshal(lines[0], &envelopeHeader)

	for i := 1; i+1 < len(lines); i += 2 {
		var itemHeader struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(lines[i], &itemHeader); err != nil {
			continue
		}

		itemType := strings.ToLower(itemHeader.Type)
		switch itemType {
		case "event", "error", "transaction", "":
			return envelopeHeader.EventID, itemType, lines[i+1], nil
		default:
			continue
		}
	}

	// Fallback: brute-force — try every line as an event payload.
	for _, line := range lines[1:] {
		var partial struct {
			EventID string `json:"event_id"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(line, &partial); err == nil && partial.Message != "" {
			return envelopeHeader.EventID, "event", line, nil
		}
	}

	return "", "", nil, fmt.Errorf("no parseable event found in envelope (%d lines)", len(lines))
}

// SplitEnvelopeLines splits envelope bytes by newlines, skipping empty lines.
func SplitEnvelopeLines(data []byte) [][]byte {
	parts := bytes.Split(data, []byte("\n"))
	lines := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = bytes.TrimSpace(p)
		if len(p) > 0 {
			lines = append(lines, p)
		}
	}
	return lines
}
