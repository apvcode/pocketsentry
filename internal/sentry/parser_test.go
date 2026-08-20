package sentry

import (
	"testing"
)

func TestParseSentryEvent(t *testing.T) {
	// Simple message event
	payload1 := []byte(`{"message": "Test error", "level": "warning"}`)
	ev1, err := ParseSentryEvent(payload1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev1.Message != "Test error" {
		t.Errorf("expected message 'Test error', got %q", ev1.Message)
	}
	if ev1.Level != "warning" {
		t.Errorf("expected level 'warning', got %q", ev1.Level)
	}

	// Exception event
	payload2 := []byte(`{
		"exception": {
			"values": [
				{
					"type": "ZeroDivisionError",
					"value": "division by zero"
				}
			]
		}
	}`)
	ev2, err := ParseSentryEvent(payload2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev2.Message != "ZeroDivisionError: division by zero" {
		t.Errorf("expected 'ZeroDivisionError: division by zero', got %q", ev2.Message)
	}
}

func TestParseEnvelope(t *testing.T) {
	envelopeData := []byte("{\"event_id\":\"9ec79c33ec9942ab8353589fcb074ad9\"}\n{\"type\":\"event\",\"content_type\":\"application/json\"}\n{\"message\":\"Hello world\"}\n")
	eventID, itemType, itemJSON, err := ParseEnvelope(envelopeData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eventID != "9ec79c33ec9942ab8353589fcb074ad9" {
		t.Errorf("unexpected eventID: %s", eventID)
	}
	if itemType != "event" {
		t.Errorf("unexpected itemType: %s", itemType)
	}
	if string(itemJSON) != "{\"message\":\"Hello world\"}" {
		t.Errorf("unexpected itemJSON: %s", string(itemJSON))
	}
}
