package models

import (
	"encoding/json"
	"time"
)

// SentryEvent represents the subset of Sentry event fields we care about.
type SentryEvent struct {
	EventID     string `json:"event_id"`
	Timestamp   string `json:"timestamp,omitempty"`
	Level       string `json:"level"`
	Platform    string `json:"platform"`
	Message     string `json:"message"`
	Logger      string `json:"logger"`
	Environment string `json:"environment"`

	Exception *SentryException `json:"exception,omitempty"`
	LogEntry  *SentryLogEntry  `json:"logentry,omitempty"`
}

// SentryException wraps the array of exception values.
type SentryException struct {
	Values []SentryExceptionValue `json:"values"`
}

// SentryExceptionValue is a single exception in the chain.
type SentryExceptionValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SentryLogEntry is an alternative message format used by some SDKs.
type SentryLogEntry struct {
	Formatted string `json:"formatted"`
	Message   string `json:"message"`
}

// ExtractMessage determines the human-readable message from a SentryEvent,
// checking multiple possible locations where SDKs place it.
func (ev *SentryEvent) ExtractMessage() string {
	if ev.Message != "" {
		return ev.Message
	}
	if ev.Exception != nil && len(ev.Exception.Values) > 0 {
		exc := ev.Exception.Values[0]
		if exc.Type != "" && exc.Value != "" {
			return exc.Type + ": " + exc.Value
		}
		if exc.Value != "" {
			return exc.Value
		}
		if exc.Type != "" {
			return exc.Type
		}
	}
	if ev.LogEntry != nil {
		if ev.LogEntry.Formatted != "" {
			return ev.LogEntry.Formatted
		}
		return ev.LogEntry.Message
	}
	return "(no message)"
}

// SentryTransaction models a Performance Monitoring transaction payload.
type SentryTransaction struct {
	EventID        string       `json:"event_id"`
	Transaction    string       `json:"transaction"`
	StartTimestamp interface{}  `json:"start_timestamp"`
	Timestamp      interface{}  `json:"timestamp"`
	Spans          []SentrySpan `json:"spans"`
}

// SentrySpan models a child operation within a transaction.
type SentrySpan struct {
	SpanID         string      `json:"span_id"`
	ParentSpanID   string      `json:"parent_span_id"`
	Op             string      `json:"op"`
	Description    string      `json:"description"`
	StartTimestamp interface{} `json:"start_timestamp"`
	Timestamp      interface{} `json:"timestamp"`
}

// EventRow is the struct passed to HTML templates for rendering.
// All fields are plain strings so we never hit nil-pointer issues from
// NULL columns (the query uses COALESCE as an extra safety net).
type EventRow struct {
	ID        string
	ProjectID string
	LastSeen  string
	Level     string
	Platform  string
	Message   string
	Count     int
	Status    string
	Release   string
}

// StackFrame represents a single frame in a stack trace.
type StackFrame struct {
	Filename    string   `json:"filename"`
	Function    string   `json:"function"`
	Module      string   `json:"module"`
	Lineno      int      `json:"lineno"`
	Colno       int      `json:"colno"`
	AbsPath     string   `json:"abs_path"`
	ContextLine string   `json:"context_line"`
	PreContext  []string `json:"pre_context"`
	PostContext []string `json:"post_context"`
	InApp       bool     `json:"in_app"`
}

// RawExceptionValue extends the ingestion struct with stacktrace data.
type RawExceptionValue struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Stacktrace *struct {
		Frames []StackFrame `json:"frames"`
	} `json:"stacktrace,omitempty"`
}

// RawPayloadDetail is used to extract rich metadata from the stored JSON.
type RawPayloadDetail struct {
	EventID     string                     `json:"event_id"`
	Timestamp   string                     `json:"timestamp"`
	Level       string                     `json:"level"`
	Platform    string                     `json:"platform"`
	ServerName  string                     `json:"server_name"`
	Environment string                     `json:"environment"`
	Release     string                     `json:"release"`
	Tags        map[string]string          `json:"tags"`
	Contexts    map[string]json.RawMessage `json:"contexts"`
	User        *struct {
		IP    string `json:"ip_address"`
		Email string `json:"email"`
	} `json:"user,omitempty"`
	Request *struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
	} `json:"request,omitempty"`
	Exception *struct {
		Values []RawExceptionValue `json:"values"`
	} `json:"exception,omitempty"`
	SDK *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"sdk,omitempty"`
	Breadcrumbs json.RawMessage `json:"breadcrumbs,omitempty"`
}

// Breadcrumb represents a single breadcrumb entry.
type Breadcrumb struct {
	Timestamp string
	Type      string
	Category  string
	Level     string
	Message   string
	Data      map[string]interface{}
}

// EventComment represents a user note on a specific event.
type EventComment struct {
	ID        int
	EventID   string
	Comment   string
	Timestamp string
	Author    string
}

// EventDetail is the struct passed to the detail.html template.
type EventDetail struct {
	ID                string
	ProjectID         string
	Timestamp         string
	LastSeen          string
	Level             string
	Platform          string
	Message           string
	Count             int
	Status            string
	ResolvedInRelease string
	SnoozedUntil      string

	ExcType  string
	ExcValue string

	OS          string
	Browser     string
	Runtime     string
	ServerName  string
	Environment string
	Release     string
	IP          string
	URL         string
	SDKName     string

	Frames           []StackFrame
	HasFrames        bool
	Tags             map[string]string
	HasTags          bool
	Breadcrumbs      []Breadcrumb
	HasBreadcrumbs   bool
	Comments         []EventComment
	Attachments      []Attachment
	HasAttachments   bool
	HasLibraryFrames bool
	RawJSON          string
	ReplayID         string
	HasReplay        bool
}

// StatPoint represents a single day's count of events.
type StatPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// TransactionGroupRow is a summary of grouped transactions for the performance UI.
type TransactionGroupRow struct {
	ExemplarID    string
	ProjectID     string
	Name          string
	Count         int
	AvgDurationMs float64
	MaxDurationMs float64
}

// SpanRow represents a single span from the DB.
type SpanRow struct {
	ID             string
	Op             string
	Description    string
	StartTimestamp time.Time
	DurationMs     float64
}

// Attachment is the struct for attachment metadata.
type Attachment struct {
	ID          string
	EventID     string
	Filename    string
	ContentType string
	SizeBytes   int
	CreatedAt   string
	IsImage     bool
}

// Project represents a user project.
type Project struct {
	ID             string
	Name           string
	TGToken        string
	TGChatID       string
	DiscordWebhook string
}

// IndexData is passed to the index.html template.
type IndexData struct {
	UnresolvedCount int
	Webhooks        string
	Retention       string
	Projects        []Project
	Environments    []string
}

// SystemMetrics holds all system health data for the dashboard.
type SystemMetrics struct {
	Version           string  `json:"version"`
	Uptime            string  `json:"uptime"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
	DBSizeBytes       int64   `json:"db_size_bytes"`
	DBSizeHuman       string  `json:"db_size_human"`
	TotalEvents       int     `json:"total_events"`
	UnresolvedEvents  int     `json:"unresolved_events"`
	ResolvedEvents    int     `json:"resolved_events"`
	SnoozedEvents     int     `json:"snoozed_events"`
	TotalProjects     int     `json:"total_projects"`
	TotalTransactions int     `json:"total_transactions"`
	EventsPerMinute   float64 `json:"events_per_minute"`
	TotalAttachments  int     `json:"total_attachments"`
	GroupingRules     int     `json:"grouping_rules"`
	RetentionDays     int     `json:"retention_days"`
	GoVersion         string  `json:"go_version"`
	GoRoutines        int     `json:"goroutines"`
	MemAllocMB        float64 `json:"mem_alloc_mb"`
	TotalLogs         int     `json:"total_logs"`
}

// LogEntry represents a single log line for ingestion.
type LogEntry struct {
	ProjectID string            `json:"project_id"`
	Source    string            `json:"source"`
	Level    string            `json:"level"`
	Message  string            `json:"message"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Timestamp string           `json:"timestamp,omitempty"`
}

// LogRow represents a single log line from the DB.
type LogRow struct {
	ID        int    `json:"id"`
	ProjectID string `json:"project_id"`
	Source    string `json:"source"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Metadata string `json:"metadata"`
	Timestamp string `json:"timestamp"`
}

// GithubRelease is a minimal representation of the GitHub Releases API response.
type GithubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// LogAlertingRule represents an alerting rule triggered by log patterns.
type LogAlertingRule struct {
	ID                   int    `json:"id"`
	ProjectID            string `json:"project_id"`
	Level                string `json:"level"`
	Pattern              string `json:"pattern"`
	TargetDiscord        string `json:"target_discord"`
	TargetTelegramToken  string `json:"target_telegram_token"`
	TargetTelegramChatID string `json:"target_telegram_chat_id"`
	Enabled              bool   `json:"enabled"`
	CreatedAt            string `json:"created_at"`
}

// APIKey represents an authorized API token for project access.
type APIKey struct {
	ID        int    `json:"id"`
	Key       string `json:"key"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Role      string `json:"role"` // 'admin' or 'viewer'
	CreatedAt string `json:"created_at"`
}

