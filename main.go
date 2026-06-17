package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"math"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pocketsentry/pocketsentry/ebpf"
	"github.com/go-sourcemap/sourcemap"
	_ "modernc.org/sqlite"
)

// currentVersion is the version of this binary, compared against GitHub releases.
const currentVersion = "v3.0.0"

// templateFS embeds the templates directory into the binary so the final
// executable is fully self-contained — no external files needed.
//
//go:embed templates/*
var templateFS embed.FS

// Parsed templates (initialized once at startup).
var (
	tmplIndex  *template.Template
	tmplRows   *template.Template
	tmplDetail *template.Template
)

// initTemplates parses the embedded templates once at startup. This is both
// faster (no re-parsing on every request) and safer (parse errors surface
// immediately instead of at runtime).
func initTemplates() error {
	var err error
	tmplIndex, err = template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		return fmt.Errorf("parse index.html: %w", err)
	}
	tmplRows, err = template.ParseFS(templateFS, "templates/rows.html")
	if err != nil {
		return fmt.Errorf("parse rows.html: %w", err)
	}
	tmplDetail, err = template.ParseFS(templateFS, "templates/detail.html")
	if err != nil {
		return fmt.Errorf("parse detail.html: %w", err)
	}
	return nil
}

// ---------- Database ----------

var db *sql.DB

// initDB opens (or creates) the SQLite database file and ensures the
// events table exists.
func initDB(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}

	// SQLite pragmas for performance.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("pragma %q: %w", p, err)
		}
	}

	const ddl = `
	CREATE TABLE IF NOT EXISTS events (
		id          TEXT PRIMARY KEY,
		project_id  TEXT     NOT NULL,
		timestamp   DATETIME NOT NULL,
		level       TEXT     NOT NULL DEFAULT 'error',
		platform    TEXT     NOT NULL DEFAULT '',
		message     TEXT     NOT NULL DEFAULT '',
		raw_payload TEXT     NOT NULL,
		count       INTEGER  NOT NULL DEFAULT 1,
		last_seen   DATETIME NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_event ON events(project_id, message, level);

	CREATE TABLE IF NOT EXISTS projects (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);
	
	CREATE TABLE IF NOT EXISTS event_comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_id TEXT NOT NULL,
		comment TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		author TEXT NOT NULL DEFAULT 'Admin'
	);
	`
	if _, err := db.Exec(ddl); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	// Migrate: add columns if upgrading from an older schema.
	migrations := []string{
		"ALTER TABLE events ADD COLUMN count INTEGER NOT NULL DEFAULT 1",
		"ALTER TABLE events ADD COLUMN last_seen DATETIME NOT NULL DEFAULT ''",
		"ALTER TABLE events ADD COLUMN status TEXT NOT NULL DEFAULT 'unresolved'",
		"ALTER TABLE projects ADD COLUMN tg_token TEXT DEFAULT ''",
		"ALTER TABLE projects ADD COLUMN tg_chat_id TEXT DEFAULT ''",
		"ALTER TABLE projects ADD COLUMN discord_webhook TEXT DEFAULT ''",
		"ALTER TABLE events ADD COLUMN resolved_in_release TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE events ADD COLUMN snoozed_until DATETIME NOT NULL DEFAULT ''",
	}
	for _, m := range migrations {
		_, _ = db.Exec(m) // ignore "duplicate column" errors
	}

	// Performance Monitoring tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS transactions (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			name TEXT NOT NULL,
			start_timestamp DATETIME NOT NULL,
			timestamp DATETIME NOT NULL,
			duration_ms REAL NOT NULL,
			raw_payload TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS spans (
			id TEXT PRIMARY KEY,
			transaction_id TEXT NOT NULL,
			parent_span_id TEXT NOT NULL,
			op TEXT NOT NULL,
			description TEXT NOT NULL,
			start_timestamp DATETIME NOT NULL,
			timestamp DATETIME NOT NULL,
			duration_ms REAL NOT NULL
		);
		CREATE TABLE IF NOT EXISTS grouping_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id TEXT NOT NULL DEFAULT '',
			pattern TEXT NOT NULL,
			replacement TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS attachments (
			id TEXT PRIMARY KEY,
			event_id TEXT NOT NULL,
			filename TEXT NOT NULL,
			content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
			size_bytes INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_attachments_event ON attachments(event_id);
		
		CREATE TABLE IF NOT EXISTS alerting_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id TEXT NOT NULL,
			environment TEXT NOT NULL DEFAULT '',
			min_count INTEGER NOT NULL DEFAULT 1,
			time_window_minutes INTEGER NOT NULL DEFAULT 0,
			target_discord TEXT NOT NULL DEFAULT '',
			target_telegram_token TEXT NOT NULL DEFAULT '',
			target_telegram_chat_id TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS network_edges (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_node TEXT NOT NULL,
			target_node TEXT NOT NULL,
			target_port INTEGER NOT NULL,
			hit_count INTEGER NOT NULL DEFAULT 1,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(source_node, target_node, target_port)
		);
	`)
	if err != nil {
		return fmt.Errorf("create performance tables: %w", err)
	}

	// Insert default project if not exists
	_, err = db.Exec("INSERT OR IGNORE INTO projects (id, name, created_at) VALUES ('1', 'Default Project', CURRENT_TIMESTAMP)")
	if err != nil {
		log.Printf("failed to insert default project: %v", err)
	}

	return nil
}

// ---------- Ingestion Metrics ----------

var (
	ingestCount    int64 // atomic counter for events ingested
	ingestCountMin int64 // snapshot for per-minute rate
	dbFilePath     string
)

func incrIngestCount() {
	atomic.AddInt64(&ingestCount, 1)
}

// ---------- Smart Grouping ----------

// applyGroupingRules normalizes the event message by applying all enabled
// grouping rules for the given project. This allows deduplication of events
// that differ only by dynamic IDs, hashes, or timestamps.
func applyGroupingRules(msg, projectID string) string {
	rows, err := db.Query(
		`SELECT pattern, replacement FROM grouping_rules
		 WHERE enabled = 1 AND (project_id = '' OR project_id = ?)
		 ORDER BY id ASC`, projectID)
	if err != nil {
		return msg
	}
	defer rows.Close()

	normalized := msg
	for rows.Next() {
		var pattern, replacement string
		if err := rows.Scan(&pattern, &replacement); err != nil {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		normalized = re.ReplaceAllString(normalized, replacement)
	}
	return normalized
}

// ---------- Attachments ----------

// saveAttachment stores an attachment file on disk and records metadata in the DB.
func saveAttachment(eventID, filename, contentType string, data []byte) error {
	dir := filepath.Join("data", "attachments", eventID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir attachments: %w", err)
	}

	// Sanitize filename
	safeName := filepath.Base(filename)
	if safeName == "" || safeName == "." || safeName == ".." {
		safeName = "attachment"
	}

	filePath := filepath.Join(dir, safeName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write attachment: %w", err)
	}

	id := generateUUID()
	_, err := db.Exec(
		`INSERT INTO attachments (id, event_id, filename, content_type, size_bytes)
		 VALUES (?, ?, ?, ?, ?)`,
		id, eventID, safeName, contentType, len(data),
	)
	if err != nil {
		return fmt.Errorf("insert attachment: %w", err)
	}

	log.Printf("[attachment] saved %s (%d bytes) for event %s", safeName, len(data), eventID)
	return nil
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

// queryAttachments returns all attachments for a given event.
func queryAttachments(eventID string) []Attachment {
	rows, err := db.Query(
		`SELECT id, filename, content_type, size_bytes, created_at
		 FROM attachments WHERE event_id = ? ORDER BY created_at ASC`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []Attachment
	for rows.Next() {
		var a Attachment
		if err := rows.Scan(&a.ID, &a.Filename, &a.ContentType, &a.SizeBytes, &a.CreatedAt); err != nil {
			continue
		}
		a.EventID = eventID
		a.IsImage = strings.HasPrefix(a.ContentType, "image/")
		a.CreatedAt = formatTimestamp(a.CreatedAt)
		result = append(result, a)
	}
	return result
}

// ---------- System Metrics ----------

// SystemMetrics holds all system health data for the dashboard.
type SystemMetrics struct {
	Version          string  `json:"version"`
	Uptime           string  `json:"uptime"`
	UptimeSeconds    float64 `json:"uptime_seconds"`
	DBSizeBytes      int64   `json:"db_size_bytes"`
	DBSizeHuman      string  `json:"db_size_human"`
	TotalEvents      int     `json:"total_events"`
	UnresolvedEvents int     `json:"unresolved_events"`
	ResolvedEvents   int     `json:"resolved_events"`
	SnoozedEvents    int     `json:"snoozed_events"`
	TotalProjects    int     `json:"total_projects"`
	TotalTransactions int    `json:"total_transactions"`
	EventsPerMinute  float64 `json:"events_per_minute"`
	TotalAttachments int     `json:"total_attachments"`
	GroupingRules    int     `json:"grouping_rules"`
	RetentionDays    int     `json:"retention_days"`
	GoVersion        string  `json:"go_version"`
	GoRoutines       int     `json:"goroutines"`
	MemAllocMB       float64 `json:"mem_alloc_mb"`
}

func querySystemMetrics() SystemMetrics {
	m := SystemMetrics{
		Version:       currentVersion,
		Uptime:        time.Since(startTime).Round(time.Second).String(),
		UptimeSeconds: time.Since(startTime).Seconds(),
		RetentionDays: globalRetentionDays,
		GoVersion:     runtime.Version(),
		GoRoutines:    runtime.NumGoroutine(),
	}

	// Memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.MemAllocMB = math.Round(float64(memStats.Alloc)/1024/1024*100) / 100

	// DB file size
	if dbFilePath != "" {
		if info, err := os.Stat(dbFilePath); err == nil {
			m.DBSizeBytes = info.Size()
			m.DBSizeHuman = humanBytes(info.Size())
		}
	}

	// Counts
	_ = db.QueryRow("SELECT COUNT(*) FROM events").Scan(&m.TotalEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'unresolved'").Scan(&m.UnresolvedEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'resolved'").Scan(&m.ResolvedEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'snoozed'").Scan(&m.SnoozedEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM projects").Scan(&m.TotalProjects)
	_ = db.QueryRow("SELECT COUNT(*) FROM transactions").Scan(&m.TotalTransactions)
	_ = db.QueryRow("SELECT COUNT(*) FROM attachments").Scan(&m.TotalAttachments)
	_ = db.QueryRow("SELECT COUNT(*) FROM grouping_rules WHERE enabled = 1").Scan(&m.GroupingRules)

	// Events per minute (based on atomic counter)
	total := atomic.LoadInt64(&ingestCount)
	upMin := time.Since(startTime).Minutes()
	if upMin > 0 {
		m.EventsPerMinute = math.Round(float64(total)/upMin*100) / 100
	}

	return m
}

func humanBytes(b int64) string {
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

// saveEvent inserts a new event or increments the counter of an existing
// duplicate. Duplicates are identified by (project_id, message, level).
func saveEvent(ev SentryEvent, projectID, rawPayload string) error {
	if ev.EventID == "" {
		ev.EventID = generateUUID()
	}
	if ev.Level == "" {
		ev.Level = "error"
	}

	// Track ingestion rate
	incrIngestCount()

	// Apply smart grouping rules to normalize the message for dedup
	ev.Message = applyGroupingRules(ev.Message, projectID)

	ts := time.Now().UTC()
	if ev.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
			ts = parsed.UTC()
		} else if parsed, err := time.Parse("2006-01-02T15:04:05", ev.Timestamp); err == nil {
			ts = parsed.UTC()
		}
	}
	tsStr := ts.Format(time.RFC3339)

	var oldStatus string
	err := db.QueryRow("SELECT status FROM events WHERE project_id = ? AND message = ? AND level = ?", projectID, ev.Message, ev.Level).Scan(&oldStatus)
	isNew := err == sql.ErrNoRows

	var newCount int
	var newStatus string
	err = db.QueryRow(
		`INSERT INTO events (id, project_id, timestamp, level, platform, message, raw_payload, count, last_seen, status, resolved_in_release, snoozed_until)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 'unresolved', '', '')
		 ON CONFLICT(project_id, message, level) DO UPDATE SET
		   count     = events.count + 1,
		   last_seen = ?,
		   status = CASE 
		     WHEN events.status = 'resolved' AND events.resolved_in_release = 'next' AND COALESCE(json_extract(EXCLUDED.raw_payload, '$.release'), '') = COALESCE(json_extract(events.raw_payload, '$.release'), '') THEN 'resolved'
		     WHEN events.status = 'snoozed' AND events.snoozed_until > ? THEN 'snoozed'
		     ELSE 'unresolved'
		   END,
		   resolved_in_release = CASE
		     WHEN events.status = 'resolved' AND events.resolved_in_release = 'next' AND COALESCE(json_extract(EXCLUDED.raw_payload, '$.release'), '') != COALESCE(json_extract(events.raw_payload, '$.release'), '') THEN ''
		     ELSE events.resolved_in_release
		   END,
		   snoozed_until = CASE
		     WHEN events.status = 'snoozed' AND events.snoozed_until <= ? THEN ''
		     ELSE events.snoozed_until
		   END,
		   raw_payload = EXCLUDED.raw_payload
		 RETURNING count, status`,
		ev.EventID, projectID, tsStr, ev.Level, ev.Platform, ev.Message, rawPayload, tsStr,
		tsStr, tsStr, tsStr,
	).Scan(&newCount, &newStatus)
	if err != nil {
		return fmt.Errorf("upsert event: %w", err)
	}
	log.Printf("event project=%s level=%s msg=%q count=%d status=%s",
		projectID, ev.Level, truncate(ev.Message, 80), newCount, newStatus)

	shouldNotify := isNew || (oldStatus == "resolved" && newStatus == "unresolved") || (oldStatus == "snoozed" && newStatus == "unresolved")
	evaluateAndTriggerWebhooks(ev, projectID, shouldNotify)

	return nil
}

// ---------- Event Row (UI) ----------

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

// parseSentryTimestamp converts float64 (unix seconds) or string (RFC3339) to time.Time
func parseSentryTimestamp(v interface{}) time.Time {
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

// saveTransaction inserts a transaction and its spans into the database.
func saveTransaction(tx SentryTransaction, projectID, rawPayload string) error {
	if tx.EventID == "" {
		tx.EventID = generateUUID()
	}
	if tx.Transaction == "" {
		tx.Transaction = "unknown_transaction"
	}

	startTs := parseSentryTimestamp(tx.StartTimestamp)
	endTs := parseSentryTimestamp(tx.Timestamp)
	durationMs := endTs.Sub(startTs).Seconds() * 1000.0

	if durationMs < 0 {
		durationMs = 0
	}

	_, err := db.Exec(
		`INSERT OR IGNORE INTO transactions (id, project_id, name, start_timestamp, timestamp, duration_ms, raw_payload)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tx.EventID, projectID, tx.Transaction, startTs.Format(time.RFC3339Nano), endTs.Format(time.RFC3339Nano), durationMs, rawPayload,
	)
	if err != nil {
		return fmt.Errorf("insert transaction: %w", err)
	}

	// Insert spans
	for _, span := range tx.Spans {
		if span.SpanID == "" {
			continue
		}
		spanStart := parseSentryTimestamp(span.StartTimestamp)
		spanEnd := parseSentryTimestamp(span.Timestamp)
		spanDur := spanEnd.Sub(spanStart).Seconds() * 1000.0
		if spanDur < 0 {
			spanDur = 0
		}
		_, _ = db.Exec(
			`INSERT OR IGNORE INTO spans (id, transaction_id, parent_span_id, op, description, start_timestamp, timestamp, duration_ms)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			span.SpanID, tx.EventID, span.ParentSpanID, span.Op, span.Description, spanStart.Format(time.RFC3339Nano), spanEnd.Format(time.RFC3339Nano), spanDur,
		)
	}

	return nil
}

// ---------- Transactions & Spans DB Queries ----------

type TransactionGroupRow struct {
	ExemplarID    string
	ProjectID     string
	Name          string
	Count         int
	AvgDurationMs float64
	MaxDurationMs float64
}

func queryTransactionGroups() ([]TransactionGroupRow, error) {
	q := `
		SELECT t1.id, t1.project_id, t1.name, t2.cnt, t2.avg_ms, t2.max_ms
		FROM transactions t1
		JOIN (
			SELECT name, COUNT(*) as cnt, AVG(duration_ms) as avg_ms, MAX(duration_ms) as max_ms
			FROM transactions
			GROUP BY name
		) t2 ON t1.name = t2.name AND t1.duration_ms = t2.max_ms
		GROUP BY t1.name
		ORDER BY t2.max_ms DESC
		LIMIT 50
	`
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []TransactionGroupRow
	for rows.Next() {
		var g TransactionGroupRow
		if err := rows.Scan(&g.ExemplarID, &g.ProjectID, &g.Name, &g.Count, &g.AvgDurationMs, &g.MaxDurationMs); err == nil {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

type SpanRow struct {
	ID             string
	Op             string
	Description    string
	StartTimestamp time.Time
	DurationMs     float64
}

func querySpans(transactionID string) ([]SpanRow, error) {
	q := `SELECT id, op, description, start_timestamp, duration_ms FROM spans WHERE transaction_id = ? ORDER BY start_timestamp ASC`
	rows, err := db.Query(q, transactionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var spans []SpanRow
	for rows.Next() {
		var s SpanRow
		var ts string
		if err := rows.Scan(&s.ID, &s.Op, &s.Description, &ts, &s.DurationMs); err == nil {
			if parsed, e := time.Parse(time.RFC3339Nano, ts); e == nil {
				s.StartTimestamp = parsed
			}
			spans = append(spans, s)
		}
	}
	return spans, nil
}

// queryEvents returns the latest events for the dashboard.
func queryEvents(limit int, levelFilter string, searchFilter string, projectFilter string, envFilter string) ([]EventRow, error) {
	var q string
	var args []interface{}

	q = `
		SELECT
			COALESCE(id, ''),
			COALESCE(project_id, ''),
			COALESCE(CASE WHEN last_seen = '' THEN timestamp ELSE last_seen END, ''),
			COALESCE(level, 'error'),
			COALESCE(platform, ''),
			COALESCE(message, ''),
			COALESCE(count, 1),
			COALESCE(status, 'unresolved'),
			json_extract(raw_payload, '$.release')
		FROM events
		WHERE status = 'unresolved'
	`

	if levelFilter != "" && levelFilter != "All" {
		q += " AND level = ?"
		args = append(args, levelFilter)
	}

	if projectFilter != "" && projectFilter != "All" {
		q += " AND project_id = ?"
		args = append(args, projectFilter)
	}

	if envFilter != "" && envFilter != "All" {
		q += " AND json_extract(raw_payload, '$.environment') = ?"
		args = append(args, envFilter)
	}

	if searchFilter != "" {
		q += " AND (message LIKE '%' || ? || '%' OR platform LIKE '%' || ? || '%')"
		args = append(args, searchFilter, searchFilter)
	}

	q += " ORDER BY CASE WHEN last_seen = '' THEN timestamp ELSE last_seen END DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var result []EventRow
	for rows.Next() {
		var ev EventRow
		var release sql.NullString
		if err := rows.Scan(&ev.ID, &ev.ProjectID, &ev.LastSeen, &ev.Level, &ev.Platform, &ev.Message, &ev.Count, &ev.Status, &release); err != nil {
			log.Printf("scan row: %v", err)
			continue
		}
		if release.Valid {
			ev.Release = release.String
		}
		ev.LastSeen = formatTimestamp(ev.LastSeen)
		result = append(result, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return result, nil
}

// ---------- Stats ----------

// StatPoint represents a single day's count of events.
type StatPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// queryStats returns the total count of events per day for the last 7 days.
func queryStats() ([]StatPoint, error) {
	const q = `
		WITH RECURSIVE dates(date) AS (
			SELECT date('now', '-6 days')
			UNION ALL
			SELECT date(date, '+1 day')
			FROM dates
			WHERE date < date('now')
		)
		SELECT
			d.date,
			COALESCE(SUM(e.count), 0)
		FROM dates d
		LEFT JOIN events e ON date(CASE WHEN e.last_seen = '' THEN e.timestamp ELSE e.last_seen END) = d.date
		GROUP BY d.date
		ORDER BY d.date ASC
	`
	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("query stats: %w", err)
	}
	defer rows.Close()

	var result []StatPoint
	for rows.Next() {
		var sp StatPoint
		if err := rows.Scan(&sp.Date, &sp.Count); err != nil {
			log.Printf("scan stat: %v", err)
			continue
		}
		result = append(result, sp)
	}
	return result, nil
}

// queryEnvironments returns a list of unique environments present in the events.
func queryEnvironments() ([]string, error) {
	q := `SELECT DISTINCT json_extract(raw_payload, '$.environment') FROM events 
	      WHERE json_extract(raw_payload, '$.environment') IS NOT NULL 
	      AND json_extract(raw_payload, '$.environment') != ''`
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var envs []string
	for rows.Next() {
		var env string
		if err := rows.Scan(&env); err == nil {
			envs = append(envs, env)
		}
	}
	return envs, nil
}

// formatTimestamp converts an RFC3339 timestamp into a shorter, more readable
// format for the dashboard (e.g. "2026-06-09 14:12:23").
func formatTimestamp(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.Format("2006-01-02 15:04:05")
}

// ---------- Event Detail ----------

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

// rawExceptionValue extends the ingestion struct with stacktrace data.
type rawExceptionValue struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Stacktrace *struct {
		Frames []StackFrame `json:"frames"`
	} `json:"stacktrace,omitempty"`
}

// rawPayloadDetail is used to extract rich metadata from the stored JSON.
type rawPayloadDetail struct {
	EventID     string            `json:"event_id"`
	Timestamp   string            `json:"timestamp"`
	Level       string            `json:"level"`
	Platform    string            `json:"platform"`
	ServerName  string            `json:"server_name"`
	Environment string            `json:"environment"`
	Release     string            `json:"release"`
	Tags        map[string]string `json:"tags"`
	Contexts    map[string]json.RawMessage `json:"contexts"`
	User        *struct {
		IP    string `json:"ip_address"`
		Email string `json:"email"`
	} `json:"user,omitempty"`
	Request *struct {
		URL    string            `json:"url"`
		Method string            `json:"method"`
		Headers map[string]string `json:"headers"`
	} `json:"request,omitempty"`
	Exception *struct {
		Values []rawExceptionValue `json:"values"`
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
	ID          string
	ProjectID   string
	Timestamp   string
	LastSeen    string
	Level       string
	Platform    string
	Message     string
	Count       int
	Status      string
	ResolvedInRelease string
	SnoozedUntil      string

	ExcType     string
	ExcValue    string

	OS          string
	Browser     string
	Runtime     string
	ServerName  string
	Environment string
	Release     string
	IP          string
	URL         string
	SDKName     string

	Frames      []StackFrame
	HasFrames   bool
	Tags        map[string]string
	HasTags     bool
	Breadcrumbs []Breadcrumb
	HasBreadcrumbs bool
	Comments    []EventComment
	Attachments []Attachment
	HasAttachments bool
	HasLibraryFrames bool
	RawJSON     string
}

// queryEventByID fetches a single event from the database.
func queryEventByID(id string) (*EventDetail, error) {
	const q = `
		SELECT
			COALESCE(id, ''),
			COALESCE(project_id, ''),
			COALESCE(timestamp, ''),
			COALESCE(CASE WHEN last_seen = '' THEN timestamp ELSE last_seen END, ''),
			COALESCE(level, 'error'),
			COALESCE(platform, ''),
			COALESCE(message, ''),
			COALESCE(count, 1),
			COALESCE(status, 'unresolved'),
			COALESCE(resolved_in_release, ''),
			COALESCE(snoozed_until, ''),
			COALESCE(raw_payload, '{}')
		FROM events WHERE id = ?
	`
	var ev EventDetail
	var rawPayload string
	err := db.QueryRow(q, id).Scan(
		&ev.ID, &ev.ProjectID, &ev.Timestamp, &ev.LastSeen,
		&ev.Level, &ev.Platform, &ev.Message, &ev.Count,
		&ev.Status, &ev.ResolvedInRelease, &ev.SnoozedUntil, &rawPayload,
	)
	if err != nil {
		return nil, err
	}
	ev.Timestamp = formatTimestamp(ev.Timestamp)
	ev.LastSeen = formatTimestamp(ev.LastSeen)

	// Pretty-print raw JSON for display.
	var buf bytes.Buffer
	if json.Indent(&buf, []byte(rawPayload), "", "  ") == nil {
		ev.RawJSON = buf.String()
	} else {
		ev.RawJSON = rawPayload
	}

	// Parse metadata from raw payload.
	var raw rawPayloadDetail
	if json.Unmarshal([]byte(rawPayload), &raw) == nil {
		ev.ServerName = raw.ServerName
		ev.Environment = raw.Environment
		ev.Release = raw.Release

		if raw.User != nil {
			ev.IP = raw.User.IP
		}
		if raw.Request != nil {
			ev.URL = raw.Request.URL
		}
		if raw.SDK != nil {
			ev.SDKName = raw.SDK.Name + " " + raw.SDK.Version
		}
		if raw.Tags != nil && len(raw.Tags) > 0 {
			ev.Tags = raw.Tags
			ev.HasTags = true
		}

		// Extract Breadcrumbs
		if len(raw.Breadcrumbs) > 0 {
			var bcArray []struct {
				Type      string                 `json:"type"`
				Category  string                 `json:"category"`
				Message   string                 `json:"message"`
				Level     string                 `json:"level"`
				Timestamp interface{}            `json:"timestamp"`
				Data      map[string]interface{} `json:"data"`
			}

			// Try to parse as array first
			if err := json.Unmarshal(raw.Breadcrumbs, &bcArray); err != nil {
				// Fallback to object format { "values": [...] }
				var bcObj struct {
					Values []struct {
						Type      string                 `json:"type"`
						Category  string                 `json:"category"`
						Message   string                 `json:"message"`
						Level     string                 `json:"level"`
						Timestamp interface{}            `json:"timestamp"`
						Data      map[string]interface{} `json:"data"`
					} `json:"values"`
				}
				if json.Unmarshal(raw.Breadcrumbs, &bcObj) == nil {
					bcArray = bcObj.Values
				}
			}

			if len(bcArray) > 0 {
				ev.HasBreadcrumbs = true
				for _, bc := range bcArray {
					ts := parseSentryTimestamp(bc.Timestamp).Format("15:04:05")
					if bc.Level == "" {
						bc.Level = "info"
					}
					ev.Breadcrumbs = append(ev.Breadcrumbs, Breadcrumb{
						Timestamp: ts,
						Type:      bc.Type,
						Category:  bc.Category,
						Level:     bc.Level,
						Message:   bc.Message,
						Data:      bc.Data,
					})
				}
			}
		}

		// Extract OS / Browser / Runtime from contexts.
		if raw.Contexts != nil {
			ev.OS = extractContextField(raw.Contexts, "os", "name", "version")
			ev.Browser = extractContextField(raw.Contexts, "browser", "name", "version")
			ev.Runtime = extractContextField(raw.Contexts, "runtime", "name", "version")
		}

		// Extract exception type/value and stack frames.
		if raw.Exception != nil && len(raw.Exception.Values) > 0 {
			exc := raw.Exception.Values[0]
			ev.ExcType = exc.Type
			ev.ExcValue = exc.Value
			if exc.Stacktrace != nil && len(exc.Stacktrace.Frames) > 0 {
				// Sentry sends frames bottom-up; reverse for display.
				frames := exc.Stacktrace.Frames
				for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
					frames[i], frames[j] = frames[j], frames[i]
				}
				
				// Apply Source Maps if available
				ev.Frames = applySourceMaps(frames, ev.ProjectID, ev.Release)
				ev.HasFrames = true
				for _, f := range ev.Frames {
					if !f.InApp {
						ev.HasLibraryFrames = true
						break
					}
				}
			}
		}
	}

	// Fetch comments
	cRows, err := db.Query("SELECT id, comment, timestamp, author FROM event_comments WHERE event_id = ? ORDER BY timestamp ASC", id)
	if err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var c EventComment
			var ts string
			if err := cRows.Scan(&c.ID, &c.Comment, &ts, &c.Author); err == nil {
				c.EventID = id
				c.Timestamp = formatTimestamp(ts)
				ev.Comments = append(ev.Comments, c)
			}
		}
	}

	// Fetch attachments
	ev.Attachments = queryAttachments(id)
	ev.HasAttachments = len(ev.Attachments) > 0

	return &ev, nil
}

// applySourceMaps attempts to translate minified frames using local .map files.
func applySourceMaps(frames []StackFrame, projectID, release string) []StackFrame {
	dataDir := filepath.Dir(dbFilePath)
	for i, frame := range frames {
		// e.g. "http://domain.com/js/main.min.js" -> "main.min.js"
		if frame.Filename == "" && frame.AbsPath != "" {
			frame.Filename = frame.AbsPath
		}
		
		base := filepath.Base(frame.Filename)
		if base == "" || !strings.HasSuffix(base, ".js") {
			continue
		}

		// Look in data/sourcemaps/{projectID}/{release}/ first
		var data []byte
		var err error
		var actualMapPath string
		if projectID != "" && release != "" {
			actualMapPath = filepath.Join(dataDir, "sourcemaps", projectID, release, base+".map")
			data, err = os.ReadFile(actualMapPath)
		}

		// Fallback to local ./sourcemaps/
		if err != nil || len(data) == 0 {
			actualMapPath = filepath.Join("sourcemaps", base+".map")
			data, err = os.ReadFile(actualMapPath)
		}

		if err != nil {
			continue // Map file not found
		}

		smap, err := sourcemap.Parse("", data)
		if err != nil {
			log.Printf("failed to parse sourcemap %s: %v", actualMapPath, err)
			continue
		}

		source, name, line, col, ok := smap.Source(frame.Lineno, frame.Colno)
		if ok {
			frames[i].Filename = source
			frames[i].Lineno = line
			frames[i].Colno = col
			if name != "" {
				frames[i].Function = name
			}
			
			// Optional: Try to extract context lines if sourcesContent is present
			if content := smap.SourceContent(source); content != "" {
				lines := strings.Split(content, "\n")
				if line > 0 && line <= len(lines) {
					frames[i].ContextLine = lines[line-1]
					
					// Pre context
					preStart := line - 4
					if preStart < 0 { preStart = 0 }
					frames[i].PreContext = lines[preStart : line-1]
					
					// Post context
					postEnd := line + 3
					if postEnd > len(lines) { postEnd = len(lines) }
					frames[i].PostContext = lines[line : postEnd]
				}
			}
		}
	}
	return frames
}

// extractContextField reads "name" and "version" from a context entry.
func extractContextField(contexts map[string]json.RawMessage, key, nameKey, versionKey string) string {
	data, ok := contexts[key]
	if !ok {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	name, _ := m[nameKey].(string)
	version, _ := m[versionKey].(string)
	if name == "" {
		return ""
	}
	if version != "" {
		return name + " " + version
	}
	return name
}

// ---------- Sentry Event Parsing ----------

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

// extractMessage determines the human-readable message from a SentryEvent,
// checking multiple possible locations where SDKs place it.
func (ev *SentryEvent) extractMessage() string {
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

// parseSentryEvent unmarshals a JSON blob into a SentryEvent and resolves
// the message field.
func parseSentryEvent(data []byte) (SentryEvent, error) {
	var ev SentryEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return ev, fmt.Errorf("unmarshal event: %w", err)
	}
	ev.Message = ev.extractMessage()
	return ev, nil
}

// ---------- Envelope Parsing ----------

// parseEnvelope handles the Sentry envelope format (NDJSON) and returns the event ID, item Type, and its raw JSON payload.
func parseEnvelope(raw []byte) (string, string, []byte, error) {
	lines := splitEnvelopeLines(raw)
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

// splitEnvelopeLines splits envelope bytes by newlines, skipping empty lines.
func splitEnvelopeLines(data []byte) [][]byte {
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

// ---------- Helpers ----------

// generateUUID generates a random UUID v4 formatted as 32 hex characters
// (no dashes), which is the format Sentry uses for event IDs.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x%04x%04x%04x%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// truncate shortens a string to at most n characters, appending "…" if cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------- Middleware ----------

// corsMiddleware sets permissive CORS headers so browser-based Sentry SDKs
// can communicate freely.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gzipDecodeMiddleware transparently decompresses gzip-encoded request bodies.
func gzipDecodeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "failed to decode gzip body", http.StatusBadRequest)
				return
			}
			defer gz.Close()
			r.Body = gz
			r.Header.Del("Content-Encoding")
		}
		next.ServeHTTP(w, r)
	})
}

// Global auth and webhook credentials (set from CLI flags in main).
var (
	adminUser         string
	adminPass         string
	discordWebhookURL   string
	tgToken             string
	tgChatID            string
	startTime           time.Time
	globalRetentionDays int
)

// basicAuthMiddleware protects UI routes with HTTP Basic Authentication.
// If adminUser and adminPass are both empty, it passes requests through.
func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminUser == "" && adminPass == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != adminUser || pass != adminPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="PocketSentry"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Webhooks ----------

// evaluateAndTriggerWebhooks evaluates smart alerting rules before triggering.
// If any rule matches, it sends to the rule's specific targets. If no rule matches,
// it falls back to the default project/global webhooks ONLY IF shouldNotify is true
// (which means it's a new or reopened event).
func evaluateAndTriggerWebhooks(ev SentryEvent, projectID string, shouldNotify bool) {
	// First, fetch all enabled alerting rules for this project.
	rows, err := db.Query("SELECT environment, min_count, time_window_minutes, target_discord, target_telegram_token, target_telegram_chat_id FROM alerting_rules WHERE project_id = ? AND enabled = 1", projectID)
	if err == nil {
		defer rows.Close()
		var env string
		var minCount, timeWindow int
		var tDiscord, tTGToken, tTGChatID string
		
		ruleMatched := false

		for rows.Next() {
			if err := rows.Scan(&env, &minCount, &timeWindow, &tDiscord, &tTGToken, &tTGChatID); err != nil {
				continue
			}

			// Check environment match
			if env != "" && ev.Environment != env && ev.Environment != "" {
				continue
			}

			// Check rate limit threshold
			countMatched := true
			if minCount > 1 && timeWindow > 0 {
				// We need to count occurrences in the transactions/events tables, but we don't store individual occurrences
				// cleanly if they are deduplicated. However, we can check the total `count` from the `events` table
				// and assume it's rising, or we just look at the current total count if timeWindow logic is too complex for now.
				// Since we just updated the event, we can check its current count.
				// For a true rolling window, we'd need an `occurrences` log table. Let's simplify: if the event count is exactly the minCount, we fire.
				// Actually, to make it simple and effective: trigger if the event's count % minCount == 0.
				var currentCount int
				err := db.QueryRow("SELECT count FROM events WHERE project_id = ? AND message = ? AND level = ?", projectID, ev.Message, ev.Level).Scan(&currentCount)
				if err != nil || currentCount < minCount || currentCount%minCount != 0 {
					countMatched = false
				}
			}

			if countMatched {
				// We found a matching rule! Trigger its specific webhooks.
				ruleMatched = true
				msg := fmt.Sprintf("🚨 **PocketSentry Smart Alert**\n\n**Project:** %s\n**Level:** %s\n**Message:** %s\n**Time:** %s",
					projectID, ev.Level, truncate(ev.Message, 150), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
				
				if tDiscord != "" {
					go sendDiscordWebhook(tDiscord, msg)
				}
				if tTGToken != "" && tTGChatID != "" {
					go sendTelegramWebhook(tTGToken, tTGChatID, msg, ev.EventID)
				}
			}
		}

		if ruleMatched {
			// If a specific rule fired, we don't fire the default fallback.
			return
		}
	}

	// No rules matched. Fallback to default if shouldNotify is true.
	if shouldNotify {
		triggerWebhooks(ev, projectID)
	}
}

// triggerWebhooks sends a notification to configured default webhooks.
func triggerWebhooks(ev SentryEvent, projectID string) {
	// Format the message
	msg := fmt.Sprintf("🚨 **PocketSentry Alert**\n\n**Project:** %s\n**Level:** %s\n**Message:** %s\n**Time:** %s",
		projectID, ev.Level, truncate(ev.Message, 150), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	// Default webhook targets
	targetDiscord := discordWebhookURL
	targetTGToken := tgToken
	targetTGChatID := tgChatID

	// Check if this project has webhook overrides
	var pTGToken, pTGChatID, pDiscordWebhook string
	err := db.QueryRow("SELECT COALESCE(tg_token, ''), COALESCE(tg_chat_id, ''), COALESCE(discord_webhook, '') FROM projects WHERE id = ?", projectID).Scan(&pTGToken, &pTGChatID, &pDiscordWebhook)
	if err == nil {
		if pDiscordWebhook != "" {
			targetDiscord = pDiscordWebhook
		}
		if pTGToken != "" && pTGChatID != "" {
			targetTGToken = pTGToken
			targetTGChatID = pTGChatID
		}
	}

	// Discord
	if targetDiscord != "" {
		go sendDiscordWebhook(targetDiscord, msg)
	}

	// Telegram
	if targetTGToken != "" && targetTGChatID != "" {
		go sendTelegramWebhook(targetTGToken, targetTGChatID, msg, ev.EventID)
	}
}

func sendDiscordWebhook(url, content string) {
	payload, _ := json.Marshal(map[string]string{"content": content})
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[discord] webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[discord] webhook returned status %d", resp.StatusCode)
	}
}

func sendTelegramWebhook(token, chatID, content, eventID string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	
	payloadData := map[string]interface{}{
		"chat_id":    chatID,
		"text":       content,
		"parse_mode": "Markdown",
	}

	if eventID != "" {
		payloadData["reply_markup"] = map[string]interface{}{
			"inline_keyboard": [][]map[string]interface{}{
				{
					{
						"text":          "✅ Resolve",
						"callback_data": "resolve_" + eventID,
					},
				},
			},
		}
	}

	payload, _ := json.Marshal(payloadData)
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[telegram] webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[telegram] webhook returned status %d", resp.StatusCode)
	}
}

// ---------- Telegram Bot Polling ----------

var (
	activePollers = make(map[string]bool)
	pollerMutex   sync.Mutex
)

func ensureTelegramPollers() {
	for {
		tokens := make(map[string]bool)
		if tgToken != "" {
			tokens[tgToken] = true
		}

		rows, err := db.Query("SELECT DISTINCT tg_token FROM projects WHERE tg_token IS NOT NULL AND tg_token != ''")
		if err == nil {
			for rows.Next() {
				var t string
				if err := rows.Scan(&t); err == nil {
					tokens[t] = true
				}
			}
			rows.Close()
		}

		pollerMutex.Lock()
		for t := range tokens {
			if !activePollers[t] {
				activePollers[t] = true
				go runTelegramPoller(t)
			}
		}
		pollerMutex.Unlock()

		time.Sleep(1 * time.Minute)
	}
}

func runTelegramPoller(token string) {
	offset := 0
	log.Printf("[telegram] started polling for bot token: %s...", token[:5])

	for {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30", token, offset)
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		var updateRes struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID      int `json:"update_id"`
				CallbackQuery struct {
					ID      string `json:"id"`
					Message struct {
						MessageID int `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
						Text string `json:"text"`
					} `json:"message"`
					Data string `json:"data"`
					From struct {
						FirstName string `json:"first_name"`
					} `json:"from"`
				} `json:"callback_query"`
			} `json:"result"`
		}

		err = json.NewDecoder(resp.Body).Decode(&updateRes)
		resp.Body.Close()
		if err != nil || !updateRes.Ok {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, u := range updateRes.Result {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}

			cb := u.CallbackQuery
			if strings.HasPrefix(cb.Data, "resolve_") {
				eventID := strings.TrimPrefix(cb.Data, "resolve_")
				
				// Resolve event in DB
				_, _ = db.Exec("UPDATE events SET status = 'resolved' WHERE id = ?", eventID)

				// Answer callback (removes loading state from button)
				ansURL := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery?callback_query_id=%s&text=Event%%20Resolved!", token, cb.ID)
				_, _ = http.Get(ansURL)

				// Edit message to remove button and append resolved info
				newText := cb.Message.Text + fmt.Sprintf("\n\n✅ *Resolved by %s*", cb.From.FirstName)
				editURL := fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", token)
				
				payload, _ := json.Marshal(map[string]interface{}{
					"chat_id":    cb.Message.Chat.ID,
					"message_id": cb.Message.MessageID,
					"text":       newText,
				})
				http.Post(editURL, "application/json", bytes.NewReader(payload))
			}
		}
	}
}

// ---------- Handlers ----------

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

// indexHandler serves the main dashboard page.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'unresolved'").Scan(&count)

	var hooks []string
	if tgToken != "" {
		hooks = append(hooks, "Telegram")
	}
	if discordWebhookURL != "" {
		hooks = append(hooks, "Discord")
	}
	webhooks := "None"
	if len(hooks) > 0 {
		webhooks = strings.Join(hooks, " & ")
	}

	retention := "Keep forever"
	if globalRetentionDays > 0 {
		retention = fmt.Sprintf("%d days", globalRetentionDays)
	}

	var projects []Project
	rows, err := db.Query("SELECT id, name, COALESCE(tg_token, ''), COALESCE(tg_chat_id, ''), COALESCE(discord_webhook, '') FROM projects ORDER BY id ASC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p Project
			if err := rows.Scan(&p.ID, &p.Name, &p.TGToken, &p.TGChatID, &p.DiscordWebhook); err == nil {
				projects = append(projects, p)
			}
		}
	}

	envs, _ := queryEnvironments()

	data := IndexData{
		UnresolvedCount: count,
		Webhooks:        webhooks,
		Retention:       retention,
		Projects:        projects,
		Environments:    envs,
	}

	if err := tmplIndex.Execute(w, data); err != nil {
		log.Printf("❌ template execute error: %v", err)
	}
}

// eventsHandler returns rendered <tr> rows for the HTMX table.
func eventsHandler(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	search := r.URL.Query().Get("search")
	project := r.URL.Query().Get("project")
	env := r.URL.Query().Get("environment")
	
	events, err := queryEvents(50, level, search, project, env)
	if err != nil {
		log.Printf("query events: %v", err)
		events = []EventRow{}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmplRows.Execute(w, events); err != nil {
		log.Printf("rows template error: %v", err)
	}
}

// exportCSVHandler generates a CSV file with currently filtered events.
func exportCSVHandler(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	search := r.URL.Query().Get("search")
	project := r.URL.Query().Get("project")
	env := r.URL.Query().Get("environment")

	events, err := queryEvents(10000, level, search, project, env)
	if err != nil {
		log.Printf("csv export error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="pocketsentry_events.csv"`)

	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"ID", "ProjectID", "LastSeen", "Level", "Platform", "Message", "Occurrences", "Status"})

	for _, ev := range events {
		_ = writer.Write([]string{
			ev.ID,
			ev.ProjectID,
			ev.LastSeen,
			ev.Level,
			ev.Platform,
			ev.Message,
			fmt.Sprintf("%d", ev.Count),
			ev.Status,
		})
	}
	writer.Flush()
}

// storeHandler handles the legacy /api/{project_id}/store/ endpoint.
func storeHandler(w http.ResponseWriter, r *http.Request) {
	projectID := extractProjectID(r.URL.Path, "/store/")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	ev, err := parseSentryEvent(body)
	if err != nil {
		log.Printf("[store] parse error: %v", err)
		respondOK(w)
		return
	}

	if err := saveEvent(ev, projectID, string(body)); err != nil {
		log.Printf("[store] save error: %v", err)
	}

	respondWithID(w, ev.EventID)
}

// envelopeHandler handles the newer /api/{project_id}/envelope/ endpoint.
func envelopeHandler(w http.ResponseWriter, r *http.Request) {
	projectID := extractProjectID(r.URL.Path, "/envelope/")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	eventID, itemType, rawJSON, err := parseEnvelope(body)
	if err != nil {
		log.Printf("[envelope] parse error: %v", err)
		respondOK(w)
		return
	}

	if itemType == "transaction" {
		var tx SentryTransaction
		if err := json.Unmarshal(rawJSON, &tx); err == nil {
			if tx.EventID == "" {
				tx.EventID = eventID
			}
			if err := saveTransaction(tx, projectID, string(rawJSON)); err != nil {
				log.Printf("[envelope] save transaction error: %v", err)
			}
		}
	} else {
		ev, err := parseSentryEvent(rawJSON)
		if err == nil {
			if ev.EventID == "" {
				ev.EventID = eventID
			}
			if err := saveEvent(ev, projectID, string(rawJSON)); err != nil {
				log.Printf("[envelope] save event error: %v", err)
			}
		}
	}

	// Process attachments from envelope
	extractAndSaveAttachments(body, eventID)

	respondWithID(w, eventID)
}

// extractAndSaveAttachments scans an envelope for attachment items and saves them.
func extractAndSaveAttachments(envelopeData []byte, eventID string) {
	if eventID == "" {
		return
	}
	lines := splitEnvelopeLines(envelopeData)
	for i := 1; i+1 < len(lines); i += 2 {
		var itemHeader struct {
			Type        string `json:"type"`
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
		}
		if err := json.Unmarshal(lines[i], &itemHeader); err != nil {
			continue
		}
		if strings.ToLower(itemHeader.Type) == "attachment" {
			ct := itemHeader.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			fn := itemHeader.Filename
			if fn == "" {
				fn = "attachment"
			}
			if err := saveAttachment(eventID, fn, ct, lines[i+1]); err != nil {
				log.Printf("[envelope] save attachment error: %v", err)
			}
		}
	}
}

// performanceHandler renders the performance tab content.
func performanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	groups, err := queryTransactionGroups()
	if err != nil {
		log.Printf("query transaction groups error: %v", err)
	}

	tmpl, err := template.ParseFiles(filepath.Join("templates", "performance.html"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, map[string]interface{}{
		"Groups": groups,
	})
}

// latencyAnalyticsHandler returns p50, p90, p99 latencies grouped by hour for the last 24h.
func latencyAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT strftime('%Y-%m-%d %H:00:00', start_timestamp) as bucket, duration_ms 
		FROM transactions 
		WHERE start_timestamp >= datetime('now', '-24 hours')
	`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	buckets := make(map[string][]float64)
	for rows.Next() {
		var bucket string
		var duration float64
		if err := rows.Scan(&bucket, &duration); err == nil {
			buckets[bucket] = append(buckets[bucket], duration)
		}
	}

	type BucketStats struct {
		Bucket string  `json:"bucket"`
		P50    float64 `json:"p50"`
		P90    float64 `json:"p90"`
		P99    float64 `json:"p99"`
		Count  int     `json:"count"`
	}

	var results []BucketStats
	for bucket, durations := range buckets {
		sort.Float64s(durations)
		count := len(durations)
		
		getPercentile := func(p float64) float64 {
			if count == 0 { return 0 }
			idx := int(math.Ceil(float64(count)*p)) - 1
			if idx < 0 { idx = 0 }
			if idx >= count { idx = count - 1 }
			return durations[idx]
		}

		results = append(results, BucketStats{
			Bucket: bucket,
			P50:    getPercentile(0.50),
			P90:    getPercentile(0.90),
			P99:    getPercentile(0.99),
			Count:  count,
		})
	}

	// Sort results by bucket time ASC
	sort.Slice(results, func(i, j int) bool {
		return results[i].Bucket < results[j].Bucket
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

// traceHandler renders the waterfall trace for a specific transaction ID.
func traceHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/performance/trace/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	var txName string
	var txStartStr string
	var txDur float64
	err := db.QueryRow("SELECT name, start_timestamp, duration_ms FROM transactions WHERE id = ?", id).Scan(&txName, &txStartStr, &txDur)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	txStart, _ := time.Parse(time.RFC3339Nano, txStartStr)
	rawSpans, _ := querySpans(id)

	type TraceSpan struct {
		Op          string
		Description string
		DurationMs  float64
		LeftPct     float64
		WidthPct    float64
	}

	var traceSpans []TraceSpan
	for _, s := range rawSpans {
		offsetMs := s.StartTimestamp.Sub(txStart).Seconds() * 1000.0
		if offsetMs < 0 { offsetMs = 0 }
		
		leftPct := (offsetMs / txDur) * 100.0
		if leftPct > 100 { leftPct = 100 }
		
		widthPct := (s.DurationMs / txDur) * 100.0
		if leftPct + widthPct > 100 { widthPct = 100 - leftPct }
		if widthPct < 0.5 { widthPct = 0.5 } // Ensure it's at least visible

		traceSpans = append(traceSpans, TraceSpan{
			Op:          s.Op,
			Description: s.Description,
			DurationMs:  s.DurationMs,
			LeftPct:     leftPct,
			WidthPct:    widthPct,
		})
	}

	tmpl, err := template.ParseFiles(filepath.Join("templates", "trace.html"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	_ = tmpl.Execute(w, map[string]interface{}{
		"ID":         id,
		"Name":       txName,
		"DurationMs": txDur,
		"Spans":      traceSpans,
	})
}

// extractProjectID pulls the project ID from a URL path.
func extractProjectID(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	path = strings.TrimPrefix(path, "/api/")
	return path
}

// respondOK sends a 200 with a freshly generated event ID.
func respondOK(w http.ResponseWriter) {
	respondWithID(w, generateUUID())
}

// eventDetailHandler serves the detail page for a single event.
func eventDetailHandler(w http.ResponseWriter, r *http.Request) {
	// Extract event ID from /events/{id}
	id := strings.TrimPrefix(r.URL.Path, "/events/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	ev, err := queryEventByID(id)
	if err != nil {
		log.Printf("event detail: %v", err)
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmplDetail.Execute(w, ev); err != nil {
		log.Printf("detail template error: %v", err)
	}
}

// postCommentHandler handles HTMX form submissions for new comments.
func postCommentHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/events/")
	id = strings.TrimSuffix(id, "/comments")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	
	comment := strings.TrimSpace(r.FormValue("comment"))
	if comment == "" {
		http.Error(w, "empty comment", http.StatusBadRequest)
		return
	}

	author := "Admin" // We could parse from session later
	ts := time.Now().UTC().Format(time.RFC3339)

	_, err := db.Exec("INSERT INTO event_comments (event_id, comment, timestamp, author) VALUES (?, ?, ?, ?)", id, comment, ts, author)
	if err != nil {
		log.Printf("insert comment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Just trigger a page reload via HTMX header to show the new comment,
	// or return the new comment snippet. Since detail.html doesn't have a partial for just comments yet, HX-Refresh is easiest.
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// statsHandler returns JSON for the ApexCharts graph.
func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := queryStats()
	if err != nil {
		log.Printf("query stats: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// systemMetricsHandler returns JSON with system health metrics.
func systemMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(querySystemMetrics())
}

// alertingRulesHandler handles GET (list) and POST (create) for alerting rules.
func alertingRulesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		projectID := r.URL.Query().Get("project_id")
		if projectID == "" {
			http.Error(w, "project_id required", http.StatusBadRequest)
			return
		}
		rows, err := db.Query("SELECT id, project_id, environment, min_count, time_window_minutes, target_discord, target_telegram_token, target_telegram_chat_id, enabled FROM alerting_rules WHERE project_id = ? ORDER BY id ASC", projectID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type Rule struct {
			ID                   int    `json:"id"`
			ProjectID            string `json:"project_id"`
			Environment          string `json:"environment"`
			MinCount             int    `json:"min_count"`
			TimeWindowMinutes    int    `json:"time_window_minutes"`
			TargetDiscord        string `json:"target_discord"`
			TargetTelegramToken  string `json:"target_telegram_token"`
			TargetTelegramChatID string `json:"target_telegram_chat_id"`
			Enabled              bool   `json:"enabled"`
		}
		var rules []Rule
		for rows.Next() {
			var r Rule
			var enabled int
			if err := rows.Scan(&r.ID, &r.ProjectID, &r.Environment, &r.MinCount, &r.TimeWindowMinutes, &r.TargetDiscord, &r.TargetTelegramToken, &r.TargetTelegramChatID, &enabled); err == nil {
				r.Enabled = enabled == 1
				rules = append(rules, r)
			}
		}
		if rules == nil {
			rules = []Rule{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		projectID := r.FormValue("project_id")
		if projectID == "" {
			http.Error(w, "project_id is required", http.StatusBadRequest)
			return
		}
		env := r.FormValue("environment")
		minCount, _ := strconv.Atoi(r.FormValue("min_count"))
		if minCount < 1 {
			minCount = 1
		}
		timeWindow, _ := strconv.Atoi(r.FormValue("time_window_minutes"))
		if timeWindow < 0 {
			timeWindow = 0
		}

		tDiscord := r.FormValue("target_discord")
		tTGToken := r.FormValue("target_telegram_token")
		tTGChatID := r.FormValue("target_telegram_chat_id")

		if tDiscord == "" && (tTGToken == "" || tTGChatID == "") {
			http.Error(w, "at least one webhook target is required", http.StatusBadRequest)
			return
		}

		_, err := db.Exec(
			"INSERT INTO alerting_rules (project_id, environment, min_count, time_window_minutes, target_discord, target_telegram_token, target_telegram_chat_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
			projectID, env, minCount, timeWindow, tDiscord, tTGToken, tTGChatID,
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Refresh", "true")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// deleteAlertingRuleHandler deletes a specific alerting rule.
func deleteAlertingRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/alerting-rules/delete/")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM alerting_rules WHERE id = ?", id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// groupingRulesHandler handles GET (list) and POST (create) for grouping rules.
func groupingRulesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query("SELECT id, project_id, pattern, replacement, description, enabled FROM grouping_rules ORDER BY id ASC")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type Rule struct {
			ID          int    `json:"id"`
			ProjectID   string `json:"project_id"`
			Pattern     string `json:"pattern"`
			Replacement string `json:"replacement"`
			Description string `json:"description"`
			Enabled     bool   `json:"enabled"`
		}
		var rules []Rule
		for rows.Next() {
			var r Rule
			var enabled int
			if err := rows.Scan(&r.ID, &r.ProjectID, &r.Pattern, &r.Replacement, &r.Description, &enabled); err == nil {
				r.Enabled = enabled == 1
				rules = append(rules, r)
			}
		}
		if rules == nil {
			rules = []Rule{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pattern := strings.TrimSpace(r.FormValue("pattern"))
		if pattern == "" {
			http.Error(w, "pattern is required", http.StatusBadRequest)
			return
		}
		// Validate regex
		if _, err := regexp.Compile(pattern); err != nil {
			http.Error(w, "invalid regex: "+err.Error(), http.StatusBadRequest)
			return
		}

		replacement := r.FormValue("replacement")
		description := r.FormValue("description")
		projectID := r.FormValue("project_id")

		_, err := db.Exec(
			"INSERT INTO grouping_rules (project_id, pattern, replacement, description) VALUES (?, ?, ?, ?)",
			projectID, pattern, replacement, description,
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// If HTMX request, refresh page
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Refresh", "true")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// resolveProcessName attempts to find the command line name for a given PID.
func resolveProcessName(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return fmt.Sprintf("PID:%d", pid)
	}
	parts := bytes.Split(b, []byte{0})
	if len(parts) > 0 && len(parts[0]) > 0 {
		return filepath.Base(string(parts[0]))
	}
	return fmt.Sprintf("PID:%d", pid)
}

// topologyHandler returns nodes and edges for the network map.
func topologyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query(`
		SELECT source_node, target_node, target_port, hit_count 
		FROM network_edges 
		ORDER BY last_seen DESC LIMIT 500
	`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Edge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Port   int    `json:"port"`
		Count  int    `json:"count"`
	}

	var edges []Edge
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.Source, &e.Target, &e.Port, &e.Count); err == nil {
			edges = append(edges, e)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(edges)
}

// topologyViewHandler renders the topology tab content.
func topologyViewHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.ParseFiles(filepath.Join("templates", "topology.html"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, nil)
}

// sourceMapUploadHandler handles POST requests to upload .map files.
func sourceMapUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 10MB limit
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	projectID := r.FormValue("project_id")
	release := r.FormValue("release")
	if projectID == "" || release == "" {
		http.Error(w, "project_id and release are required", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if !strings.HasSuffix(header.Filename, ".map") {
		http.Error(w, "only .map files are allowed", http.StatusBadRequest)
		return
	}

	baseDir := filepath.Join(filepath.Dir(dbFilePath), "sourcemaps", projectID, release)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		http.Error(w, "failed to create directory", http.StatusInternalServerError)
		return
	}

	outPath := filepath.Join(baseDir, filepath.Base(header.Filename))
	outFile, err := os.Create(outPath)
	if err != nil {
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		http.Error(w, "failed to write file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// deleteGroupingRuleHandler deletes a specific grouping rule.
func deleteGroupingRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/grouping-rules/delete/")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM grouping_rules WHERE id = ?", id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// attachmentHandler serves attachment files from disk.
func attachmentHandler(w http.ResponseWriter, r *http.Request) {
	// URL: /api/attachments/{event_id}/{filename}
	path := strings.TrimPrefix(r.URL.Path, "/api/attachments/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	eventID := parts[0]
	filename := filepath.Base(parts[1])

	filePath := filepath.Join("data", "attachments", eventID, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	// Query content type from DB
	var contentType string
	err := db.QueryRow("SELECT content_type FROM attachments WHERE event_id = ? AND filename = ?", eventID, filename).Scan(&contentType)
	if err != nil {
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	http.ServeFile(w, r, filePath)
}

// respondWithID sends a 200 JSON response with the given event ID.
func respondWithID(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

// healthHandler serves the /health endpoint for uptime monitoring.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	if err != nil {
		log.Printf("health check error: %v", err)
	}

	uptime := time.Since(startTime).Round(time.Second).String()

	resp := map[string]interface{}{
		"status":       "ok",
		"version":      currentVersion,
		"uptime":       uptime,
		"total_events": count,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveHandler sets an event's status to 'resolved'
func resolveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/events/resolve/")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	
	snoozeStr := r.URL.Query().Get("snooze")
	if snoozeStr != "" {
		dur, err := time.ParseDuration(snoozeStr)
		if err != nil {
			http.Error(w, "Invalid duration", http.StatusBadRequest)
			return
		}
		until := time.Now().UTC().Add(dur).Format(time.RFC3339)
		_, err = db.Exec("UPDATE events SET status = 'snoozed', snoozed_until = ? WHERE id = ?", until, id)
		if err != nil {
			log.Printf("snooze error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		
		if strings.Contains(r.Header.Get("HX-Current-Url"), "/events/") {
			w.Header().Set("Content-Type", "text/html")
			badge := `<div class="px-3 py-1.5 bg-amber-500/10 text-amber-400 text-xs font-semibold rounded-lg border border-amber-500/20 shadow-sm flex items-center gap-1.5"><svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0M3.124 7.5A8.969 8.969 0 015.292 3m13.416 0a8.969 8.969 0 012.168 4.5" /></svg> Snoozed (` + snoozeStr + `)</div>`
			w.Write([]byte(badge))
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	nextStr := r.URL.Query().Get("next")
	resolvedIn := ""
	if nextStr == "true" {
		resolvedIn = "next"
	}
	
	_, err := db.Exec("UPDATE events SET status = 'resolved', resolved_in_release = ? WHERE id = ?", resolvedIn, id)
	if err != nil {
		log.Printf("resolve error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	
	if strings.Contains(r.Header.Get("HX-Current-Url"), "/events/") {
		w.Header().Set("Content-Type", "text/html")
		var badge string
		if resolvedIn == "next" {
			badge = `<div class="px-3 py-1.5 bg-brand-500/10 text-brand-400 text-xs font-semibold rounded-lg border border-brand-500/20 shadow-sm flex items-center gap-1.5"><svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg> Resolved in Next Release</div>`
		} else {
			badge = `<div class="px-3 py-1.5 bg-emerald-500/10 text-emerald-400 text-xs font-semibold rounded-lg border border-emerald-500/20 shadow-sm flex items-center gap-1.5"><svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg> Resolved</div>`
		}
		w.Write([]byte(badge))
		return
	}

	w.WriteHeader(http.StatusOK)
}

// createProjectHandler creates a new project and redirects to dashboard.
func createProjectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	var maxID int
	err := db.QueryRow("SELECT COALESCE(MAX(CAST(id AS INTEGER)), 0) FROM projects").Scan(&maxID)
	if err != nil {
		log.Printf("project max id query error: %v", err)
		maxID = 1
	}
	newID := fmt.Sprintf("%d", maxID+1)

	_, err = db.Exec("INSERT INTO projects (id, name, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)", newID, name)
	if err != nil {
		log.Printf("create project error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// deleteProjectHandler deletes a project and all its associated events.
func deleteProjectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/projects/delete/")
	if id == "" || id == "1" { // Prevent deleting default project
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Delete events associated with the project
	_, err := db.Exec("DELETE FROM events WHERE project_id = ?", id)
	if err != nil {
		log.Printf("delete project events error: %v", err)
	}

	// Delete the project itself
	_, err = db.Exec("DELETE FROM projects WHERE id = ?", id)
	if err != nil {
		log.Printf("delete project error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// updateProjectSettingsHandler updates the webhook configurations for a specific project.
func updateProjectSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/projects/update/")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tgToken := r.FormValue("tg_token")
	tgChatID := r.FormValue("tg_chat_id")
	discordWebhook := r.FormValue("discord_webhook")

	_, err := db.Exec(`
		UPDATE projects 
		SET tg_token = ?, tg_chat_id = ?, discord_webhook = ?
		WHERE id = ?`,
		tgToken, tgChatID, discordWebhook, id,
	)
	if err != nil {
		log.Printf("update project settings error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------- Router ----------

func newRouter() http.Handler {
	mux := http.NewServeMux()

	// UI routes — protected by Basic Auth.
	protected := http.NewServeMux()
	protected.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		indexHandler(w, r)
	})
	protected.HandleFunc("/events/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			eventDetailHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	protected.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			eventsHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	protected.HandleFunc("/api/events/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			exportCSVHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	protected.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			statsHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Mount protected UI behind auth middleware.
	mux.Handle("/", basicAuthMiddleware(protected))
	mux.Handle("/events/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))
	mux.Handle("/api/events", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))
	mux.Handle("/api/events/export", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))
	mux.Handle("/api/events/resolve/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolveHandler(w, r)
	})))
	mux.Handle("/api/events/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/comments") && r.Method == http.MethodPost {
			postCommentHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})))

	mux.Handle("/api/projects", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		createProjectHandler(w, r)
	})))

	mux.Handle("/api/projects/delete/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteProjectHandler(w, r)
	})))

	mux.Handle("/api/projects/update/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		updateProjectSettingsHandler(w, r)
	})))

	mux.Handle("/api/topology", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		topologyHandler(w, r)
	})))

	mux.Handle("/api/topology/view", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		topologyViewHandler(w, r)
	})))

	mux.Handle("/api/performance", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		performanceHandler(w, r)
	})))

	mux.Handle("/api/performance/analytics", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		latencyAnalyticsHandler(w, r)
	})))

	mux.Handle("/api/performance/trace/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceHandler(w, r)
	})))

	mux.Handle("/api/stats", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))

	mux.Handle("/api/system-metrics", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		systemMetricsHandler(w, r)
	})))

	mux.Handle("/api/alerting-rules", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertingRulesHandler(w, r)
	})))

	mux.Handle("/api/alerting-rules/delete/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteAlertingRuleHandler(w, r)
	})))

	mux.Handle("/api/sourcemaps/upload", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceMapUploadHandler(w, r)
	})))

	mux.Handle("/api/grouping-rules", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		groupingRulesHandler(w, r)
	})))

	mux.Handle("/api/grouping-rules/delete/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteGroupingRuleHandler(w, r)
	})))

	mux.Handle("/api/attachments/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attachmentHandler(w, r)
	})))

	// Public health check endpoint
	mux.HandleFunc("/health", healthHandler)

	// Public ingestion routes — NO auth.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Exclude UI routes from this handler (handled above with auth).
		if r.URL.Path == "/api/events" || r.URL.Path == "/api/stats" {
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/store/"):
			storeHandler(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/envelope/"):
			envelopeHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	return corsMiddleware(gzipDecodeMiddleware(mux))
}

// ---------- Self-Update ----------

// githubRelease is a minimal representation of the GitHub Releases API response.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// checkUpdate checks GitHub for a newer release. If one is found it prompts
// the user to confirm, downloads the new binary, atomically replaces the
// current executable, and exits so the user can restart with the new version.
func checkUpdate() {
	fmt.Println("🔍 Checking for updates...")

	const apiURL = "https://api.github.com/repos/apvcode/pocketsentry/releases/latest"

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pocketsentry-selfupdate/"+currentVersion)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Could not reach GitHub: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to parse GitHub response: %v\n", err)
		return
	}

	latest := strings.TrimSpace(release.TagName)
	if latest == "" {
		fmt.Println("❌ Could not determine the latest version.")
		return
	}

	if latest == currentVersion {
		fmt.Printf("✅ You are already on the latest version (%s). No update needed.\n", currentVersion)
		return
	}

	fmt.Printf("🆕 New version available: %s (current: %s)\n", latest, currentVersion)

	// Determine the asset name for the current platform.
	// Convention: pocketsentry-linux-amd64, pocketsentry-windows-amd64.exe, etc.
	assetName := fmt.Sprintf("pocketsentry-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		fmt.Printf("⚠️  No pre-built binary found for %s/%s (asset: %s).\n",
			runtime.GOOS, runtime.GOARCH, assetName)
		fmt.Printf("   You can build manually: go build -o pocketsentry .\n")
		return
	}

	// Ask the user to confirm.
	fmt.Printf("   Asset : %s\n", assetName)
	fmt.Printf("   URL   : %s\n", downloadURL)
	fmt.Print("\n❓ Do you want to update? [y/N]: ")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "y" && answer != "yes" {
		fmt.Println("⏭️  Update cancelled.")
		return
	}

	// Determine path of the currently running executable.
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot determine executable path: %v\n", err)
		return
	}

	// Download to a temporary file next to the current binary.
	tmpPath := exePath + ".update_tmp"
	fmt.Printf("⬇️  Downloading %s...\n", assetName)

	dlResp, err := client.Get(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Download failed: %v\n", err)
		return
	}
	defer dlResp.Body.Close()

	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot create temp file %s: %v\n", tmpPath, err)
		return
	}

	n, err := io.Copy(tmpFile, dlResp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "❌ Write failed: %v\n", err)
		return
	}
	fmt.Printf("   Downloaded %.1f MB\n", float64(n)/1024/1024)

	// Atomically replace the running binary.
	// On Windows we cannot replace a running exe, so we rename ours first.
	if runtime.GOOS == "windows" {
		oldPath := exePath + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(exePath, oldPath); err != nil {
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "❌ Cannot move old binary: %v\n", err)
			return
		}
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "❌ Cannot replace binary: %v\n", err)
		return
	}

	fmt.Printf("✅ Updated to %s successfully!\n", latest)
	fmt.Println("   Restart PocketSentry to use the new version.")
}

// ---------- Banner ----------

const banner = `
   ___           _        _   ___            _
  | _ \ ___  __ | | __ __| |_/ __| ___ _ __ | |_ _ _ _  _
  |  _// _ \/ _|| |/ // _| __\__ \/ _ \ '_ \|  _| '_| || |
  |_|  \___/\__||_\_\\__|\__|___/\___/_||_|\__|_| \_, |
                                                   |__/
`

func printBanner(port, dbPath, user string, retDays int) {
	fmt.Print(banner)
	fmt.Println("  ──────────────────────────────────────────────────")
	fmt.Printf("  🛡️  Version     : 3.0.0\n")
	fmt.Printf("  🌐 Dashboard   : http://localhost:%s\n", port)
	fmt.Printf("  📦 Database    : %s\n", dbPath)
	fmt.Printf("  🔗 DSN         : http://public@localhost:%s/1\n", port)
	if user != "" {
		fmt.Printf("  🔒 Auth        : enabled (user: %s)\n", user)
	} else {
		fmt.Printf("  🔓 Auth        : disabled\n")
	}
	if retDays > 0 {
		fmt.Printf("  🗑️  Retention   : %d days\n", retDays)
	} else {
		fmt.Printf("  ♾️  Retention   : unlimited\n")
	}

	var notifs []string
	if discordWebhookURL != "" {
		notifs = append(notifs, "Discord")
	}
	if tgToken != "" && tgChatID != "" {
		notifs = append(notifs, "Telegram")
	}
	if len(notifs) > 0 {
		fmt.Printf("  🔔 Webhooks    : %s\n", strings.Join(notifs, ", "))
	} else {
		fmt.Printf("  🔕 Webhooks    : disabled\n")
	}

	fmt.Println("  ──────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Point your Sentry SDK to the DSN above.")
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()
}

// ---------- Main ----------

func main() {
	startTime = time.Now()

	// CLI flags.
	port := flag.String("port", "8080", "HTTP server port")
	dbPath := flag.String("db", "pocketsentry.db", "Path to SQLite database file")
	flagUser := flag.String("admin-user", "", "Dashboard admin username (empty = auth disabled)")
	flagPass := flag.String("admin-pass", "", "Dashboard admin password")
	retentionDays := flag.Int("retention-days", 30, "Auto-delete events older than N days (0 = disabled)")
	checkUpd := flag.Bool("checkupd", false, "Check for a newer release on GitHub and offer to update")
	flagDiscord := flag.String("discord-webhook-url", "", "Discord Webhook URL for error notifications")
	flagTgToken := flag.String("tg-token", "", "Telegram Bot Token for error notifications")
	flagTgChatID := flag.String("tg-chat-id", "", "Telegram Chat ID for error notifications")
	flagEnableEBPF := flag.Bool("enable-ebpf", false, "Enable the eBPF agent for zero-config HTTP 500 tracing (requires root)")
	flag.Parse()

	// Handle --checkupd before anything else: no server, no DB needed.
	if *checkUpd {
		checkUpdate()
		return
	}

	// Override from env vars (flags take priority if explicitly set).
	if envPort := os.Getenv("PORT"); envPort != "" && !isFlagPassed("port") {
		*port = envPort
	}
	if envDB := os.Getenv("DB_PATH"); envDB != "" && !isFlagPassed("db") {
		*dbPath = envDB
	}

	// Set global auth and webhook credentials.
	adminUser = *flagUser
	adminPass = *flagPass
	discordWebhookURL = *flagDiscord
	tgToken = *flagTgToken
	tgChatID = *flagTgChatID
	globalRetentionDays = *retentionDays

	// Initialize templates (from embedded FS).
	if err := initTemplates(); err != nil {
		log.Fatalf("Template init failed: %v", err)
	}

	// Initialize database.
	dbFilePath = *dbPath
	if err := initDB(*dbPath); err != nil {
		log.Fatalf("Database init failed: %v", err)
	}

	// Print startup banner.
	printBanner(*port, *dbPath, adminUser, *retentionDays)

	// Start eBPF Agent if enabled
	if *flagEnableEBPF {
		err := ebpf.StartAgent(ebpf.Callbacks{
			OnHTTP500: func(pid uint32, snippet string) {
				msg := fmt.Sprintf("Zero-Config Intercept: HTTP 500 error from PID %d\nSnippet: %s", pid, snippet)
				ev := SentryEvent{
					EventID:   generateUUID(),
					Level:     "error",
					Platform:  "ebpf",
					Message:   msg,
					Logger:    "pocketsentry.ebpf",
				}
				raw := fmt.Sprintf(`{"message":"%s","level":"error","platform":"ebpf","tags":{"pid":"%d","source":"kernel_intercept"}}`, msg, pid)
				_ = saveEvent(ev, "1", raw)
			},
			OnTCPConn: func(pid uint32, destIP string, destPort uint16) {
				// Ignore loopback or zero IP to keep map clean
				if destIP == "127.0.0.1" || destIP == "0.0.0.0" {
					return
				}
				sourceNode := resolveProcessName(pid)
				targetNode := destIP

				// Upsert edge
				_, err := db.Exec(`
					INSERT INTO network_edges (source_node, target_node, target_port, hit_count, last_seen)
					VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
					ON CONFLICT(source_node, target_node, target_port) 
					DO UPDATE SET hit_count = hit_count + 1, last_seen = CURRENT_TIMESTAMP
				`, sourceNode, targetNode, destPort)
				if err != nil {
					log.Printf("ebpf DB insert error: %v", err)
				}
			},
		})
		if err != nil {
			log.Printf("⚠️  Failed to start eBPF Agent: %v (Are you running as root?)", err)
		} else {
			log.Printf("🔥 eBPF Agent running! Monitoring global HTTP traffic for 500s...")
		}
	}

	// Create HTTP server.
	addr := ":" + *port
	srv := &http.Server{
		Addr:    addr,
		Handler: newRouter(),
	}

	// Graceful shutdown: listen for SIGINT / SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start retention cleanup goroutine.
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	if *retentionDays > 0 {
		go runRetentionCleanup(cleanupCtx, *retentionDays)
	}

	// Start Telegram bot pollers.
	go ensureTelegramPollers()

	// Start server in a goroutine.
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Block until we receive a shutdown signal.
	sig := <-quit
	log.Printf("Received %v, shutting down gracefully...", sig)

	// Stop the retention worker.
	cleanupCancel()

	// Give in-flight requests up to 10 seconds to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	if err := db.Close(); err != nil {
		log.Printf("Database close error: %v", err)
	}

	log.Println("PocketSentry stopped.")
}

// runRetentionCleanup periodically deletes events older than retentionDays.
func runRetentionCleanup(ctx context.Context, days int) {
	// Run once at startup, then every hour.
	cleanup := func() {
		res, err := db.Exec(
			`DELETE FROM events WHERE
			 CASE WHEN last_seen = '' THEN timestamp ELSE last_seen END
			 < datetime('now', '-' || ? || ' days')`, days,
		)
		if err != nil {
			log.Printf("[retention] cleanup error: %v", err)
			return
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[retention] deleted %d events older than %d days", n, days)
		}
	}

	cleanup()
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

// isFlagPassed checks if a flag was explicitly provided on the command line.
func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
