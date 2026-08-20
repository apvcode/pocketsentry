package main

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
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
	"github.com/pocketsentry/pocketsentry/internal/container"
	"github.com/pocketsentry/pocketsentry/internal/helpers"
	"github.com/pocketsentry/pocketsentry/internal/middleware"
	"github.com/pocketsentry/pocketsentry/internal/models"
	"github.com/pocketsentry/pocketsentry/internal/notify"
	"github.com/pocketsentry/pocketsentry/internal/sentry"
	"github.com/pocketsentry/pocketsentry/internal/sourcemap"
	"github.com/pocketsentry/pocketsentry/internal/update"
	_ "modernc.org/sqlite"
)

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

// initTemplates parses the embedded templates once at startup.
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

		CREATE TABLE IF NOT EXISTS app_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id TEXT NOT NULL DEFAULT '1',
			source TEXT NOT NULL DEFAULT '',
			level TEXT NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			metadata TEXT NOT NULL DEFAULT '{}',
			timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_app_logs_project ON app_logs(project_id);
		CREATE INDEX IF NOT EXISTS idx_app_logs_timestamp ON app_logs(timestamp);
		CREATE INDEX IF NOT EXISTS idx_app_logs_level ON app_logs(level);

		CREATE TABLE IF NOT EXISTS log_alerting_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id TEXT NOT NULL DEFAULT '',
			level TEXT NOT NULL DEFAULT '',
			pattern TEXT NOT NULL,
			target_discord TEXT NOT NULL DEFAULT '',
			target_telegram_token TEXT NOT NULL DEFAULT '',
			target_telegram_chat_id TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT UNIQUE NOT NULL,
			project_id TEXT NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'viewer',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	ingestCount         int64
	dbFilePath          string
	startTime           time.Time
	globalRetentionDays int
)

func incrIngestCount() {
	atomic.AddInt64(&ingestCount, 1)
}

// ---------- Smart Grouping ----------

// applyGroupingRules normalizes the event message by applying all enabled
// grouping rules for the given project.
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

	safeName := filepath.Base(filename)
	if safeName == "" || safeName == "." || safeName == ".." {
		safeName = "attachment"
	}

	filePath := filepath.Join(dir, safeName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write attachment: %w", err)
	}

	id := helpers.GenerateUUID()
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

// queryAttachments returns all attachments for a given event.
func queryAttachments(eventID string) []models.Attachment {
	rows, err := db.Query(
		`SELECT id, filename, content_type, size_bytes, created_at
		 FROM attachments WHERE event_id = ? ORDER BY created_at ASC`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []models.Attachment
	for rows.Next() {
		var a models.Attachment
		if err := rows.Scan(&a.ID, &a.Filename, &a.ContentType, &a.SizeBytes, &a.CreatedAt); err != nil {
			continue
		}
		a.EventID = eventID
		a.IsImage = strings.HasPrefix(a.ContentType, "image/")
		a.CreatedAt = helpers.FormatTimestamp(a.CreatedAt)
		result = append(result, a)
	}
	return result
}

// ---------- System Metrics ----------

func querySystemMetrics() models.SystemMetrics {
	m := models.SystemMetrics{
		Version:       update.CurrentVersion,
		Uptime:        time.Since(startTime).Round(time.Second).String(),
		UptimeSeconds: time.Since(startTime).Seconds(),
		RetentionDays: globalRetentionDays,
		GoVersion:     runtime.Version(),
		GoRoutines:    runtime.NumGoroutine(),
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.MemAllocMB = math.Round(float64(memStats.Alloc)/1024/1024*100) / 100

	if dbFilePath != "" {
		if info, err := os.Stat(dbFilePath); err == nil {
			m.DBSizeBytes = info.Size()
			m.DBSizeHuman = helpers.HumanBytes(info.Size())
		}
	}

	_ = db.QueryRow("SELECT COUNT(*) FROM events").Scan(&m.TotalEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'unresolved'").Scan(&m.UnresolvedEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'resolved'").Scan(&m.ResolvedEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'snoozed'").Scan(&m.SnoozedEvents)
	_ = db.QueryRow("SELECT COUNT(*) FROM projects").Scan(&m.TotalProjects)
	_ = db.QueryRow("SELECT COUNT(*) FROM transactions").Scan(&m.TotalTransactions)
	_ = db.QueryRow("SELECT COUNT(*) FROM attachments").Scan(&m.TotalAttachments)
	_ = db.QueryRow("SELECT COUNT(*) FROM app_logs").Scan(&m.TotalLogs)
	_ = db.QueryRow("SELECT COUNT(*) FROM grouping_rules WHERE enabled = 1").Scan(&m.GroupingRules)

	total := atomic.LoadInt64(&ingestCount)
	upMin := time.Since(startTime).Minutes()
	if upMin > 0 {
		m.EventsPerMinute = math.Round(float64(total)/upMin*100) / 100
	}

	return m
}

// saveEvent inserts a new event or increments the counter of an existing duplicate.
func saveEvent(ev models.SentryEvent, projectID, rawPayload string) error {
	if ev.EventID == "" {
		ev.EventID = helpers.GenerateUUID()
	}
	if ev.Level == "" {
		ev.Level = "error"
	}

	incrIngestCount()
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
		projectID, ev.Level, helpers.Truncate(ev.Message, 80), newCount, newStatus)

	shouldNotify := isNew || (oldStatus == "resolved" && newStatus == "unresolved") || (oldStatus == "snoozed" && newStatus == "unresolved")
	notify.EvaluateAndTriggerWebhooks(ev, projectID, shouldNotify)

	return nil
}

// saveTransaction inserts a transaction and its spans into the database.
func saveTransaction(tx models.SentryTransaction, projectID, rawPayload string) error {
	if tx.EventID == "" {
		tx.EventID = helpers.GenerateUUID()
	}
	if tx.Transaction == "" {
		tx.Transaction = "unknown_transaction"
	}

	startTs := helpers.ParseSentryTimestamp(tx.StartTimestamp)
	endTs := helpers.ParseSentryTimestamp(tx.Timestamp)
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
		spanStart := helpers.ParseSentryTimestamp(span.StartTimestamp)
		spanEnd := helpers.ParseSentryTimestamp(span.Timestamp)
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

func queryTransactionGroups() ([]models.TransactionGroupRow, error) {
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

	var groups []models.TransactionGroupRow
	for rows.Next() {
		var g models.TransactionGroupRow
		if err := rows.Scan(&g.ExemplarID, &g.ProjectID, &g.Name, &g.Count, &g.AvgDurationMs, &g.MaxDurationMs); err == nil {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func querySpans(transactionID string) ([]models.SpanRow, error) {
	q := `SELECT id, op, description, start_timestamp, duration_ms FROM spans WHERE transaction_id = ? ORDER BY start_timestamp ASC`
	rows, err := db.Query(q, transactionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var spans []models.SpanRow
	for rows.Next() {
		var s models.SpanRow
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
func queryEvents(limit int, levelFilter string, searchFilter string, projectFilter string, envFilter string) ([]models.EventRow, error) {
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

	var result []models.EventRow
	for rows.Next() {
		var ev models.EventRow
		var release sql.NullString
		if err := rows.Scan(&ev.ID, &ev.ProjectID, &ev.LastSeen, &ev.Level, &ev.Platform, &ev.Message, &ev.Count, &ev.Status, &release); err != nil {
			log.Printf("scan row: %v", err)
			continue
		}
		if release.Valid {
			ev.Release = release.String
		}
		ev.LastSeen = helpers.FormatTimestamp(ev.LastSeen)
		result = append(result, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return result, nil
}

// queryStats returns the total count of events per day for the last 7 days.
func queryStats() ([]models.StatPoint, error) {
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

	var result []models.StatPoint
	for rows.Next() {
		var sp models.StatPoint
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

// queryEventByID fetches a single event from the database.
func queryEventByID(id string) (*models.EventDetail, error) {
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
	var ev models.EventDetail
	var rawPayload string
	err := db.QueryRow(q, id).Scan(
		&ev.ID, &ev.ProjectID, &ev.Timestamp, &ev.LastSeen,
		&ev.Level, &ev.Platform, &ev.Message, &ev.Count,
		&ev.Status, &ev.ResolvedInRelease, &ev.SnoozedUntil, &rawPayload,
	)
	if err != nil {
		return nil, err
	}
	ev.Timestamp = helpers.FormatTimestamp(ev.Timestamp)
	ev.LastSeen = helpers.FormatTimestamp(ev.LastSeen)

	var buf bytes.Buffer
	if json.Indent(&buf, []byte(rawPayload), "", "  ") == nil {
		ev.RawJSON = buf.String()
	} else {
		ev.RawJSON = rawPayload
	}

	var detail models.RawPayloadDetail
	if json.Unmarshal([]byte(rawPayload), &detail) == nil {
		ev.OS = extractContextField(detail.Contexts, "os", "name", "version")
		ev.Browser = extractContextField(detail.Contexts, "browser", "name", "version")
		ev.Runtime = extractContextField(detail.Contexts, "runtime", "name", "version")
		ev.ServerName = detail.ServerName
		ev.Environment = detail.Environment
		ev.Release = detail.Release
		ev.Tags = detail.Tags
		if len(ev.Tags) > 0 {
			ev.HasTags = true
		}

		if replayId, ok := ev.Tags["replayId"]; ok && replayId != "" {
			ev.ReplayID = replayId
		} else {
			var replayCtx struct {
				ReplayID string `json:"replay_id"`
			}
			if b, ok := detail.Contexts["replay"]; ok {
				if err := json.Unmarshal(b, &replayCtx); err == nil {
					ev.ReplayID = replayCtx.ReplayID
				}
			}
		}
		ev.HasReplay = ev.ReplayID != ""

		if detail.User != nil {
			ev.IP = detail.User.IP
		}
		if detail.Request != nil {
			ev.URL = detail.Request.URL
		}
		if detail.SDK != nil {
			ev.SDKName = detail.SDK.Name + " " + detail.SDK.Version
		}

		// Extract Breadcrumbs
		if len(detail.Breadcrumbs) > 0 {
			var bcArray []struct {
				Type      string                 `json:"type"`
				Category  string                 `json:"category"`
				Message   string                 `json:"message"`
				Level     string                 `json:"level"`
				Timestamp interface{}            `json:"timestamp"`
				Data      map[string]interface{} `json:"data"`
			}

			if err := json.Unmarshal(detail.Breadcrumbs, &bcArray); err != nil {
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
				if json.Unmarshal(detail.Breadcrumbs, &bcObj) == nil {
					bcArray = bcObj.Values
				}
			}

			if len(bcArray) > 0 {
				ev.HasBreadcrumbs = true
				for _, bc := range bcArray {
					ts := helpers.ParseSentryTimestamp(bc.Timestamp).Format("15:04:05")
					if bc.Level == "" {
						bc.Level = "info"
					}
					ev.Breadcrumbs = append(ev.Breadcrumbs, models.Breadcrumb{
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

		// Extract exception type/value and stack frames.
		if detail.Exception != nil && len(detail.Exception.Values) > 0 {
			exc := detail.Exception.Values[0]
			ev.ExcType = exc.Type
			ev.ExcValue = exc.Value
			if exc.Stacktrace != nil && len(exc.Stacktrace.Frames) > 0 {
				frames := exc.Stacktrace.Frames
				for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
					frames[i], frames[j] = frames[j], frames[i]
				}

				ev.Frames = sourcemap.ApplySourceMaps(frames, ev.ProjectID, ev.Release, dbFilePath)
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
			var c models.EventComment
			var ts string
			if err := cRows.Scan(&c.ID, &c.Comment, &ts, &c.Author); err == nil {
				c.EventID = id
				c.Timestamp = helpers.FormatTimestamp(ts)
				ev.Comments = append(ev.Comments, c)
			}
		}
	}

	// Fetch attachments
	ev.Attachments = queryAttachments(id)
	ev.HasAttachments = len(ev.Attachments) > 0

	return &ev, nil
}

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

// ---------- Handlers ----------

// indexHandler serves the main dashboard page.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM events WHERE status = 'unresolved'").Scan(&count)

	var hooks []string
	if notify.TgToken != "" {
		hooks = append(hooks, "Telegram")
	}
	if notify.DiscordWebhookURL != "" {
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

	var projects []models.Project
	rows, err := db.Query("SELECT id, name, COALESCE(tg_token, ''), COALESCE(tg_chat_id, ''), COALESCE(discord_webhook, '') FROM projects ORDER BY id ASC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p models.Project
			if err := rows.Scan(&p.ID, &p.Name, &p.TGToken, &p.TGChatID, &p.DiscordWebhook); err == nil {
				projects = append(projects, p)
			}
		}
	}

	envs, _ := queryEnvironments()

	data := models.IndexData{
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
		events = []models.EventRow{}
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

	ev, err := sentry.ParseSentryEvent(body)
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

	eventID, itemType, rawJSON, err := sentry.ParseEnvelope(body)
	if err != nil {
		log.Printf("[envelope] parse error: %v", err)
		respondOK(w)
		return
	}

	if itemType == "transaction" {
		var tx models.SentryTransaction
		if err := json.Unmarshal(rawJSON, &tx); err == nil {
			if tx.EventID == "" {
				tx.EventID = eventID
			}
			if err := saveTransaction(tx, projectID, string(rawJSON)); err != nil {
				log.Printf("[envelope] save transaction error: %v", err)
			}
		}
	} else {
		ev, err := sentry.ParseSentryEvent(rawJSON)
		if err == nil {
			if ev.EventID == "" {
				ev.EventID = eventID
			}
			if err := saveEvent(ev, projectID, string(rawJSON)); err != nil {
				log.Printf("[envelope] save event error: %v", err)
			}
		}
	}

	extractAndSaveAttachments(body, eventID)
	extractAndSaveReplays(body, eventID)

	respondWithID(w, eventID)
}

func extractAndSaveAttachments(envelopeData []byte, eventID string) {
	if eventID == "" {
		return
	}
	lines := sentry.SplitEnvelopeLines(envelopeData)
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

func extractAndSaveReplays(envelopeData []byte, eventID string) {
	lines := sentry.SplitEnvelopeLines(envelopeData)
	for i := 1; i+1 < len(lines); i += 2 {
		var itemHeader struct {
			Type     string `json:"type"`
			ReplayID string `json:"replay_id"`
		}
		if err := json.Unmarshal(lines[i], &itemHeader); err != nil {
			continue
		}
		t := strings.ToLower(itemHeader.Type)
		if t == "replay_event" || t == "replay_recording" {
			replayID := itemHeader.ReplayID
			if replayID == "" {
				replayID = eventID
			}
			if replayID == "" {
				continue
			}
			os.MkdirAll(filepath.Join("data", "replays"), 0755)
			filePath := filepath.Join("data", "replays", replayID+".jsonl")
			f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.Write(lines[i+1])
				f.Write([]byte("\n"))
				f.Close()
				log.Printf("[replay] saved chunk for replay %s", replayID)
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

	tmpl, err := template.ParseFS(templateFS, "templates/performance.html")
	if err != nil {
		tmpl, err = template.ParseFiles(filepath.Join("templates", "performance.html"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
			if count == 0 {
				return 0
			}
			idx := int(math.Ceil(float64(count)*p)) - 1
			if idx < 0 {
				idx = 0
			}
			if idx >= count {
				idx = count - 1
			}
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
		if offsetMs < 0 {
			offsetMs = 0
		}

		leftPct := (offsetMs / txDur) * 100.0
		if leftPct > 100 {
			leftPct = 100
		}

		widthPct := (s.DurationMs / txDur) * 100.0
		if leftPct+widthPct > 100 {
			widthPct = 100 - leftPct
		}
		if widthPct < 0.5 {
			widthPct = 0.5
		}

		traceSpans = append(traceSpans, TraceSpan{
			Op:          s.Op,
			Description: s.Description,
			DurationMs:  s.DurationMs,
			LeftPct:     leftPct,
			WidthPct:    widthPct,
		})
	}

	tmpl, err := template.ParseFS(templateFS, "templates/trace.html")
	if err != nil {
		tmpl, err = template.ParseFiles(filepath.Join("templates", "trace.html"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	_ = tmpl.Execute(w, map[string]interface{}{
		"ID":         id,
		"Name":       txName,
		"DurationMs": txDur,
		"Spans":      traceSpans,
	})
}

func extractProjectID(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	path = strings.TrimPrefix(path, "/api/")
	return path
}

func respondOK(w http.ResponseWriter) {
	respondWithID(w, helpers.GenerateUUID())
}

// eventDetailHandler serves the detail page for a single event.
func eventDetailHandler(w http.ResponseWriter, r *http.Request) {
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

	author := "Admin"
	ts := time.Now().UTC().Format(time.RFC3339)

	_, err := db.Exec("INSERT INTO event_comments (event_id, comment, timestamp, author) VALUES (?, ?, ?, ?)", id, comment, ts, author)
	if err != nil {
		log.Printf("insert comment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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
	tmpl, err := template.ParseFS(templateFS, "templates/topology.html")
	if err != nil {
		tmpl, err = template.ParseFiles(filepath.Join("templates", "topology.html"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	_ = tmpl.Execute(w, nil)
}

// ---------- Log Streaming & Alerting ----------

type logSubscriber struct {
	ch        chan models.LogRow
	projectID string
	level     string
}

var (
	logSubscribers   = make(map[*logSubscriber]struct{})
	logSubscribersMu sync.RWMutex
)

func broadcastLog(logRow models.LogRow) {
	logSubscribersMu.RLock()
	defer logSubscribersMu.RUnlock()

	for sub := range logSubscribers {
		if sub.projectID != "" && sub.projectID != "All" && sub.projectID != logRow.ProjectID {
			continue
		}
		if sub.level != "" && sub.level != "All" && !strings.EqualFold(sub.level, logRow.Level) {
			continue
		}
		select {
		case sub.ch <- logRow:
		default:
		}
	}
}

func evaluateAndTriggerLogAlerts(entry models.LogEntry) {
	rows, err := db.Query(
		`SELECT level, pattern, target_discord, target_telegram_token, target_telegram_chat_id
		 FROM log_alerting_rules
		 WHERE enabled = 1 AND (project_id = '' OR project_id = ?)`, entry.ProjectID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var reqLevel, pattern, tDiscord, tTGToken, tTGChatID string
		if err := rows.Scan(&reqLevel, &pattern, &tDiscord, &tTGToken, &tTGChatID); err != nil {
			continue
		}
		if reqLevel != "" && !strings.EqualFold(reqLevel, entry.Level) {
			continue
		}
		if pattern != "" {
			re, err := regexp.Compile(pattern)
			if err != nil || !re.MatchString(entry.Message) {
				continue
			}
		}

		msg := fmt.Sprintf("🪵 **PocketSentry Log Alert**\n\n**Project:** %s\n**Level:** %s\n**Source:** %s\n**Message:** %s\n**Time:** %s",
			entry.ProjectID, entry.Level, entry.Source, helpers.Truncate(entry.Message, 200), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

		if tDiscord != "" {
			go notify.SendDiscordWebhook(tDiscord, msg)
		}
		if tTGToken != "" && tTGChatID != "" {
			go notify.SendTelegramWebhook(tTGToken, tTGChatID, msg, "")
		}
	}
}

// logsIngestHandler handles POST /api/logs for ingesting log entries.
func logsIngestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body or body too large", http.StatusBadRequest)
		return
	}

	var entries []models.LogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		var single models.LogEntry
		if err := json.Unmarshal(body, &single); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		entries = []models.LogEntry{single}
	}

	count := 0
	for _, entry := range entries {
		if entry.Message == "" || len(entry.Message) > 8192 {
			continue
		}
		if len(entry.Source) > 256 || len(entry.Level) > 64 || len(entry.ProjectID) > 64 {
			continue
		}

		if entry.ProjectID == "" {
			entry.ProjectID = "1"
		}
		if entry.Level == "" {
			entry.Level = "info"
		}
		if entry.Source == "" {
			entry.Source = "app"
		}

		metaJSON := "{}"
		if entry.Metadata != nil {
			if len(entry.Metadata) > 100 {
				continue
			}
			tooLarge := false
			for k, v := range entry.Metadata {
				if len(k) > 128 || len(v) > 1024 {
					tooLarge = true
					break
				}
			}
			if tooLarge {
				continue
			}

			if b, err := json.Marshal(entry.Metadata); err == nil {
				metaJSON = string(b)
			}
		}

		ts := time.Now().UTC().Format(time.RFC3339)
		if entry.Timestamp != "" {
			if len(entry.Timestamp) < 32 {
				ts = entry.Timestamp
			}
		}

		res, err := db.Exec(
			`INSERT INTO app_logs (project_id, source, level, message, metadata, timestamp)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			entry.ProjectID, entry.Source, entry.Level, entry.Message, metaJSON, ts,
		)
		if err != nil {
			log.Printf("[logs] insert error: %v", err)
			continue
		}

		var lastID int64
		if res != nil {
			lastID, _ = res.LastInsertId()
		}

		// Broadcast to real-time SSE stream
		broadcastLog(models.LogRow{
			ID:        int(lastID),
			ProjectID: entry.ProjectID,
			Source:    entry.Source,
			Level:     entry.Level,
			Message:   entry.Message,
			Metadata:  metaJSON,
			Timestamp: helpers.FormatTimestamp(ts),
		})

		// Evaluate log alert rules
		evaluateAndTriggerLogAlerts(entry)

		count++
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"ingested": count,
	})
}

// logsStreamHandler handles GET /api/logs/stream for real-time SSE log tailing.
func logsStreamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	projectID := r.URL.Query().Get("project")
	level := r.URL.Query().Get("level")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	sub := &logSubscriber{
		ch:        make(chan models.LogRow, 100),
		projectID: projectID,
		level:     level,
	}

	logSubscribersMu.Lock()
	logSubscribers[sub] = struct{}{}
	logSubscribersMu.Unlock()

	defer func() {
		logSubscribersMu.Lock()
		delete(logSubscribers, sub)
		logSubscribersMu.Unlock()
		close(sub.ch)
	}()

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case logRow, ok := <-sub.ch:
			if !ok {
				return
			}
			data, err := json.Marshal(logRow)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}

// logAlertingRulesHandler handles GET (list) and POST (create) for log alerting rules.
func logAlertingRulesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		projectID := r.URL.Query().Get("project_id")
		rows, err := db.Query("SELECT id, project_id, level, pattern, target_discord, target_telegram_token, target_telegram_chat_id, enabled, created_at FROM log_alerting_rules WHERE (project_id = '' OR project_id = ?) ORDER BY id ASC", projectID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var rules []models.LogAlertingRule
		for rows.Next() {
			var rule models.LogAlertingRule
			var enabled int
			if err := rows.Scan(&rule.ID, &rule.ProjectID, &rule.Level, &rule.Pattern, &rule.TargetDiscord, &rule.TargetTelegramToken, &rule.TargetTelegramChatID, &enabled, &rule.CreatedAt); err == nil {
				rule.Enabled = enabled == 1
				rule.CreatedAt = helpers.FormatTimestamp(rule.CreatedAt)
				rules = append(rules, rule)
			}
		}
		if rules == nil {
			rules = []models.LogAlertingRule{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		projectID := r.FormValue("project_id")
		level := r.FormValue("level")
		pattern := strings.TrimSpace(r.FormValue("pattern"))
		if pattern != "" {
			if _, err := regexp.Compile(pattern); err != nil {
				http.Error(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		tDiscord := r.FormValue("target_discord")
		tTGToken := r.FormValue("target_telegram_token")
		tTGChatID := r.FormValue("target_telegram_chat_id")

		if tDiscord == "" && (tTGToken == "" || tTGChatID == "") {
			http.Error(w, "at least one webhook target is required", http.StatusBadRequest)
			return
		}

		_, err := db.Exec(
			"INSERT INTO log_alerting_rules (project_id, level, pattern, target_discord, target_telegram_token, target_telegram_chat_id) VALUES (?, ?, ?, ?, ?, ?)",
			projectID, level, pattern, tDiscord, tTGToken, tTGChatID,
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

// deleteLogAlertingRuleHandler deletes a specific log alerting rule.
func deleteLogAlertingRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/log-alerting-rules/delete/")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM log_alerting_rules WHERE id = ?", id)
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

// metricsHandler exports Prometheus format metrics at /metrics.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	m := querySystemMetrics()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b bytes.Buffer

	fmt.Fprintf(&b, "# HELP pocketsentry_uptime_seconds PocketSentry uptime in seconds\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "pocketsentry_uptime_seconds %f\n\n", m.UptimeSeconds)

	fmt.Fprintf(&b, "# HELP pocketsentry_events_total Total error events ingested\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_events_total counter\n")
	fmt.Fprintf(&b, "pocketsentry_events_total %d\n\n", m.TotalEvents)

	fmt.Fprintf(&b, "# HELP pocketsentry_events_unresolved Currently unresolved error events\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_events_unresolved gauge\n")
	fmt.Fprintf(&b, "pocketsentry_events_unresolved %d\n\n", m.UnresolvedEvents)

	fmt.Fprintf(&b, "# HELP pocketsentry_events_resolved Currently resolved error events\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_events_resolved gauge\n")
	fmt.Fprintf(&b, "pocketsentry_events_resolved %d\n\n", m.ResolvedEvents)

	fmt.Fprintf(&b, "# HELP pocketsentry_logs_total Total application logs ingested\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_logs_total counter\n")
	fmt.Fprintf(&b, "pocketsentry_logs_total %d\n\n", m.TotalLogs)

	fmt.Fprintf(&b, "# HELP pocketsentry_transactions_total Total performance transactions recorded\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_transactions_total counter\n")
	fmt.Fprintf(&b, "pocketsentry_transactions_total %d\n\n", m.TotalTransactions)

	fmt.Fprintf(&b, "# HELP pocketsentry_db_size_bytes SQLite database file size in bytes\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_db_size_bytes gauge\n")
	fmt.Fprintf(&b, "pocketsentry_db_size_bytes %d\n\n", m.DBSizeBytes)

	fmt.Fprintf(&b, "# HELP pocketsentry_goroutines Number of active goroutines\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_goroutines gauge\n")
	fmt.Fprintf(&b, "pocketsentry_goroutines %d\n\n", m.GoRoutines)

	fmt.Fprintf(&b, "# HELP pocketsentry_mem_alloc_mb Memory allocated by process in MB\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_mem_alloc_mb gauge\n")
	fmt.Fprintf(&b, "pocketsentry_mem_alloc_mb %f\n\n", m.MemAllocMB)

	fmt.Fprintf(&b, "# HELP pocketsentry_events_per_minute Ingestion rate in events per minute\n")
	fmt.Fprintf(&b, "# TYPE pocketsentry_events_per_minute gauge\n")
	fmt.Fprintf(&b, "pocketsentry_events_per_minute %f\n", m.EventsPerMinute)

	w.Write(b.Bytes())
}

// otlpTracesHandler handles POST /v1/traces (OpenTelemetry Traces JSON).
func otlpTracesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var payload struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					TraceID           string `json:"traceId"`
					SpanID            string `json:"spanId"`
					ParentSpanID      string `json:"parentSpanId"`
					Name              string `json:"name"`
					StartTimeUnixNano string `json:"startTimeUnixNano"`
					EndTimeUnixNano   string `json:"endTimeUnixNano"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	ingested := 0
	for _, rs := range payload.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				tx := models.SentryTransaction{
					EventID:     span.TraceID,
					Transaction: span.Name,
				}
				if tx.EventID == "" {
					tx.EventID = helpers.GenerateUUID()
				}
				_ = saveTransaction(tx, "1", string(body))
				ingested++
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "ingested": ingested})
}

// otlpLogsHandler handles POST /v1/logs (OpenTelemetry Logs JSON).
func otlpLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var payload struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					TimeUnixNano   string          `json:"timeUnixNano"`
					SeverityText   string          `json:"severityText"`
					SeverityNumber int             `json:"severityNumber"`
					Body           json.RawMessage `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	ingested := 0
	for _, rl := range payload.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				msg := string(lr.Body)
				var bodyObj struct {
					StringValue string `json:"stringValue"`
				}
				if json.Unmarshal(lr.Body, &bodyObj) == nil && bodyObj.StringValue != "" {
					msg = bodyObj.StringValue
				}
				msg = strings.Trim(msg, `"`)

				level := strings.ToLower(lr.SeverityText)
				if level == "" {
					if lr.SeverityNumber >= 17 {
						level = "fatal"
					} else if lr.SeverityNumber >= 13 {
						level = "error"
					} else if lr.SeverityNumber >= 9 {
						level = "warning"
					} else if lr.SeverityNumber >= 5 {
						level = "info"
					} else {
						level = "debug"
					}
				}

				entry := models.LogEntry{
					ProjectID: "1",
					Source:    "otlp",
					Level:     level,
					Message:   msg,
				}

				ts := time.Now().UTC().Format(time.RFC3339)
				res, err := db.Exec(
					`INSERT INTO app_logs (project_id, source, level, message, metadata, timestamp)
					 VALUES (?, ?, ?, ?, ?, ?)`,
					entry.ProjectID, entry.Source, entry.Level, entry.Message, "{}", ts,
				)
				if err == nil {
					var lastID int64
					if res != nil {
						lastID, _ = res.LastInsertId()
					}
					broadcastLog(models.LogRow{
						ID:        int(lastID),
						ProjectID: entry.ProjectID,
						Source:    entry.Source,
						Level:     entry.Level,
						Message:   entry.Message,
						Metadata:  "{}",
						Timestamp: helpers.FormatTimestamp(ts),
					})
					evaluateAndTriggerLogAlerts(entry)
					ingested++
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "ingested": ingested})
}

// apiKeysHandler handles GET and POST for API Keys.
func apiKeysHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		projectID := r.URL.Query().Get("project_id")
		rows, err := db.Query("SELECT id, key, project_id, name, role, created_at FROM api_keys WHERE (project_id = '' OR project_id = ?) ORDER BY id ASC", projectID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var keys []models.APIKey
		for rows.Next() {
			var k models.APIKey
			if err := rows.Scan(&k.ID, &k.Key, &k.ProjectID, &k.Name, &k.Role, &k.CreatedAt); err == nil {
				k.CreatedAt = helpers.FormatTimestamp(k.CreatedAt)
				keys = append(keys, k)
			}
		}
		if keys == nil {
			keys = []models.APIKey{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		projectID := r.FormValue("project_id")
		if projectID == "" {
			projectID = "1"
		}
		name := r.FormValue("name")
		if name == "" {
			name = "API Key"
		}
		role := r.FormValue("role")
		if role != "admin" {
			role = "viewer"
		}

		key := "pk_" + helpers.GenerateUUID()
		_, err := db.Exec("INSERT INTO api_keys (key, project_id, name, role) VALUES (?, ?, ?, ?)", key, projectID, name, role)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Refresh", "true")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "key": key})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// deleteAPIKeyHandler deletes an API key.
func deleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/api-keys/delete/")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM api_keys WHERE id = ?", id)
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

// logsQueryHandler handles GET /api/logs for querying log entries.
func logsQueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	search := r.URL.Query().Get("search")
	level := r.URL.Query().Get("level")
	project := r.URL.Query().Get("project")
	source := r.URL.Query().Get("source")
	limitStr := r.URL.Query().Get("limit")
	limit := 200
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}

	q := `SELECT id, project_id, source, level, message, metadata, timestamp
	      FROM app_logs WHERE 1=1`
	var args []interface{}

	if level != "" && level != "All" {
		q += " AND level = ?"
		args = append(args, level)
	}
	if project != "" && project != "All" {
		q += " AND project_id = ?"
		args = append(args, project)
	}
	if source != "" {
		q += " AND source = ?"
		args = append(args, source)
	}
	if search != "" {
		q += " AND message LIKE '%' || ? || '%'"
		args = append(args, search)
	}

	q += " ORDER BY timestamp DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []models.LogRow
	for rows.Next() {
		var l models.LogRow
		if err := rows.Scan(&l.ID, &l.ProjectID, &l.Source, &l.Level, &l.Message, &l.Metadata, &l.Timestamp); err == nil {
			l.Timestamp = helpers.FormatTimestamp(l.Timestamp)
			logs = append(logs, l)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if logs == nil {
		logs = []models.LogRow{}
	}
	_ = json.NewEncoder(w).Encode(logs)
}

// logsViewHandler renders the logs tab content.
func logsViewHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.ParseFS(templateFS, "templates/logs.html")
	if err != nil {
		tmpl, err = template.ParseFiles(filepath.Join("templates", "logs.html"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	_ = tmpl.Execute(w, nil)
}

// sourceMapUploadHandler handles POST requests to upload .map files.
func sourceMapUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

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
	_, _ = w.Write([]byte(`{"status":"ok"}`))
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

	var contentType string
	err := db.QueryRow("SELECT content_type FROM attachments WHERE event_id = ? AND filename = ?", eventID, filename).Scan(&contentType)
	if err != nil {
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	http.ServeFile(w, r, filePath)
}

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
		"version":      update.CurrentVersion,
		"uptime":       uptime,
		"total_events": count,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveHandler sets an event's status to 'resolved' or 'snoozed'.
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
			_, _ = w.Write([]byte(badge))
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
		_, _ = w.Write([]byte(badge))
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
	if id == "" || id == "1" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM events WHERE project_id = ?", id)
	if err != nil {
		log.Printf("delete project events error: %v", err)
	}

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

	tgTok := r.FormValue("tg_token")
	tgChat := r.FormValue("tg_chat_id")
	discordWebhook := r.FormValue("discord_webhook")

	_, err := db.Exec(`
		UPDATE projects 
		SET tg_token = ?, tg_chat_id = ?, discord_webhook = ?
		WHERE id = ?`,
		tgTok, tgChat, discordWebhook, id,
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
	mux.Handle("/", middleware.BasicAuthMiddleware(protected))
	mux.Handle("/events/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))
	mux.Handle("/api/events", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))
	mux.Handle("/api/events/export", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))
	mux.Handle("/api/events/resolve/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolveHandler(w, r)
	})))
	mux.Handle("/api/events/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/comments") && r.Method == http.MethodPost {
			postCommentHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})))

	mux.Handle("/api/projects", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		createProjectHandler(w, r)
	})))

	mux.Handle("/api/projects/delete/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteProjectHandler(w, r)
	})))

	mux.Handle("/api/projects/update/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		updateProjectSettingsHandler(w, r)
	})))

	mux.Handle("/api/topology", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		topologyHandler(w, r)
	})))

	mux.Handle("/api/topology/view", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		topologyViewHandler(w, r)
	})))

	mux.Handle("/api/logs", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logsQueryHandler(w, r)
	})))

	mux.Handle("/api/logs/view", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logsViewHandler(w, r)
	})))

	mux.HandleFunc("/api/logs/ingest", func(w http.ResponseWriter, r *http.Request) {
		logsIngestHandler(w, r)
	})

	mux.Handle("/api/performance", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		performanceHandler(w, r)
	})))

	mux.Handle("/api/performance/analytics", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		latencyAnalyticsHandler(w, r)
	})))

	mux.Handle("/api/performance/trace/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceHandler(w, r)
	})))

	mux.Handle("/api/stats", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected.ServeHTTP(w, r)
	})))

	mux.Handle("/api/system-metrics", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		systemMetricsHandler(w, r)
	})))

	mux.Handle("/api/alerting-rules", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertingRulesHandler(w, r)
	})))

	mux.Handle("/api/alerting-rules/delete/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteAlertingRuleHandler(w, r)
	})))

	mux.Handle("/api/log-alerting-rules", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logAlertingRulesHandler(w, r)
	})))

	mux.Handle("/api/log-alerting-rules/delete/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteLogAlertingRuleHandler(w, r)
	})))

	mux.Handle("/api/api-keys", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKeysHandler(w, r)
	})))

	mux.Handle("/api/api-keys/delete/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteAPIKeyHandler(w, r)
	})))

	mux.Handle("/api/sourcemaps/upload", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceMapUploadHandler(w, r)
	})))

	mux.Handle("/api/grouping-rules", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		groupingRulesHandler(w, r)
	})))

	mux.Handle("/api/grouping-rules/delete/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleteGroupingRuleHandler(w, r)
	})))

	mux.Handle("/api/attachments/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attachmentHandler(w, r)
	})))

	mux.Handle("/api/replays/", middleware.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replayID := strings.TrimPrefix(r.URL.Path, "/api/replays/")
		replayID = filepath.Base(replayID)
		filePath := filepath.Join("data", "replays", replayID+".jsonl")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/x-ndjson")
		http.ServeFile(w, r, filePath)
	})))

	// Public health check and Prometheus metrics endpoints
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/metrics", metricsHandler)

	// Real-time SSE log stream endpoint
	mux.HandleFunc("/api/logs/stream", logsStreamHandler)

	// OpenTelemetry OTLP Ingest endpoints
	mux.HandleFunc("/v1/traces", otlpTracesHandler)
	mux.HandleFunc("/v1/logs", otlpLogsHandler)

	// Public ingestion routes — NO auth.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
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

	return middleware.CorsMiddleware(middleware.GzipDecodeMiddleware(mux))
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
	fmt.Printf("  🛡️  Version     : %s\n", update.CurrentVersion)
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
	if notify.DiscordWebhookURL != "" {
		notifs = append(notifs, "Discord")
	}
	if notify.TgToken != "" && notify.TgChatID != "" {
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

	port := flag.String("port", "8080", "HTTP server port")
	dbPath := flag.String("db", "pocketsentry.db", "Path to SQLite database file")
	flagUser := flag.String("admin-user", "", "Dashboard admin username (empty = auth disabled)")
	flagPass := flag.String("admin-pass", "", "Dashboard admin password")
	retentionDays := flag.Int("retention-days", 30, "Auto-delete events older than N days (0 = disabled)")
	logRetentionDays := flag.Int("log-retention-days", 30, "Auto-delete app logs older than N days (0 = disabled)")
	txRetentionDays := flag.Int("tx-retention-days", 30, "Auto-delete transactions & spans older than N days (0 = disabled)")
	versionFlag := flag.Bool("version", false, "Print PocketSentry version and exit")
	versionFlagShort := flag.Bool("v", false, "Print PocketSentry version and exit")
	checkUpd := flag.Bool("checkupd", false, "Check for a newer release on GitHub and offer to update")
	flagDiscord := flag.String("discord-webhook-url", "", "Discord Webhook URL for error notifications")
	flagTgToken := flag.String("tg-token", "", "Telegram Bot Token for error notifications")
	flagTgChatID := flag.String("tg-chat-id", "", "Telegram Chat ID for error notifications")
	flagEnableEBPF := flag.Bool("enable-ebpf", false, "Enable the eBPF agent for zero-config HTTP 500 tracing (requires root)")
	flag.Parse()

	if *versionFlag || *versionFlagShort {
		fmt.Printf("PocketSentry %s\n", update.CurrentVersion)
		return
	}

	if *checkUpd {
		update.CheckUpdate()
		return
	}

	if envPort := os.Getenv("PORT"); envPort != "" && !isFlagPassed("port") {
		*port = envPort
	}
	if envDB := os.Getenv("DB_PATH"); envDB != "" && !isFlagPassed("db") {
		*dbPath = envDB
	}

	middleware.AdminUser = *flagUser
	middleware.AdminPass = *flagPass
	notify.DiscordWebhookURL = *flagDiscord
	notify.TgToken = *flagTgToken
	notify.TgChatID = *flagTgChatID
	globalRetentionDays = *retentionDays

	if err := initTemplates(); err != nil {
		log.Fatalf("Template init failed: %v", err)
	}

	dbFilePath = *dbPath
	if err := initDB(*dbPath); err != nil {
		log.Fatalf("Database init failed: %v", err)
	}
	notify.DB = db

	printBanner(*port, *dbPath, middleware.AdminUser, *retentionDays)

	if *flagEnableEBPF {
		err := ebpf.StartAgent(ebpf.Callbacks{
			OnHTTP500: func(pid uint32, snippet string) {
				msg := fmt.Sprintf("Zero-Config Intercept: HTTP 500 error from PID %d\nSnippet: %s", pid, snippet)
				ev := models.SentryEvent{
					EventID:  helpers.GenerateUUID(),
					Level:    "error",
					Platform: "ebpf",
					Message:  msg,
					Logger:   "pocketsentry.ebpf",
				}
				raw := fmt.Sprintf(`{"message":"%s","level":"error","platform":"ebpf","tags":{"pid":"%d","source":"kernel_intercept"}}`, msg, pid)
				_ = saveEvent(ev, "1", raw)
			},
			OnTCPConn: func(pid uint32, destIP string, destPort uint16) {
				if destIP == "127.0.0.1" || destIP == "0.0.0.0" {
					return
				}
				sourceNode := container.ResolveProcessName(pid)
				targetNode := container.ResolveIPToContainer(destIP)

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
			go container.FlushContainerCache()
		}
	}

	addr := ":" + *port
	srv := &http.Server{
		Addr:    addr,
		Handler: newRouter(),
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	if *retentionDays > 0 || *logRetentionDays > 0 || *txRetentionDays > 0 {
		go runRetentionCleanup(cleanupCtx, *retentionDays, *logRetentionDays, *txRetentionDays)
	}

	go notify.EnsureTelegramPollers()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	sig := <-quit
	log.Printf("Received %v, shutting down gracefully...", sig)

	cleanupCancel()

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

func runRetentionCleanup(ctx context.Context, eventDays, logDays, txDays int) {
	cleanup := func() {
		// 1. Clean events & orphaned attachments
		if eventDays > 0 {
			res, err := db.Exec(
				`DELETE FROM events WHERE
				 CASE WHEN last_seen = '' THEN timestamp ELSE last_seen END
				 < datetime('now', '-' || ? || ' days')`, eventDays,
			)
			if err != nil {
				log.Printf("[retention] events cleanup error: %v", err)
			} else if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("[retention] deleted %d events older than %d days", n, eventDays)
			}

			// Clean orphaned attachments from DB and disk
			cleanOrphanedAttachments()
		}

		// 2. Clean app_logs
		if logDays > 0 {
			res, err := db.Exec(
				`DELETE FROM app_logs WHERE timestamp < datetime('now', '-' || ? || ' days')`, logDays,
			)
			if err != nil {
				log.Printf("[retention] logs cleanup error: %v", err)
			} else if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("[retention] deleted %d logs older than %d days", n, logDays)
			}
		}

		// 3. Clean transactions & spans
		if txDays > 0 {
			res, err := db.Exec(
				`DELETE FROM transactions WHERE timestamp < datetime('now', '-' || ? || ' days')`, txDays,
			)
			if err != nil {
				log.Printf("[retention] transactions cleanup error: %v", err)
			} else if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("[retention] deleted %d transactions older than %d days", n, txDays)
			}

			// Clean orphaned spans
			resSpans, err := db.Exec(`DELETE FROM spans WHERE transaction_id NOT IN (SELECT id FROM transactions)`)
			if err == nil {
				if n, _ := resSpans.RowsAffected(); n > 0 {
					log.Printf("[retention] cleaned %d orphaned spans", n)
				}
			}
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

func cleanOrphanedAttachments() {
	// Query attachments whose event no longer exists
	rows, err := db.Query(`SELECT id, event_id FROM attachments WHERE event_id NOT IN (SELECT id FROM events)`)
	if err != nil {
		return
	}
	defer rows.Close()

	var eventIDs []string
	for rows.Next() {
		var attID, evID string
		if err := rows.Scan(&attID, &evID); err == nil {
			eventIDs = append(eventIDs, evID)
		}
	}

	if len(eventIDs) > 0 {
		_, _ = db.Exec(`DELETE FROM attachments WHERE event_id NOT IN (SELECT id FROM events)`)
		for _, evID := range eventIDs {
			dir := filepath.Join("data", "attachments", evID)
			_ = os.RemoveAll(dir)
		}
		log.Printf("[retention] purged disk files for %d orphaned attachments", len(eventIDs))
	}
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
