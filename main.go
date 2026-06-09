package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// templateFS embeds the templates directory into the binary so the final
// executable is fully self-contained — no external files needed.
//
//go:embed templates/*
var templateFS embed.FS

// Parsed templates (initialized once at startup).
var (
	tmplIndex *template.Template
	tmplRows  *template.Template
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
		raw_payload TEXT     NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	`
	if _, err := db.Exec(ddl); err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	return nil
}

// saveEvent inserts a parsed event into the events table.
func saveEvent(ev SentryEvent, projectID, rawPayload string) error {
	if ev.EventID == "" {
		ev.EventID = generateUUID()
	}
	if ev.Level == "" {
		ev.Level = "error"
	}

	ts := time.Now().UTC()
	if ev.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
			ts = parsed.UTC()
		} else if parsed, err := time.Parse("2006-01-02T15:04:05", ev.Timestamp); err == nil {
			ts = parsed.UTC()
		}
	}

	_, err := db.Exec(
		`INSERT OR IGNORE INTO events (id, project_id, timestamp, level, platform, message, raw_payload)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.EventID, projectID, ts.Format(time.RFC3339), ev.Level, ev.Platform, ev.Message, rawPayload,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	log.Printf("event id=%s project=%s level=%s msg=%q",
		ev.EventID, projectID, ev.Level, truncate(ev.Message, 80))
	return nil
}

// ---------- Event Row (UI) ----------

// EventRow is the struct passed to HTML templates for rendering.
// All fields are plain strings so we never hit nil-pointer issues from
// NULL columns (the query uses COALESCE as an extra safety net).
type EventRow struct {
	ID        string
	ProjectID string
	Timestamp string
	Level     string
	Platform  string
	Message   string
}

// queryEvents returns the latest events for the dashboard.
func queryEvents(limit int) ([]EventRow, error) {
	const q = `
		SELECT
			COALESCE(id, ''),
			COALESCE(project_id, ''),
			COALESCE(timestamp, ''),
			COALESCE(level, 'error'),
			COALESCE(platform, ''),
			COALESCE(message, '')
		FROM events
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := db.Query(q, limit)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var result []EventRow
	for rows.Next() {
		var ev EventRow
		if err := rows.Scan(&ev.ID, &ev.ProjectID, &ev.Timestamp, &ev.Level, &ev.Platform, &ev.Message); err != nil {
			log.Printf("⚠️  scan row: %v", err)
			continue
		}
		ev.Timestamp = formatTimestamp(ev.Timestamp)
		result = append(result, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return result, nil
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

// ---------- Sentry Event Parsing ----------

// SentryEvent represents the subset of Sentry event fields we care about.
type SentryEvent struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp,omitempty"`
	Level     string `json:"level"`
	Platform  string `json:"platform"`
	Message   string `json:"message"`
	Logger    string `json:"logger"`

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

// parseEnvelope handles the Sentry envelope format (NDJSON).
func parseEnvelope(raw []byte) (SentryEvent, error) {
	lines := splitEnvelopeLines(raw)
	if len(lines) == 0 {
		return SentryEvent{}, fmt.Errorf("empty envelope")
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
			ev, err := parseSentryEvent(lines[i+1])
			if err != nil {
				continue
			}
			if ev.EventID == "" {
				ev.EventID = envelopeHeader.EventID
			}
			return ev, nil
		default:
			continue
		}
	}

	// Fallback: brute-force — try every line as an event payload.
	for _, line := range lines[1:] {
		ev, err := parseSentryEvent(line)
		if err == nil && (ev.Message != "" || ev.Exception != nil || ev.LogEntry != nil) {
			if ev.EventID == "" {
				ev.EventID = envelopeHeader.EventID
			}
			return ev, nil
		}
	}

	return SentryEvent{}, fmt.Errorf("no parseable event found in envelope (%d lines)", len(lines))
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

// ---------- Handlers ----------

// indexHandler serves the main dashboard page.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmplIndex.Execute(w, nil); err != nil {
		log.Printf("❌ template execute error: %v", err)
	}
}

// eventsHandler returns rendered <tr> rows for the HTMX table.
func eventsHandler(w http.ResponseWriter, r *http.Request) {
	events, err := queryEvents(50)
	if err != nil {
		log.Printf("❌ query events: %v", err)
		events = []EventRow{}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmplRows.Execute(w, events); err != nil {
		log.Printf("❌ rows template execute error: %v", err)
	}
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

	ev, err := parseEnvelope(body)
	if err != nil {
		log.Printf("[envelope] parse error: %v", err)
		respondOK(w)
		return
	}

	if err := saveEvent(ev, projectID, string(body)); err != nil {
		log.Printf("[envelope] save error: %v", err)
	}

	respondWithID(w, ev.EventID)
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

// respondWithID sends a 200 JSON response with the given event ID.
func respondWithID(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

// ---------- Router ----------

func newRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		indexHandler(w, r)
	})

	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			eventsHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
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

// ---------- Banner ----------

const banner = `
   ___           _        _   ___            _
  | _ \ ___  __ | | __ __| |_/ __| ___ _ __ | |_ _ _ _  _
  |  _// _ \/ _|| |/ // _| __\__ \/ _ \ '_ \|  _| '_| || |
  |_|  \___/\__||_\_\\__|\__|___/\___/_||_|\__|_| \_, |
                                                   |__/
`

func printBanner(port, dbPath string) {
	fmt.Print(banner)
	fmt.Println("  ──────────────────────────────────────────────────")
	fmt.Printf("  🛡️  Version     : 0.1.0-dev\n")
	fmt.Printf("  🌐 Dashboard   : http://localhost:%s\n", port)
	fmt.Printf("  📦 Database    : %s\n", dbPath)
	fmt.Printf("  🔗 DSN         : http://public@localhost:%s/1\n", port)
	fmt.Println("  ──────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Point your Sentry SDK to the DSN above.")
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()
}

// ---------- Main ----------

func main() {
	// CLI flags.
	port := flag.String("port", "8080", "HTTP server port")
	dbPath := flag.String("db", "pocketsentry.db", "Path to SQLite database file")
	flag.Parse()

	// Override from env vars (flags take priority if explicitly set).
	if envPort := os.Getenv("PORT"); envPort != "" && !isFlagPassed("port") {
		*port = envPort
	}
	if envDB := os.Getenv("DB_PATH"); envDB != "" && !isFlagPassed("db") {
		*dbPath = envDB
	}

	// Initialize templates (from embedded FS).
	if err := initTemplates(); err != nil {
		log.Fatalf("❌ Template init failed: %v", err)
	}

	// Initialize database.
	if err := initDB(*dbPath); err != nil {
		log.Fatalf("❌ Database init failed: %v", err)
	}

	// Print startup banner.
	printBanner(*port, *dbPath)

	// Create HTTP server.
	addr := ":" + *port
	srv := &http.Server{
		Addr:    addr,
		Handler: newRouter(),
	}

	// Graceful shutdown: listen for SIGINT / SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine.
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server error: %v", err)
		}
	}()

	// Block until we receive a shutdown signal.
	sig := <-quit
	log.Printf("⏳ Received %v, shutting down gracefully...", sig)

	// Give in-flight requests up to 10 seconds to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("⚠️  HTTP shutdown error: %v", err)
	}

	if err := db.Close(); err != nil {
		log.Printf("⚠️  Database close error: %v", err)
	}

	log.Println("✅ PocketSentry stopped gracefully.")
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
