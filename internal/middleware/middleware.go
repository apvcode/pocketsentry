package middleware

import (
	"compress/gzip"
	"crypto/subtle"
	"io"
	"net/http"
	"strings"
)

// MaxBodyBytes is the hard cap for request bodies (applied to both plain and
// gzip-decompressed bodies) to prevent decompression bombs and OOM.
const MaxBodyBytes = 20 << 20 // 20 MB

// AdminUser and AdminPass are set from CLI flags / env in main.
// If both are empty, basic auth is disabled.
var (
	AdminUser string
	AdminPass string
)

// publicPathPrefixes are paths that need permissive CORS (ingestion endpoints
// used by browser-based Sentry SDKs, health checks and metrics). Everything
// else (dashboard, API keys, project settings) gets no CORS headers at all.
var publicPathPrefixes = []string{
	"/health",
	"/metrics",
	"/api/logs/ingest",
	"/api/logs/stream",
	"/v1/traces",
	"/v1/logs",
}

// isPublicIngestPath reports whether the path is an ingestion or monitoring
// endpoint that must stay reachable cross-origin: /api/{project}/store/ or
// /api/{project}/envelope/.
func isPublicIngestPath(path string) bool {
	for _, p := range publicPathPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	rest, ok := strings.CutPrefix(path, "/api/")
	if !ok || rest == "" {
		return false
	}
	return strings.HasSuffix(rest, "/store/") || strings.HasSuffix(rest, "/envelope/")
}

// CorsMiddleware sets permissive CORS headers only for public ingestion and
// monitoring endpoints. Private routes get no CORS headers at all so browsers
// cannot read dashboard data, API keys or tokens cross-origin.
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicIngestPath(r.URL.Path) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GzipDecodeMiddleware transparently decompresses gzip-encoded request bodies.
// The decompressed stream is wrapped in a MaxBytesReader so a small gzip
// payload cannot expand into gigabytes of memory (decompression bomb).
func GzipDecodeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(io.LimitReader(r.Body, MaxBodyBytes))
			if err != nil {
				http.Error(w, "failed to decode gzip body", http.StatusBadRequest)
				return
			}
			defer gz.Close()
			r.Body = http.MaxBytesReader(w, io.NopCloser(io.Reader(gz)), MaxBodyBytes)
			r.Header.Del("Content-Encoding")
			r.ContentLength = -1
		}
		next.ServeHTTP(w, r)
	})
}

// BasicAuthMiddleware protects UI routes with HTTP Basic Authentication.
// Credentials are compared in constant time to prevent timing attacks.
// If AdminUser and AdminPass are both empty, it passes requests through.
func BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if AdminUser == "" && AdminPass == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(AdminUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(AdminPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="PocketSentry"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
