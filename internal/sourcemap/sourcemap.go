package sourcemap

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-sourcemap/sourcemap"
	"github.com/pocketsentry/pocketsentry/internal/models"
)

// ApplySourceMaps attempts to translate minified frames using local .map files.
func ApplySourceMaps(frames []models.StackFrame, projectID, release, dbFilePath string) []models.StackFrame {
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
					if preStart < 0 {
						preStart = 0
					}
					frames[i].PreContext = lines[preStart : line-1]

					// Post context
					postEnd := line + 3
					if postEnd > len(lines) {
						postEnd = len(lines)
					}
					frames[i].PostContext = lines[line:postEnd]
				}
			}
		}
	}
	return frames
}
