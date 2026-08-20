package update

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pocketsentry/pocketsentry/internal/models"
)

// CurrentVersion is the version of this binary, compared against GitHub releases.
const CurrentVersion = "v3.2.0"

// CheckUpdate checks GitHub for a newer release. If one is found it prompts
// the user to confirm, downloads the new binary, atomically replaces the
// current executable, and exits so the user can restart with the new version.
func CheckUpdate() {
	fmt.Println("🔍 Checking for updates...")

	const apiURL = "https://api.github.com/repos/apvcode/pocketsentry/releases/latest"

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pocketsentry-selfupdate/"+CurrentVersion)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Could not reach GitHub: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var release models.GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to parse GitHub response: %v\n", err)
		return
	}

	latest := strings.TrimSpace(release.TagName)
	if latest == "" {
		fmt.Println("❌ Could not determine the latest version.")
		return
	}

	if latest == CurrentVersion {
		fmt.Printf("✅ You are already on the latest version (%s). No update needed.\n", CurrentVersion)
		return
	}

	fmt.Printf("🆕 New version available: %s (current: %s)\n", latest, CurrentVersion)

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
