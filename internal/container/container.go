package container

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------- Docker / K8s Container Resolution ----------

// containerNameCache caches PID→container name and IP→container name lookups.
var containerNameCache sync.Map // key: string (pid:N or ip:X.X.X.X) → value: string

// ResolveProcessName resolves a PID to a human-readable name.
// Priority: Docker container name → K8s pod name → process binary name → PID:N.
func ResolveProcessName(pid uint32) string {
	cacheKey := fmt.Sprintf("pid:%d", pid)
	if v, ok := containerNameCache.Load(cacheKey); ok {
		return v.(string)
	}

	name := resolveProcessNameUncached(pid)
	containerNameCache.Store(cacheKey, name)
	return name
}

func resolveProcessNameUncached(pid uint32) string {
	// 1. Try to detect Docker/K8s via /proc/{pid}/cgroup
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	cgData, err := os.ReadFile(cgroupPath)
	if err == nil {
		containerID, podUID := ParseCgroupForContainer(string(cgData))
		if containerID != "" {
			// Try Docker API to resolve container name
			if name := QueryDockerContainerName(containerID); name != "" {
				if podUID != "" {
					return fmt.Sprintf("🐳 %s (pod:%s)", name, podUID[:8])
				}
				return "🐳 " + name
			}
			// Fallback: short container ID
			short := containerID
			if len(short) > 12 {
				short = short[:12]
			}
			if podUID != "" {
				return fmt.Sprintf("☸ pod:%s/%s", podUID[:8], short)
			}
			return "🐳 " + short
		}
	}

	// 2. Fallback to process cmdline
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

// ResolveIPToContainer tries to resolve a destination IP to a Docker container name.
func ResolveIPToContainer(ip string) string {
	cacheKey := "ip:" + ip
	if v, ok := containerNameCache.Load(cacheKey); ok {
		return v.(string)
	}

	name := QueryDockerContainerByIP(ip)
	if name == "" {
		name = ip // fallback to raw IP
	} else {
		name = "🐳 " + name
	}
	containerNameCache.Store(cacheKey, name)
	return name
}

// ParseCgroupForContainer extracts Docker container ID and K8s pod UID from cgroup data.
func ParseCgroupForContainer(cgroupData string) (containerID, podUID string) {
	for _, line := range strings.Split(cgroupData, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]

		// Docker: .../docker/<container_id> or .../containerd/<container_id>
		for _, prefix := range []string{"/docker/", "/containerd/", "/cri-containerd-"} {
			if idx := strings.LastIndex(path, prefix); idx != -1 {
				id := path[idx+len(prefix):]
				id = strings.TrimSuffix(id, ".scope")
				if len(id) >= 12 {
					containerID = id
				}
			}
		}

		// K8s: .../kubepods/.../pod<uid>/...
		if strings.Contains(path, "kubepods") {
			re := regexp.MustCompile(`pod([0-9a-f-]{36})`)
			if m := re.FindStringSubmatch(path); len(m) > 1 {
				podUID = m[1]
			}
		}
	}
	return
}

// QueryDockerContainerName calls the Docker Engine API via Unix socket to get a container's name.
func QueryDockerContainerName(containerID string) string {
	// Trim to first 12 chars if needed (Docker accepts prefix)
	short := containerID
	if len(short) > 12 {
		short = short[:12]
	}

	conn, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		return ""
	}
	defer conn.Close()

	req := fmt.Sprintf("GET /containers/%s/json HTTP/1.0\r\nHost: localhost\r\n\r\n", short)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write([]byte(req))
	if err != nil {
		return ""
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		return ""
	}

	// Skip HTTP headers
	headerEnd := bytes.Index(body, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return ""
	}
	jsonBody := body[headerEnd+4:]

	var info struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(jsonBody, &info); err != nil {
		return ""
	}

	return strings.TrimPrefix(info.Name, "/")
}

// QueryDockerContainerByIP inspects Docker networks to find a container by IP.
func QueryDockerContainerByIP(ip string) string {
	conn, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		return ""
	}
	defer conn.Close()

	req := "GET /containers/json HTTP/1.0\r\nHost: localhost\r\n\r\n"
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte(req))
	if err != nil {
		return ""
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		return ""
	}

	headerEnd := bytes.Index(body, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return ""
	}
	jsonBody := body[headerEnd+4:]

	var containers []struct {
		Names           []string `json:"Names"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(jsonBody, &containers); err != nil {
		return ""
	}

	for _, c := range containers {
		for _, n := range c.NetworkSettings.Networks {
			if n.IPAddress == ip && len(c.Names) > 0 {
				return strings.TrimPrefix(c.Names[0], "/")
			}
		}
	}
	return ""
}

// FlushContainerCache periodically clears the container name cache so stale entries are refreshed.
func FlushContainerCache() {
	for {
		time.Sleep(60 * time.Second)
		containerNameCache.Range(func(key, value any) bool {
			containerNameCache.Delete(key)
			return true
		})
	}
}
