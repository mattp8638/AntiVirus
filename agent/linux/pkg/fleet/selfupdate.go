package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// AgentUpdate describes the Linux agent build the cloud serves (from its own /downloads).
type AgentUpdate struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	URL       string `json:"url"`
}

func (c *Client) FetchAgentUpdate(arch string) (*AgentUpdate, error) {
	var out AgentUpdate
	return &out, c.do("GET", "/api/v1/agent/update/"+platformName()+"?arch="+arch, nil, &out, nil)
}

// DownloadFile fetches a path on the cloud (with the device key), capped at limit bytes.
func (c *Client) DownloadFile(path string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("update URL must be a path on the Fenrir server")
	}
	req, err := http.NewRequest("GET", c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Device-Api-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &APIError{Status: resp.StatusCode, Body: string(body)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("update is larger than allowed")
	}
	return data, nil
}

// NewerVersion reports whether candidate (e.g. 1.2.0) is newer than current.
func NewerVersion(candidate, current string) bool {
	parse := func(v string) []int {
		var out []int
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' }) {
			n, err := strconv.Atoi(part)
			if err != nil {
				n = 0
			}
			out = append(out, n)
		}
		return out
	}
	a, b := parse(candidate), parse(current)
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

const maxAgentBinary = 200 << 20

// selfUpdate downloads the server's Linux agent build, checks its SHA-256, swaps it in atomically
// and exits so systemd (Restart=always) starts the new version.
func (a *Agent) selfUpdate(force bool) (map[string]interface{}, error) {
	info, err := a.client.FetchAgentUpdate(runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("could not check for an update: %w", err)
	}
	if !info.Available {
		return nil, errors.New("the Fenrir server has no Linux agent build for " + runtime.GOARCH)
	}
	if !force && !NewerVersion(info.Version, Version) {
		return map[string]interface{}{"updated": false, "current": Version, "available": info.Version, "reason": "already up to date"}, nil
	}
	data, err := a.client.DownloadFile(info.URL, maxAgentBinary)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, info.SHA256) || info.SHA256 == "" {
		return nil, fmt.Errorf("checksum mismatch (expected %s, got %s); update not applied", info.SHA256, got)
	}
	exe, err := a.executablePath()
	if err != nil {
		return nil, err
	}
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return nil, fmt.Errorf("could not write the new binary: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("could not replace the agent binary: %w", err)
	}
	a.emit("agent.updated", "updater", "Agent updated from "+Version+" to "+info.Version,
		map[string]interface{}{"from": Version, "to": info.Version, "sha256": info.SHA256})
	go func() {
		// Leave time for the command result and the event above to reach the cloud.
		time.Sleep(a.restartDelay)
		_ = a.Flush()
		log.Printf("restarting into agent %s", info.Version)
		a.exit(0)
	}()
	return map[string]interface{}{"updated": true, "from": Version, "to": info.Version, "restarting": true}, nil
}

func (a *Agent) executablePath() (string, error) {
	if a.exePath != "" {
		return a.exePath, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// maybeAutoUpdate runs at most every 6 hours when the policy turns on automatic agent updates.
func (a *Agent) maybeAutoUpdate() {
	if !a.state.Policy.ModuleBool("updates", "autoUpdateAgent", false) || time.Since(a.lastUpdateCheck) < 6*time.Hour {
		return
	}
	a.lastUpdateCheck = time.Now()
	if result, err := a.selfUpdate(false); err != nil {
		log.Printf("automatic update check failed: %v", err)
	} else if updated, _ := result["updated"].(bool); updated {
		data, _ := json.Marshal(result)
		log.Printf("automatic update: %s", data)
	}
}
