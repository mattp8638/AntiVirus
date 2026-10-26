package fleet

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxBundleFile  = 1 << 20  // persistence files are small; skip anything bigger
	maxBundleTotal = 50 << 20 // stay well under the cloud's upload limit
)

// BuildBundle packs triage data and copies of the given files into a .tar.gz.
// Files that cannot be read, or are too big, are listed in skipped.txt instead.
func BuildBundle(triage map[string]interface{}, files []string, read func(string) ([]byte, error)) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	summary, err := json.MarshalIndent(triage, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := add("triage.json", summary); err != nil {
		return nil, err
	}
	sort.Strings(files)
	var skipped []string
	total := len(summary)
	for _, path := range files {
		data, err := read(path)
		switch {
		case err != nil:
			skipped = append(skipped, path+": "+err.Error())
			continue
		case len(data) > maxBundleFile || total+len(data) > maxBundleTotal:
			skipped = append(skipped, path+": too large")
			continue
		}
		total += len(data)
		if err := add("files/"+strings.TrimPrefix(filepath.Clean(path), "/"), data); err != nil {
			return nil, err
		}
	}
	if len(skipped) > 0 {
		if err := add("skipped.txt", []byte(strings.Join(skipped, "\n")+"\n")); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UploadArtifact sends a bundle for a command; the cloud verifies the SHA-256.
func (c *Client) UploadArtifact(commandID, filename string, data []byte) (string, error) {
	sum := sha256.Sum256(data)
	q := url.Values{"filename": {filename}, "sha256": {hex.EncodeToString(sum[:])}}
	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/devices/"+c.DeviceID+"/commands/"+commandID+"/artifact?"+q.Encode(),
		bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Device-Api-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", &APIError{Status: resp.StatusCode, Body: string(body)}
	}
	var out struct {
		ArtifactID string `json:"artifactId"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.ArtifactID, nil
}

// collectBundle runs triage, packs it with the watched persistence files and uploads it.
// The command still succeeds with the inline triage if the upload fails.
func (a *Agent) collectBundle(cmd Command) map[string]interface{} {
	triage := a.triage()
	var files []string
	if persistence, ok := triage["persistence"].(map[string]string); ok {
		for path := range persistence {
			files = append(files, path)
		}
	}
	result := map[string]interface{}{"collectedAt": triage["collectedAt"], "processCount": len(asSlice(triage["processes"])),
		"persistenceFiles": len(files), "agentVersion": Version}
	data, err := BuildBundle(triage, files, os.ReadFile)
	if err == nil {
		var id string
		name := fmt.Sprintf("%s-%s.tar.gz", strings.ReplaceAll(cmd.Type, ".", "-"), time.Now().UTC().Format("20060102-150405"))
		if id, err = a.client.UploadArtifact(cmd.ID, name, data); err == nil {
			result["artifactId"], result["bundleBytes"] = id, len(data)
			return result
		}
	}
	result["uploadError"] = err.Error()
	result["triage"] = triage // fall back to returning the data inline
	return result
}

func asSlice(v interface{}) []map[string]interface{} {
	s, _ := v.([]map[string]interface{})
	return s
}
