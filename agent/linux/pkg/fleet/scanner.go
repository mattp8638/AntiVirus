package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Scanner holds the malicious hash set from the cloud bundle and quarantines matches.
type Scanner struct {
	mu            sync.RWMutex
	bad           map[string]string // sha256 -> family
	allow         map[string]bool
	Version       string
	QuarantineDir string
	MaxFileBytes  int64
}

func NewScanner(quarantineDir string) *Scanner {
	return &Scanner{bad: map[string]string{}, allow: map[string]bool{}, QuarantineDir: quarantineDir, MaxFileBytes: 256 << 20}
}

func (s *Scanner) Load(b *Bundle) {
	bad := make(map[string]string, len(b.Hashes))
	for _, h := range b.Hashes {
		if strings.EqualFold(h.Type, "sha256") && len(h.Value) == 64 {
			bad[strings.ToLower(h.Value)] = h.MalwareFamily
		}
	}
	allow := map[string]bool{}
	for _, h := range b.AllowSha256 {
		allow[strings.ToLower(h)] = true
	}
	s.mu.Lock()
	s.bad, s.allow, s.Version = bad, allow, b.SignatureVersion
	s.mu.Unlock()
}

func (s *Scanner) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bad)
}

// Verdict returns (malicious, family) for a hash.
func (s *Scanner) Verdict(sha string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.allow[sha] {
		return false, ""
	}
	family, ok := s.bad[sha]
	return ok, family
}

func HashFile(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	if limit > 0 && info.Size() > limit {
		return "", fmt.Errorf("file larger than scan limit")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type Finding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Family string `json:"family"`
	Action string `json:"action"`
	Record string `json:"recordId,omitempty"`
}

type QuarantineRecord struct {
	ID           string `json:"id"`
	OriginalPath string `json:"originalPath"`
	SHA256       string `json:"sha256"`
	Mode         uint32 `json:"mode"`
	At           string `json:"at"`
}

// Quarantine moves a file into the quarantine store with permissions stripped.
func (s *Scanner) Quarantine(path, sha string) (string, error) {
	if err := os.MkdirAll(s.QuarantineDir, 0o700); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	id := fmt.Sprintf("q-%d-%s", time.Now().UnixNano(), sha[:12])
	dst := filepath.Join(s.QuarantineDir, id+".bin")
	if err := os.Rename(path, dst); err != nil {
		// Cross-device: copy then remove.
		if err := copyFile(path, dst); err != nil {
			return "", err
		}
		if err := os.Remove(path); err != nil {
			return "", err
		}
	}
	_ = os.Chmod(dst, 0)
	record := QuarantineRecord{ID: id, OriginalPath: path, SHA256: sha, Mode: uint32(info.Mode().Perm()), At: time.Now().UTC().Format(time.RFC3339)}
	data, _ := json.Marshal(record)
	return id, os.WriteFile(filepath.Join(s.QuarantineDir, id+".json"), data, 0o600)
}

func (s *Scanner) Restore(id string) (string, error) {
	if strings.ContainsAny(id, "/\\") {
		return "", fmt.Errorf("invalid record id")
	}
	data, err := os.ReadFile(filepath.Join(s.QuarantineDir, id+".json"))
	if err != nil {
		return "", err
	}
	var record QuarantineRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return "", err
	}
	src := filepath.Join(s.QuarantineDir, id+".bin")
	if err := os.Rename(src, record.OriginalPath); err != nil {
		if err := copyFile(src, record.OriginalPath); err != nil {
			return "", err
		}
		_ = os.Remove(src)
	}
	_ = os.Chmod(record.OriginalPath, fs.FileMode(record.Mode))
	_ = os.Remove(filepath.Join(s.QuarantineDir, id+".json"))
	return record.OriginalPath, nil
}

func (s *Scanner) Delete(id string) error {
	if strings.ContainsAny(id, "/\\") {
		return fmt.Errorf("invalid record id")
	}
	_ = os.Remove(filepath.Join(s.QuarantineDir, id+".bin"))
	return os.Remove(filepath.Join(s.QuarantineDir, id+".json"))
}

// ScanPaths walks the given roots, hashing files and quarantining matches.
func (s *Scanner) ScanPaths(roots []string, skip []string, quarantine bool, maxFiles int) (scanned int, findings []Finding) {
	skipped := func(path string) bool {
		for _, prefix := range append(skip, "/proc", "/sys", "/dev", "/run", s.QuarantineDir) {
			if prefix != "" && strings.HasPrefix(path, prefix) {
				return true
			}
		}
		return false
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if skipped(path) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if maxFiles > 0 && scanned >= maxFiles {
				return filepath.SkipAll
			}
			sha, err := HashFile(path, s.MaxFileBytes)
			if err != nil {
				return nil
			}
			scanned++
			if bad, family := s.Verdict(sha); bad {
				f := Finding{Path: path, SHA256: sha, Family: family, Action: "detected"}
				if quarantine {
					if id, err := s.Quarantine(path, sha); err == nil {
						f.Action, f.Record = "quarantined", id
					} else {
						f.Action = "quarantine-failed: " + err.Error()
					}
				}
				findings = append(findings, f)
			}
			return nil
		})
	}
	return scanned, findings
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
