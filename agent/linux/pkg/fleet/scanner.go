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

	"github.com/AntiVirus/agent/linux/pkg/ml"
)

// Scanner holds the malicious hash set from the cloud bundle and quarantines matches.
type Scanner struct {
	mu            sync.RWMutex
	bad           map[string]string // sha256 -> family
	pua           map[string]bool   // sha256 of potentially unwanted applications (subset of bad)
	allow         map[string]bool
	Version       string
	QuarantineDir string
	MaxFileBytes  int64
	// Static PE model (optional). Threshold <= 0 disables it.
	Model       *ml.Model
	MLThreshold float64
}

func NewScanner(quarantineDir string) *Scanner {
	return &Scanner{bad: map[string]string{}, allow: map[string]bool{}, QuarantineDir: quarantineDir, MaxFileBytes: 256 << 20}
}

func (s *Scanner) Load(b *Bundle) {
	bad := make(map[string]string, len(b.Hashes))
	pua := map[string]bool{}
	for _, h := range b.Hashes {
		if strings.EqualFold(h.Type, "sha256") && len(h.Value) == 64 {
			bad[strings.ToLower(h.Value)] = h.MalwareFamily
			if strings.EqualFold(h.Category, "pua") {
				pua[strings.ToLower(h.Value)] = true
			}
		}
	}
	allow := map[string]bool{}
	for _, h := range b.AllowSha256 {
		allow[strings.ToLower(h)] = true
	}
	s.mu.Lock()
	s.bad, s.pua, s.allow, s.Version = bad, pua, allow, b.SignatureVersion
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

// IsPUA reports whether a malicious hash is a potentially unwanted application rather than malware.
func (s *Scanner) IsPUA(sha string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pua[sha]
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
	// Member is the file inside an archive that matched (archive!member); the archive itself is quarantined.
	Member   string `json:"archiveMember,omitempty"`
	Category string `json:"category,omitempty"` // "pua" for potentially unwanted applications
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

// ScanPaths walks the given roots with default options (no archives, no throttling).
func (s *Scanner) ScanPaths(roots []string, skip []string, quarantine bool, maxFiles int) (scanned int, findings []Finding) {
	return s.ScanPathsWith(roots, skip, quarantine, maxFiles, ScanOptions{PUA: "block"})
}

// ScanPathsWith walks the given roots, hashing files (and archive members) and quarantining matches.
func (s *Scanner) ScanPathsWith(roots []string, skip []string, quarantine bool, maxFiles int, opts ScanOptions) (scanned int, findings []Finding) {
	skip = append(append([]string{}, skip...), "/proc", "/sys", "/dev", "/run", s.QuarantineDir)
	if opts.SkipNetwork {
		skip = append(skip, networkMounts()...)
	}
	skipped := func(path string) bool {
		for _, prefix := range skip {
			if prefix != "" && (path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")) {
				return true
			}
		}
		return false
	}
	throttle := newCPUThrottle(opts.CPULimitPercent)
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
			start := time.Now()
			defer func() { throttle.after(time.Since(start)) }()
			sha, err := HashFile(path, s.MaxFileBytes)
			if err != nil {
				return nil
			}
			scanned++
			bad, family, pua := s.classify(sha, path)
			inner := ""
			if !bad && opts.Archives {
				if hit := s.scanArchive(path, opts.MaxDepth); hit != nil {
					bad, family, pua, inner = true, hit.family, hit.pua, hit.member
				}
			}
			if bad && pua && opts.PUA == "off" {
				return nil
			}
			if bad {
				f := Finding{Path: path, SHA256: sha, Family: family, Action: "detected", Member: inner}
				if pua {
					f.Category = "pua"
				}
				if quarantine && !(pua && opts.PUA == "audit") {
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

// classify looks a hash up and, failing that, scores Windows executables with the ML model.
func (s *Scanner) classify(sha, path string) (bad bool, family string, pua bool) {
	bad, family = s.Verdict(sha)
	if bad {
		return true, family, s.IsPUA(sha)
	}
	if score, ok := s.MLScore(path); ok && score >= s.MLThreshold {
		return true, fmt.Sprintf("ML.Static.PE (score %.2f)", score), false
	}
	return false, "", false
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

// MLScore scores a Windows PE file with the static model. ok=false if not evaluated.
func (s *Scanner) MLScore(path string) (float64, bool) {
	s.mu.RLock()
	model, threshold := s.Model, s.MLThreshold
	s.mu.RUnlock()
	if model == nil || threshold <= 0 {
		return 0, false
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	magic := make([]byte, 2)
	_, err = io.ReadFull(f, magic)
	f.Close()
	if err != nil || magic[0] != 'M' || magic[1] != 'Z' {
		return 0, false
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > 64<<20 {
		return 0, false
	}
	data, err := os.ReadFile(path)
	if err != nil || !ml.IsPE(data) {
		return 0, false
	}
	return model.Score(ml.Extract(data)), true
}

func (s *Scanner) SetModel(model *ml.Model, threshold float64) {
	s.mu.Lock()
	s.Model, s.MLThreshold = model, threshold
	s.mu.Unlock()
}
