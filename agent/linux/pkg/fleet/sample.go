package fleet

// sample.collect: upload one quarantined file to the cloud for sandbox analysis, after a technician approved the
// submission there. The file is read from quarantine only (never from its original path) and its SHA-256 must match
// the quarantine record before anything is sent.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const sampleMaxBytes = 32 << 20

// Sample returns the bytes of a quarantined file after checking them against the record.
func (s *Scanner) Sample(id, wantSHA string) ([]byte, error) {
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return nil, errors.New("invalid record id")
	}
	data, err := os.ReadFile(filepath.Join(s.QuarantineDir, id+".json"))
	if err != nil {
		return nil, errors.New("no such quarantine record")
	}
	var record QuarantineRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if wantSHA != "" && !strings.EqualFold(wantSHA, record.SHA256) {
		return nil, errors.New("the quarantine record is for a different file")
	}
	path := filepath.Join(s.QuarantineDir, id+".bin")
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrPermission) {
		// Quarantine leaves the file with no permissions (mode 0). Root reads it anyway; an agent running without
		// root (and the tests in CI) grants itself read access for this one read and takes it away again.
		if os.Chmod(path, 0o400) == nil {
			defer os.Chmod(path, 0)
			f, err = os.Open(path)
		}
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, sampleMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > sampleMaxBytes {
		return nil, errors.New("the file is larger than 32 MB")
	}
	sum := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), record.SHA256) {
		return nil, errors.New("the quarantined file does not match its recorded SHA-256")
	}
	return body, nil
}

// SampleCollect reads the sample named in the payload and uploads it as the command's artifact.
func SampleCollect(payloadJSON string, scanner *Scanner, upload func(name string, data []byte) (string, error)) (map[string]interface{}, error) {
	var p struct {
		RecordID string `json:"recordId"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil || p.RecordID == "" || len(p.SHA256) != 64 {
		return nil, errors.New("sample.collect needs a quarantine record and its SHA-256")
	}
	body, err := scanner.Sample(p.RecordID, p.SHA256)
	if err != nil {
		return nil, err
	}
	id, err := upload(strings.ToLower(p.SHA256)+".sample", body)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"artifactId": id, "bytes": len(body), "sha256": strings.ToLower(p.SHA256)}, nil
}
