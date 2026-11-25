package fleet

// fim.scan: file integrity monitoring. The agent hashes the files under the paths the cloud names (bounded) and
// returns a manifest of SHA-256, size, mode, owner and modification time. The cloud keeps the baseline and works out
// what was added, removed or changed, so the agent keeps no state and an attacker on the device cannot edit the
// baseline.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const fimMaxFiles = 5000
const fimMaxFileBytes = 64 << 20

// FimDefaultPaths are watched when the policy names none.
var FimDefaultPaths = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config",
	"/etc/crontab", "/etc/cron.d", "/etc/hosts", "/etc/ld.so.preload", "/etc/pam.d", "/etc/systemd/system", "/root/.ssh/authorized_keys"}

// FimScanContext returns {"files": [{path, sha256, size, mode, uid, gid, mtime}], "truncated": bool, "errors": [...]}.
func FimScanContext(ctx context.Context, payloadJSON string) (map[string]interface{}, error) {
	var p struct {
		Paths []string `json:"paths"`
	}
	_ = json.Unmarshal([]byte(payloadJSON), &p)
	paths := p.Paths
	if len(paths) == 0 {
		paths = FimDefaultPaths
	}
	if len(paths) > 200 {
		return nil, errors.New("at most 200 watched paths")
	}
	files := []map[string]interface{}{}
	errs := []string{}
	truncated := false
	for _, root := range paths {
		if !filepath.IsAbs(root) || strings.Contains(root, "..") {
			errs = append(errs, root+": not an absolute path")
			continue
		}
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, path+": "+err.Error())
				}
				return nil
			}
			if d.IsDir() || d.Type()&fs.ModeSymlink != 0 && path != root {
				return nil
			}
			if len(files) >= fimMaxFiles {
				truncated = true
				return fs.SkipAll
			}
			entry, ferr := fimEntry(path)
			if ferr != nil {
				errs = append(errs, path+": "+ferr.Error())
				return nil
			}
			files = append(files, entry)
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
			return nil, walkErr
		}
	}
	if len(errs) > 50 {
		errs = errs[:50]
	}
	return map[string]interface{}{"files": files, "truncated": truncated, "errors": errs}, nil
}

func fimEntry(path string) (map[string]interface{}, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	entry := map[string]interface{}{"path": path, "size": info.Size(), "mode": info.Mode().String(), "mtime": info.ModTime().UTC().Unix()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		entry["uid"], entry["gid"] = st.Uid, st.Gid
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, _ := os.Readlink(path)
		entry["link"] = target
		return entry, nil
	}
	if !info.Mode().IsRegular() {
		return entry, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, fimMaxFileBytes)); err != nil {
		return nil, err
	}
	entry["sha256"] = hex.EncodeToString(h.Sum(nil))
	return entry, nil
}
