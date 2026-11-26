package fleet

// First-seen record for applicationControl.blockNewlySeenExecutables: when this device first saw each program
// (by SHA-256). Kept on disk so a restart does not make every program "new" again, and capped so it cannot grow
// without limit (the oldest entries go first; a program that old is no longer new anyway).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// NewlySeenWindow is how long a program counts as newly seen.
const NewlySeenWindow = 24 * time.Hour

const firstSeenMax = 50000

type FirstSeenStore struct {
	mu    sync.Mutex
	path  string
	seen  map[string]int64 // sha256 (lower case) -> first seen, unix seconds
	dirty bool
}

func OpenFirstSeen(stateDir string) *FirstSeenStore {
	s := &FirstSeenStore{path: filepath.Join(stateDir, "first-seen.json"), seen: map[string]int64{}}
	if data, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(data, &s.seen)
	}
	return s
}

// Observe records sha if it is new and returns when it was first seen.
func (s *FirstSeenStore) Observe(sha string, now time.Time) time.Time {
	sha = strings.ToLower(sha)
	s.mu.Lock()
	defer s.mu.Unlock()
	if at, ok := s.seen[sha]; ok {
		return time.Unix(at, 0)
	}
	s.seen[sha] = now.Unix()
	s.dirty = true
	if len(s.seen) > firstSeenMax {
		type entry struct {
			sha string
			at  int64
		}
		all := make([]entry, 0, len(s.seen))
		for k, v := range s.seen {
			all = append(all, entry{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].at < all[j].at })
		for _, e := range all[:len(all)-firstSeenMax] {
			delete(s.seen, e.sha)
		}
	}
	return now
}

// Save writes the record if it changed.
func (s *FirstSeenStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	data, err := json.Marshal(s.seen)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// NewlySeen reports whether a program first seen at firstSeen is still within the newly seen window at now.
func NewlySeen(firstSeen, now time.Time) bool {
	return !firstSeen.IsZero() && now.Sub(firstSeen) < NewlySeenWindow
}
