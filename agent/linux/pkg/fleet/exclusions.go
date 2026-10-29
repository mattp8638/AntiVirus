package fleet

import (
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Strict EDR exclusions (cloud: edr_exclusions.py). A process-chain rule trusts a child only when its
// parent's image path *and* SHA-256 match; a hash rule trusts one exact file. Paths compare
// case-insensitively, "/" and "\" alike, with wildcards allowed only in the final path component.

type ExclusionRule struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind"`
	ParentImage         string   `json:"parentImage"`
	ParentSha256        []string `json:"parentSha256"`
	ChildImage          string   `json:"childImage"`
	ChildSha256         []string `json:"childSha256"`
	CommandLineContains string   `json:"commandLineContains"`
	Scopes              []string `json:"scopes"`
}

func (r ExclusionRule) HasScope(scope string) bool {
	for _, s := range r.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// EdrExclusions reads modules.edrExclusions.rules from the policy.
func (p Policy) EdrExclusions() []ExclusionRule {
	raw, _ := p.Modules["edrExclusions"]["rules"].([]interface{})
	out := make([]ExclusionRule, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		str := func(key string) string { s, _ := m[key].(string); return s }
		list := func(key string) []string {
			values, _ := m[key].([]interface{})
			res := make([]string, 0, len(values))
			for _, v := range values {
				if s, ok := v.(string); ok {
					res = append(res, strings.ToLower(s))
				}
			}
			return res
		}
		out = append(out, ExclusionRule{ID: str("id"), Kind: str("kind"), ParentImage: str("parentImage"), ParentSha256: list("parentSha256"),
			ChildImage: str("childImage"), ChildSha256: list("childSha256"), CommandLineContains: str("commandLineContains"),
			Scopes: list("scopes")})
	}
	return out
}

func normalisePath(p string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
}

// ExclusionPathMatches compares a rule pattern with a real path; the directory part must be identical.
func ExclusionPathMatches(pattern, actual string) bool {
	if pattern == "" {
		return true
	}
	want, have := normalisePath(pattern), normalisePath(actual)
	if have == "" {
		return false
	}
	wantDir, wantName := splitLast(want)
	haveDir, haveName := splitLast(have)
	if wantDir != haveDir {
		return false
	}
	ok, err := path.Match(strings.ReplaceAll(wantName, "[", "\\["), haveName)
	return err == nil && ok
}

func splitLast(p string) (string, string) {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

func containsHash(list []string, sha string) bool {
	if sha == "" {
		return false
	}
	sha = strings.ToLower(sha)
	for _, h := range list {
		if h == sha {
			return true
		}
	}
	return false
}

// ExclusionMatches reports whether one rule covers a process. Missing hashes never match.
func ExclusionMatches(r ExclusionRule, image, sha, parentImage, parentSha, commandLine string) bool {
	if r.ChildImage != "" && !ExclusionPathMatches(r.ChildImage, image) {
		return false
	}
	if len(r.ChildSha256) > 0 && !containsHash(r.ChildSha256, sha) {
		return false
	}
	if needle := strings.ToLower(r.CommandLineContains); needle != "" && !strings.Contains(strings.ToLower(commandLine), needle) {
		return false
	}
	if r.Kind == "hash" {
		return len(r.ChildSha256) > 0
	}
	return r.ParentImage != "" && ExclusionPathMatches(r.ParentImage, parentImage) && containsHash(r.ParentSha256, parentSha)
}

// MatchExclusion returns the first rule with the scope that covers the process.
func MatchExclusion(rules []ExclusionRule, scope, image, sha, parentImage, parentSha, commandLine string) *ExclusionRule {
	for i := range rules {
		if rules[i].HasScope(scope) && ExclusionMatches(rules[i], image, sha, parentImage, parentSha, commandLine) {
			return &rules[i]
		}
	}
	return nil
}

// NeedsParentHash: hash the parent only when some rule names its path (hashing every parent is wasteful).
func NeedsParentHash(rules []ExclusionRule, parentImage string) bool {
	for _, r := range rules {
		if r.Kind != "hash" && r.ParentImage != "" && ExclusionPathMatches(r.ParentImage, parentImage) {
			return true
		}
	}
	return false
}

// hashCache remembers file hashes by (path, size, mtime): RMM agents start many children.
type hashCache struct {
	mu      sync.Mutex
	entries map[string]hashEntry
}

type hashEntry struct {
	size  int64
	mtime time.Time
	sha   string
}

func (c *hashCache) Hash(p string, limit int64) string {
	info, err := os.Stat(p)
	if err != nil {
		return ""
	}
	c.mu.Lock()
	if e, ok := c.entries[p]; ok && e.size == info.Size() && e.mtime.Equal(info.ModTime()) {
		c.mu.Unlock()
		return e.sha
	}
	c.mu.Unlock()
	sha, err := HashFile(p, limit)
	if err != nil {
		return ""
	}
	c.mu.Lock()
	if c.entries == nil || len(c.entries) > 4096 {
		c.entries = map[string]hashEntry{}
	}
	c.entries[p] = hashEntry{info.Size(), info.ModTime(), sha}
	c.mu.Unlock()
	return sha
}
