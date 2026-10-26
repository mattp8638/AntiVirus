package fleet

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanPlan is a calendar scan schedule from the cloud policy ("daily 12:30" -> every day at minute
// 750), evaluated in the device's local time.
type ScanPlan struct {
	Off         bool  `json:"off"`
	Days        []int `json:"days"` // 0 = Monday .. 6 = Sunday
	MinuteOfDay int   `json:"minuteOfDay"`
}

// scanPlan reads modules.antimalware.<key>; nil when the policy has no usable schedule.
func scanPlan(modules map[string]map[string]interface{}, key string) *ScanPlan {
	raw, ok := modules["antimalware"][key]
	if !ok {
		return nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var plan ScanPlan
	if json.Unmarshal(data, &plan) != nil {
		return nil
	}
	days := plan.Days[:0]
	for _, d := range plan.Days {
		if d >= 0 && d <= 6 {
			days = append(days, d)
		}
	}
	plan.Days = days
	if plan.MinuteOfDay < 0 || plan.MinuteOfDay >= 24*60 || (!plan.Off && len(plan.Days) == 0) {
		return nil
	}
	return &plan
}

// latestSlot is the most recent scheduled time at or before now (looking back a week).
func latestSlot(plan *ScanPlan, now time.Time) (time.Time, bool) {
	if plan == nil || plan.Off {
		return time.Time{}, false
	}
	for back := 0; back <= 7; back++ {
		day := now.AddDate(0, 0, -back)
		weekday := (int(day.Weekday()) + 6) % 7 // Go: 0 = Sunday
		wanted := false
		for _, d := range plan.Days {
			if d == weekday {
				wanted = true
				break
			}
		}
		if !wanted {
			continue
		}
		slot := time.Date(day.Year(), day.Month(), day.Day(), plan.MinuteOfDay/60, plan.MinuteOfDay%60, 0, 0, now.Location())
		if !slot.After(now) {
			return slot, true
		}
	}
	return time.Time{}, false
}

// scanDue: run once per slot, catching up a slot missed while the device was off.
func scanDue(plan *ScanPlan, last, now time.Time) bool {
	slot, ok := latestSlot(plan, now)
	return ok && last.Before(slot)
}

// scanSchedule remembers when each scheduled scan last ran (its own file, so the background scan
// never races the main state file).
type scanSchedule struct {
	mu   sync.Mutex
	path string
	Last map[string]time.Time `json:"last"`
	busy atomic.Bool
}

func loadScanSchedule(stateDir string) *scanSchedule {
	s := &scanSchedule{path: filepath.Join(stateDir, "scan-schedule.json"), Last: map[string]time.Time{}}
	if data, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(data, s)
		if s.Last == nil {
			s.Last = map[string]time.Time{}
		}
	}
	return s
}

func (s *scanSchedule) last(kind string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Last[kind]
}

func (s *scanSchedule) record(kind string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Last[kind] = at
	data, _ := json.Marshal(s)
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (a *Agent) quickScanRoots() []string {
	if IsMacOS {
		return macQuickScanRoots()
	}
	return append([]string{"/tmp", "/var/tmp", "/dev/shm"}, homeDirs()...)
}

// runScan scans roots and reports every finding; shared by commands and scheduled scans.
// The policy's CPU limit applies to scheduled scans only; an analyst's scan runs at full speed.
func (a *Agent) runScan(roots, skip []string, quarantine, scheduled bool) (int, []Finding) {
	opts := ScanOptionsFromPolicy(a.state.Policy)
	if !scheduled {
		opts.CPULimitPercent = 100
	}
	scanned, findings := a.scanner.ScanPathsWith(roots, skip, quarantine, 0, opts)
	for _, f := range findings {
		summary, score := "Malware found: "+f.Family, 95
		if f.Category == "pua" {
			summary, score = "Potentially unwanted application found: "+f.Family, 60
		}
		payload := map[string]interface{}{"path": f.Path, "sha256": f.SHA256, "threatName": f.Family, "verdict": f.Action, "score": score, "recordId": f.Record}
		if f.Member != "" {
			payload["archiveMember"] = f.Member
			summary += " (inside the archive, as " + f.Member + ")"
		}
		if f.Category != "" {
			payload["category"] = f.Category
		}
		a.emit("scan.threat."+strings.SplitN(f.Action, ":", 2)[0], "scanner", summary, payload)
	}
	return scanned, findings
}

// maybeScheduledScans starts the policy's quick or full scan in the background when its slot is due.
// One scheduled scan runs at a time; a full scan also counts as that slot's quick scan.
func (a *Agent) maybeScheduledScans(now time.Time) {
	if a.schedule == nil || a.schedule.busy.Load() {
		return
	}
	policy := a.state.Policy
	for _, kind := range []string{"full", "quick"} {
		plan := scanPlan(policy.Modules, kind+"ScanPlan")
		if !scanDue(plan, a.schedule.last(kind), now) {
			continue
		}
		roots := a.quickScanRoots()
		if kind == "full" {
			roots = []string{"/"}
		}
		skip := append([]string(nil), policy.SuppressionPathRoots...)
		quarantine := policy.QuarantineOnMalicious
		a.schedule.busy.Store(true)
		go func(kind string) {
			defer a.schedule.busy.Store(false)
			started := time.Now()
			scanned, findings := a.runScan(roots, skip, quarantine, true)
			a.schedule.record(kind, started)
			if kind == "full" {
				a.schedule.record("quick", started)
			}
			a.emit("scan.completed", "scan."+kind+"-scheduled", "Scheduled "+kind+" scan completed",
				map[string]interface{}{"scope": kind, "targetCount": scanned, "findingCount": len(findings)})
			log.Printf("scheduled %s scan: %d files, %d findings", kind, scanned, len(findings))
		}(kind)
		return
	}
}
