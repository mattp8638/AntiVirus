package fleet

// antimalware.scanRemovableMedia on Linux and macOS: a newly mounted USB drive or memory card
// (under /media, /run/media or /Volumes) is scanned once, in the background.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type removableWatch struct {
	known   map[string]bool
	primed  bool
	pending []string
}

// removableMountsFrom lists mount points of removable media from /proc/self/mounts content.
func removableMountsFrom(mounts string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(mounts))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		// Mount points escape spaces as \040.
		point := strings.ReplaceAll(fields[1], `\040`, " ")
		if (strings.HasPrefix(point, "/media/") || strings.HasPrefix(point, "/run/media/")) && !networkFS[fields[2]] {
			out = append(out, point)
		}
	}
	sort.Strings(out)
	return out
}

var networkFS = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "sshfs": true,
	"fuse.sshfs": true, "afs": true, "9p": true, "davfs": true, "fuse.davfs2": true}

func removableMounts() []string {
	if IsMacOS {
		entries, err := os.ReadDir("/Volumes")
		if err != nil {
			return nil
		}
		var out []string
		for _, e := range entries {
			// The startup disk appears as a symlink to /; skip it and anything that is not a directory.
			if e.Type()&os.ModeSymlink != 0 || !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			out = append(out, filepath.Join("/Volumes", e.Name()))
		}
		return out
	}
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil
	}
	return removableMountsFrom(string(data))
}

// newRemovable updates the watch with the current mounts and returns those not seen before.
// Media already mounted when the agent starts are not scanned (they would be rescanned on every restart).
func (w *removableWatch) newRemovable(current []string) []string {
	seen := map[string]bool{}
	var fresh []string
	for _, m := range current {
		seen[m] = true
		if w.primed && !w.known[m] {
			fresh = append(fresh, m)
		}
	}
	w.known, w.primed = seen, true
	return fresh
}

func (a *Agent) checkRemovableMedia(now time.Time) {
	if a.media == nil {
		a.media = &removableWatch{}
	}
	fresh := a.media.newRemovable(removableMounts())
	if !a.state.Policy.ModuleBool("antimalware", "scanRemovableMedia", true) {
		a.media.pending = nil
		return
	}
	a.media.pending = append(a.media.pending, fresh...)
	// Drop media unplugged before their scan started.
	kept := a.media.pending[:0]
	for _, m := range a.media.pending {
		if a.media.known[m] {
			kept = append(kept, m)
		}
	}
	a.media.pending = kept
	if len(a.media.pending) == 0 || a.schedule == nil || !a.schedule.busy.CompareAndSwap(false, true) {
		return // one scan at a time; try again next tick
	}
	root := a.media.pending[0]
	a.media.pending = a.media.pending[1:]
	skip := append([]string(nil), a.state.Policy.SuppressionPathRoots...)
	quarantine := a.state.Policy.QuarantineOnMalicious
	a.emit("scan.removable.started", "scanner", "Scanning newly inserted media "+root, map[string]interface{}{"path": root})
	go func() {
		defer a.schedule.busy.Store(false)
		scanned, findings := a.runScan([]string{root}, skip, quarantine, false)
		a.emit("scan.removable.completed", "scanner", "Scanned newly inserted media "+root,
			map[string]interface{}{"path": root, "targetCount": scanned, "findingCount": len(findings)})
	}()
}
