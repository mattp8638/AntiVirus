package fleet

// Network attack protection (policy firewall.networkAttackProtection) on Linux: kernel settings that stop common
// network attacks against the host. SYN cookies against SYN floods, reverse-path filtering against spoofed source
// addresses, no ICMP redirects or source-routed packets (traffic hijacking), no replies to broadcast pings (smurf
// amplification), and logging of impossible ("martian") addresses.
//
// The original values are saved before Fenrir changes anything, written back when the setting is turned off, and
// the settings are kept across reboots in /etc/sysctl.d. macOS is not covered.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// NetworkHardeningSysctls maps /proc/sys paths (relative) to the values network attack protection sets.
// Reverse-path filtering is "loose" (2), which still drops spoofed addresses but keeps multi-homed and VPN
// hosts working.
var NetworkHardeningSysctls = map[string]string{
	"net/ipv4/tcp_syncookies":                    "1",
	"net/ipv4/conf/all/rp_filter":                "2",
	"net/ipv4/conf/default/rp_filter":            "2",
	"net/ipv4/conf/all/accept_redirects":         "0",
	"net/ipv4/conf/default/accept_redirects":     "0",
	"net/ipv4/conf/all/secure_redirects":         "0",
	"net/ipv4/conf/default/secure_redirects":     "0",
	"net/ipv4/conf/all/accept_source_route":      "0",
	"net/ipv4/conf/default/accept_source_route":  "0",
	"net/ipv4/icmp_echo_ignore_broadcasts":       "1",
	"net/ipv4/icmp_ignore_bogus_error_responses": "1",
	"net/ipv4/conf/all/log_martians":             "1",
	"net/ipv6/conf/all/accept_redirects":         "0",
	"net/ipv6/conf/default/accept_redirects":     "0",
	"net/ipv6/conf/all/accept_source_route":      "0",
	"net/ipv6/conf/default/accept_source_route":  "0",
}

const netHardeningConf = "etc/sysctl.d/90-fenrir-network.conf"
const netHardeningSaved = "network-hardening-original.json"

// NetHardening applies or removes network attack protection. Roots are configurable so tests run anywhere.
type NetHardening struct {
	ProcRoot string // normally "/proc"
	EtcRoot  string // normally "/"
	StateDir string
}

func (n NetHardening) proc(key string) string { return filepath.Join(n.ProcRoot, "sys", key) }

func (n NetHardening) savedPath() string { return filepath.Join(n.StateDir, netHardeningSaved) }

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SysctlConf renders the /etc/sysctl.d file that keeps the settings across reboots.
func SysctlConf() string {
	var b strings.Builder
	b.WriteString("# Managed by Fenrir (network attack protection). Local edits are overwritten.\n")
	for _, key := range sortedKeys(NetworkHardeningSysctls) {
		b.WriteString(strings.ReplaceAll(key, "/", ".") + " = " + NetworkHardeningSysctls[key] + "\n")
	}
	return b.String()
}

// Enable saves the current values (once, so a later restore returns to what was there before Fenrir), sets the
// hardened values and writes the boot-time file. Keys this kernel does not have are skipped. Returns the keys
// changed.
func (n NetHardening) Enable() ([]string, error) {
	if _, err := os.Stat(n.savedPath()); errors.Is(err, os.ErrNotExist) {
		original := map[string]string{}
		for key := range NetworkHardeningSysctls {
			if data, err := os.ReadFile(n.proc(key)); err == nil {
				original[key] = strings.TrimSpace(string(data))
			}
		}
		data, _ := json.Marshal(original)
		if err := os.MkdirAll(n.StateDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(n.savedPath(), data, 0o600); err != nil {
			return nil, err
		}
	}
	var changed []string
	var failed []string
	for _, key := range sortedKeys(NetworkHardeningSysctls) {
		want := NetworkHardeningSysctls[key]
		data, err := os.ReadFile(n.proc(key))
		if err != nil {
			continue // not on this kernel (for example IPv6 disabled)
		}
		if strings.TrimSpace(string(data)) == want {
			continue
		}
		if err := os.WriteFile(n.proc(key), []byte(want), 0o644); err != nil {
			failed = append(failed, key)
			continue
		}
		changed = append(changed, key)
	}
	conf := filepath.Join(n.EtcRoot, netHardeningConf)
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err == nil {
		_ = os.WriteFile(conf, []byte(SysctlConf()), 0o644)
	}
	if len(failed) > 0 {
		return changed, errors.New("could not set " + strings.Join(failed, ", "))
	}
	return changed, nil
}

// Disable writes back the values saved before Fenrir changed them and removes the boot-time file. Does nothing if
// Fenrir never enabled it.
func (n NetHardening) Disable() ([]string, error) {
	data, err := os.ReadFile(n.savedPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	original := map[string]string{}
	if err := json.Unmarshal(data, &original); err != nil {
		return nil, err
	}
	var restored []string
	for _, key := range sortedKeys(original) {
		if _, managed := NetworkHardeningSysctls[key]; !managed {
			continue
		}
		if err := os.WriteFile(n.proc(key), []byte(original[key]), 0o644); err == nil {
			restored = append(restored, key)
		}
	}
	_ = os.Remove(filepath.Join(n.EtcRoot, netHardeningConf))
	return restored, os.Remove(n.savedPath())
}

// applyNetworkHardening keeps the host in step with firewall.networkAttackProtection (Linux only).
func (a *Agent) applyNetworkHardening() {
	if IsMacOS {
		return
	}
	on := a.state.Policy.ModuleBool("firewall", "networkAttackProtection", false)
	a.mu.Lock()
	unchanged := a.netHardeningSet && a.netHardeningOn == on
	a.mu.Unlock()
	if unchanged || a.cfg.DryRunIsolation {
		return
	}
	procRoot := a.cfg.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	n := NetHardening{ProcRoot: procRoot, EtcRoot: "/", StateDir: a.cfg.StateDir}
	var keys []string
	var err error
	if on {
		keys, err = n.Enable()
	} else {
		keys, err = n.Disable()
	}
	if err != nil {
		a.emit("firewall.network_protection_failed", "firewall", "Network attack protection could not be fully applied: "+err.Error(),
			map[string]interface{}{"enabled": on, "changed": keys})
	}
	a.mu.Lock()
	a.netHardeningOn, a.netHardeningSet = on, true
	a.mu.Unlock()
	if len(keys) > 0 {
		summary := "Network attack protection on: kernel network settings hardened"
		if !on {
			summary = "Network attack protection off: original kernel network settings restored"
		}
		a.emit("firewall.network_protection", "firewall", summary, map[string]interface{}{"enabled": on, "settings": keys})
	}
}
