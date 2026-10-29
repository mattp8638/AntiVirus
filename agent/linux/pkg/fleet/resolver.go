package fleet

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Pointing the operating system's resolver at the local DNS proxy, and putting it back.
//
// Linux with systemd-resolved: a drop-in sets the proxy as the global server with the "~." routing
// domain, then resolved restarts. Plain Linux: /etc/resolv.conf is backed up and replaced.
// macOS: every network service's DNS servers are set with networksetup and the old values saved.
// A marker in the agent state directory records the change, so a crash or forced stop is undone at
// the next start even if the proxy is no longer wanted.

var (
	resolvConfPath       = "/etc/resolv.conf"
	resolvedDropInDir    = "/etc/systemd/resolved.conf.d"
	resolvedUpstreamPath = "/run/systemd/resolve/resolv.conf"
	runResolverCommand   = func(name string, args ...string) ([]byte, error) { return exec.Command(name, args...).CombinedOutput() }
)

const resolverMarker = "dns-resolver-change.json"

type resolverChange struct {
	Mode       string            `json:"mode"` // resolved | resolv.conf | macos
	StateDir   string            `json:"-"`
	Backup     string            `json:"backup,omitempty"`     // previous resolv.conf content
	WasSymlink string            `json:"wasSymlink,omitempty"` // previous resolv.conf symlink target
	MacDNS     map[string]string `json:"macDns,omitempty"`     // network service -> previous servers ("Empty" = DHCP)
}

func readNameservers(path string, skip string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" && fields[1] != skip && net.ParseIP(fields[1]) != nil {
			out = append(out, net.JoinHostPort(fields[1], "53"))
		}
	}
	return out
}

func resolvedActive() bool {
	target, err := os.Readlink(resolvConfPath)
	return err == nil && strings.Contains(target, "systemd/resolve") && fileExists(resolvedUpstreamPath)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// systemResolvers returns the real upstream servers, ignoring the proxy and resolved's own stub.
func systemResolvers(proxyAddr string) []string {
	var servers []string
	if resolvedActive() {
		servers = readNameservers(resolvedUpstreamPath, proxyAddr)
	} else {
		servers = readNameservers(resolvConfPath, proxyAddr)
	}
	out := servers[:0]
	for _, s := range servers {
		if !strings.HasPrefix(s, "127.0.0.53:") {
			out = append(out, s)
		}
	}
	return out
}

func pointResolverAt(stateDir, proxyAddr string) (*resolverChange, error) {
	if IsMacOS {
		return pointMacResolverAt(stateDir, proxyAddr)
	}
	change := &resolverChange{StateDir: stateDir}
	if resolvedActive() {
		change.Mode = "resolved"
		if err := os.MkdirAll(resolvedDropInDir, 0o755); err != nil {
			return nil, err
		}
		conf := "# Managed by the Fenrir agent (dns.localProxy). Removed when the proxy is turned off.\n[Resolve]\nDNS=" + proxyAddr + "\nDomains=~.\n"
		if err := os.WriteFile(filepath.Join(resolvedDropInDir, "90-fenrir-dns-proxy.conf"), []byte(conf), 0o644); err != nil {
			return nil, err
		}
		if out, err := runResolverCommand("systemctl", "restart", "systemd-resolved"); err != nil {
			_ = os.Remove(filepath.Join(resolvedDropInDir, "90-fenrir-dns-proxy.conf"))
			return nil, fmt.Errorf("restart systemd-resolved: %v %s", err, out)
		}
	} else {
		change.Mode = "resolv.conf"
		if target, err := os.Readlink(resolvConfPath); err == nil {
			change.WasSymlink = target
		} else if data, err := os.ReadFile(resolvConfPath); err == nil {
			change.Backup = string(data)
		}
		conf := "# Managed by the Fenrir agent (dns.localProxy). The previous file is restored when the proxy is turned off.\nnameserver " +
			proxyAddr + "\noptions edns0 trust-ad\n"
		tmp := resolvConfPath + ".fenrir-tmp"
		if err := os.WriteFile(tmp, []byte(conf), 0o644); err != nil {
			return nil, err
		}
		_ = os.Remove(resolvConfPath)
		if err := os.Rename(tmp, resolvConfPath); err != nil {
			return nil, err
		}
	}
	return change, change.save()
}

func (c *resolverChange) save() error {
	data, _ := json.Marshal(c)
	return os.WriteFile(filepath.Join(c.StateDir, resolverMarker), data, 0o600)
}

// Restore undoes the change and removes the marker.
func (c *resolverChange) Restore() error {
	var err error
	switch c.Mode {
	case "resolved":
		_ = os.Remove(filepath.Join(resolvedDropInDir, "90-fenrir-dns-proxy.conf"))
		if out, e := runResolverCommand("systemctl", "restart", "systemd-resolved"); e != nil {
			err = fmt.Errorf("restart systemd-resolved: %v %s", e, out)
		}
	case "resolv.conf":
		_ = os.Remove(resolvConfPath)
		if c.WasSymlink != "" {
			err = os.Symlink(c.WasSymlink, resolvConfPath)
		} else {
			err = os.WriteFile(resolvConfPath, []byte(c.Backup), 0o644)
		}
	case "macos":
		for service, servers := range c.MacDNS {
			args := append([]string{"-setdnsservers", service}, strings.Fields(servers)...)
			if out, e := runResolverCommand("networksetup", args...); e != nil {
				err = fmt.Errorf("networksetup %s: %v %s", service, e, out)
			}
		}
	}
	if err == nil {
		_ = os.Remove(filepath.Join(c.StateDir, resolverMarker))
	}
	return err
}

// restoreStaleResolver undoes a change left behind by a crash or a forced stop.
func restoreStaleResolver(stateDir string) {
	data, err := os.ReadFile(filepath.Join(stateDir, resolverMarker))
	if err != nil {
		return
	}
	var change resolverChange
	if json.Unmarshal(data, &change) != nil {
		return
	}
	change.StateDir = stateDir
	_ = change.Restore()
}

func pointMacResolverAt(stateDir, proxyAddr string) (*resolverChange, error) {
	out, err := runResolverCommand("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("networksetup: %v", err)
	}
	change := &resolverChange{Mode: "macos", StateDir: stateDir, MacDNS: map[string]string{}}
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		service := strings.TrimSpace(line)
		if i == 0 || service == "" || strings.HasPrefix(service, "*") { // header line; "*" marks a disabled service
			continue
		}
		previous, _ := runResolverCommand("networksetup", "-getdnsservers", service)
		servers := "Empty"
		if text := strings.TrimSpace(string(previous)); !strings.Contains(text, "aren't any") && text != "" {
			servers = strings.Join(strings.Fields(text), " ")
		}
		change.MacDNS[service] = servers
		if _, err := runResolverCommand("networksetup", "-setdnsservers", service, proxyAddr); err != nil {
			continue
		}
	}
	return change, change.save()
}

// ensureLoopbackAliases: Linux answers on all of 127/8; macOS only on 127.0.0.1 unless aliased.
func ensureLoopbackAliases(addrs ...string) error {
	if !IsMacOS {
		return nil
	}
	for _, addr := range addrs {
		if out, err := runResolverCommand("ifconfig", "lo0", "alias", addr, "up"); err != nil {
			return fmt.Errorf("lo0 alias %s: %v %s", addr, err, out)
		}
	}
	return nil
}
