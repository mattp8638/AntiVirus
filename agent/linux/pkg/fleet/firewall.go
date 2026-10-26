package fleet

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Policy firewall (modules.firewall): default inbound/outbound behaviour and custom rules.
// Linux uses its own nftables table so it never edits the distribution's firewall (ufw, firewalld);
// macOS uses a pf anchor next to the isolation one and switches on the application firewall.
//
// Safeguards: loopback, replies to existing connections, DHCP, ICMP (IPv6 needs it) and DNS always pass,
// and the Fenrir Cloud address stays reachable when outbound traffic is blocked. On Linux and macOS
// inbound SSH stays open unless a custom rule blocks port 22, so a default-block policy cannot lock
// administrators out.

// FirewallRule is one parsed custom rule, as the cloud sends it in modules.firewall.parsedRules.
type FirewallRule struct {
	Action    string   // allow | block
	Direction string   // in | out
	Protocol  string   // tcp | udp | any
	Ports     [][2]int // empty: any port
	Remote    []string // empty: any address
}

// FirewallPlan is what the policy asks for once validated.
type FirewallPlan struct {
	Enabled       bool
	BlockInbound  bool
	BlockOutbound bool
	Rules         []FirewallRule
}

// Active reports whether the plan changes anything; an inactive plan removes Fenrir's rules.
func (p FirewallPlan) Active() bool {
	return p.Enabled && (p.BlockInbound || p.BlockOutbound || len(p.Rules) > 0)
}

// FirewallPlanFromPolicy reads modules.firewall, dropping any rule that fails validation.
func FirewallPlanFromPolicy(p Policy) FirewallPlan {
	plan := FirewallPlan{Enabled: p.ModuleBool("firewall", "enabled", false)}
	// Default actions are opt-in on Linux and macOS: blocking inbound by default would cut off services a
	// server offers the moment the agent upgrades.
	if p.ModuleBool("firewall", "defaultsOnLinuxMac", false) {
		plan.BlockInbound = p.ModuleString("firewall", "defaultInbound", "allow") == "block"
		plan.BlockOutbound = p.ModuleString("firewall", "defaultOutbound", "allow") == "block"
	}
	raw, _ := p.Modules["firewall"]["parsedRules"].([]interface{})
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if rule, ok := firewallRuleFromJSON(m); ok {
			plan.Rules = append(plan.Rules, rule)
		}
	}
	return plan
}

func firewallRuleFromJSON(m map[string]interface{}) (FirewallRule, bool) {
	r := FirewallRule{}
	r.Action, _ = m["action"].(string)
	r.Direction, _ = m["direction"].(string)
	r.Protocol, _ = m["protocol"].(string)
	if (r.Action != "allow" && r.Action != "block") || (r.Direction != "in" && r.Direction != "out") ||
		(r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "any") {
		return r, false
	}
	ports, _ := m["ports"].([]interface{})
	for _, item := range ports {
		pair, _ := item.([]interface{})
		if len(pair) != 2 {
			return r, false
		}
		lo, ok1 := pair[0].(float64)
		hi, ok2 := pair[1].(float64)
		if !ok1 || !ok2 || lo < 1 || hi > 65535 || lo > hi || lo != float64(int(lo)) || hi != float64(int(hi)) {
			return r, false
		}
		r.Ports = append(r.Ports, [2]int{int(lo), int(hi)})
	}
	if len(r.Ports) > 0 && r.Protocol == "any" {
		return r, false
	}
	remote, _ := m["remote"].([]interface{})
	for _, item := range remote {
		s, _ := item.(string)
		if !validAddress(s) {
			return r, false
		}
		r.Remote = append(r.Remote, s)
	}
	return r, true
}

func validAddress(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func isIPv6(s string) bool { return strings.Contains(s, ":") }

func (r FirewallRule) blocksPort(port int) bool {
	if r.Action != "block" || r.Direction != "in" || r.Protocol == "udp" || len(r.Remote) > 0 {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p[0] <= port && port <= p[1] {
			return true
		}
	}
	return false
}

func (p FirewallPlan) keepSSH() bool {
	for _, r := range p.Rules {
		if r.blocksPort(22) {
			return false
		}
	}
	return true
}

// orderedRules puts block rules first so they win over allow rules, as on Windows.
func (p FirewallPlan) orderedRules() []FirewallRule {
	var out []FirewallRule
	for _, action := range []string{"block", "allow"} {
		for _, r := range p.Rules {
			if r.Action == action {
				out = append(out, r)
			}
		}
	}
	return out
}

func portList(ports [][2]int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p[0] == p[1] {
			parts = append(parts, fmt.Sprint(p[0]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", p[0], p[1]))
		}
	}
	return strings.Join(parts, ", ")
}

// NftFirewallRuleset renders the plan as an nftables script that atomically replaces table inet fenrir_policy.
// It returns "" when the plan is inactive (the table should be deleted).
func NftFirewallRuleset(p FirewallPlan, controlPlane []string) string {
	if !p.Active() {
		return ""
	}
	verdict := map[string]string{"allow": "accept", "block": "drop"}
	policy := func(block bool) string {
		if block {
			return "drop"
		}
		return "accept"
	}
	var b strings.Builder
	b.WriteString("add table inet fenrir_policy\ndelete table inet fenrir_policy\ntable inet fenrir_policy {\n")
	for _, dir := range []string{"in", "out"} {
		block := p.BlockInbound
		hook, iface, addrKey := "input", "iifname", "saddr"
		if dir == "out" {
			block, hook, iface, addrKey = p.BlockOutbound, "output", "oifname", "daddr"
		}
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority 0; policy %s;\n", dir, hook, policy(block))
		fmt.Fprintf(&b, "    %s \"lo\" accept\n    ct state established,related accept\n", iface)
		// Explicit block rules come before the safeguards so an administrator can still close a port on purpose.
		for _, r := range p.orderedRules() {
			if r.Direction != dir || r.Action != "block" {
				continue
			}
			writeNftRule(&b, r, addrKey, verdict[r.Action])
		}
		b.WriteString("    meta l4proto { icmp, ipv6-icmp } accept\n")
		if dir == "in" {
			b.WriteString("    udp sport 67 udp dport 68 accept\n    udp sport 547 udp dport 546 accept\n")
			if block && p.keepSSH() {
				b.WriteString("    tcp dport 22 accept\n")
			}
		} else {
			b.WriteString("    udp dport { 53, 67, 123, 547 } accept\n    tcp dport 53 accept\n")
			if block {
				for _, addr := range controlPlane {
					family := "ip"
					if isIPv6(addr) {
						family = "ip6"
					}
					fmt.Fprintf(&b, "    %s daddr %s accept\n", family, addr)
				}
			}
		}
		for _, r := range p.orderedRules() {
			if r.Direction != dir || r.Action != "allow" {
				continue
			}
			writeNftRule(&b, r, addrKey, verdict[r.Action])
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func writeNftRule(b *strings.Builder, r FirewallRule, addrKey, verdict string) {
	// nftables cannot mix IPv4 and IPv6 in one set, so split the remote list by family.
	var v4, v6 []string
	for _, addr := range r.Remote {
		if isIPv6(addr) {
			v6 = append(v6, addr)
		} else {
			v4 = append(v4, addr)
		}
	}
	match := ""
	switch {
	case r.Protocol != "any" && len(r.Ports) > 0:
		match = fmt.Sprintf("%s dport { %s } ", r.Protocol, portList(r.Ports))
	case r.Protocol != "any":
		match = fmt.Sprintf("meta l4proto %s ", r.Protocol)
	}
	if len(r.Remote) == 0 {
		fmt.Fprintf(b, "    %s%s\n", match, verdict)
		return
	}
	if len(v4) > 0 {
		fmt.Fprintf(b, "    ip %s { %s } %s%s\n", addrKey, strings.Join(v4, ", "), match, verdict)
	}
	if len(v6) > 0 {
		fmt.Fprintf(b, "    ip6 %s { %s } %s%s\n", addrKey, strings.Join(v6, ", "), match, verdict)
	}
}

// PFPolicyAnchor sits beside the isolation anchor under com.apple/*, which macOS's /etc/pf.conf evaluates.
const PFPolicyAnchor = "com.apple/fenrir-policy"

// PFFirewallRules renders the plan for pf. pf uses the last matching rule unless a rule says quick, so the
// defaults come first and everything else is quick. Returns "" when the plan is inactive.
func PFFirewallRules(p FirewallPlan, controlPlane []string) string {
	if !p.Active() {
		return ""
	}
	var b strings.Builder
	// Without a stateful pass, replies to our own outbound connections would hit "block in".
	if p.BlockOutbound {
		b.WriteString("block drop out all\n")
	} else {
		b.WriteString("pass out all keep state\n")
	}
	if p.BlockInbound {
		b.WriteString("block drop in all\n")
	}
	b.WriteString("pass quick on lo0 all\n")
	for _, r := range p.orderedRules() {
		if r.Action == "block" {
			writePFRule(&b, r)
		}
	}
	b.WriteString("pass in quick inet proto icmp all\npass in quick inet6 proto icmp6 all\npass out quick inet6 proto icmp6 all\n")
	b.WriteString("pass in quick proto udp from any port { 67, 547 } to any port { 68, 546 }\n")
	b.WriteString("pass in quick proto udp from any to any port 5353\n") // Bonjour
	if p.BlockInbound && p.keepSSH() {
		b.WriteString("pass in quick proto tcp from any to any port 22 keep state\n")
	}
	if p.BlockOutbound {
		b.WriteString("pass out quick proto { tcp udp } from any to any port 53 keep state\n")
		b.WriteString("pass out quick proto udp from any to any port { 67, 123, 547, 5353 } keep state\n")
		for _, addr := range controlPlane {
			family := "inet"
			if isIPv6(addr) {
				family = "inet6"
			}
			fmt.Fprintf(&b, "pass out quick %s proto { tcp udp } to %s keep state\n", family, addr)
		}
	}
	for _, r := range p.orderedRules() {
		if r.Action == "allow" {
			writePFRule(&b, r)
		}
	}
	return b.String()
}

func writePFRule(b *strings.Builder, r FirewallRule) {
	action := "pass"
	if r.Action == "block" {
		action = "block drop"
	}
	proto := ""
	if r.Protocol != "any" {
		proto = " proto " + r.Protocol
	}
	remote := "any"
	if len(r.Remote) > 0 {
		remote = "{ " + strings.Join(r.Remote, ", ") + " }"
	}
	ports := ""
	if len(r.Ports) > 0 {
		parts := make([]string, 0, len(r.Ports))
		for _, p := range r.Ports {
			if p[0] == p[1] {
				parts = append(parts, fmt.Sprint(p[0]))
			} else {
				parts = append(parts, fmt.Sprintf("%d:%d", p[0], p[1]))
			}
		}
		ports = " port { " + strings.Join(parts, ", ") + " }"
	}
	state := ""
	if r.Action == "allow" {
		state = " keep state"
	}
	if r.Direction == "in" {
		fmt.Fprintf(b, "%s in quick%s from %s to any%s%s\n", action, proto, remote, ports, state)
	} else {
		fmt.Fprintf(b, "%s out quick%s from any to %s%s%s\n", action, proto, remote, ports, state)
	}
}

// applyFirewall brings the host firewall in line with the policy. It is cheap to call often: the
// rules are only reloaded when they change (for example when the cloud's address changes).
func (a *Agent) applyFirewall() {
	plan := FirewallPlanFromPolicy(a.state.Policy)
	var addrs []string
	if plan.Active() && plan.BlockOutbound {
		addrs = a.controlPlaneAddrs()
		if len(addrs) == 0 {
			// Blocking outbound now would cut the agent off from its own cloud; try again next heartbeat.
			return
		}
		if a.state.Isolated {
			for _, addr := range a.state.Policy.ModuleStrings("firewall", "isolationAllowlist") {
				if validAddress(addr) {
					addrs = append(addrs, addr)
				}
			}
		}
	}
	var rules string
	if IsMacOS {
		rules = PFFirewallRules(plan, addrs)
		if a.state.Isolated {
			rules = "" // the isolation anchor decides while isolated; pf would otherwise mix the two
		}
	} else {
		rules = NftFirewallRuleset(plan, addrs)
	}
	key := rules
	if IsMacOS {
		key = fmt.Sprintf("%t|%t|%s", plan.Enabled, plan.BlockInbound, rules)
	}
	a.mu.Lock()
	unchanged := a.firewallApplied == key && a.firewallSet
	a.mu.Unlock()
	if unchanged {
		return
	}
	var err error
	if !a.cfg.DryRunIsolation {
		if IsMacOS {
			err = applyMacFirewall(plan, rules)
		} else {
			err = applyNftPolicy(rules)
		}
	}
	if err != nil {
		a.emit("firewall.apply_failed", "firewall", "Firewall policy could not be applied: "+err.Error(), map[string]interface{}{})
		return
	}
	a.mu.Lock()
	a.firewallApplied, a.firewallSet = key, true
	a.mu.Unlock()
	summary := "Fenrir firewall rules removed"
	if plan.Active() {
		summary = fmt.Sprintf("Firewall policy applied (inbound %s, outbound %s, %d custom rules)",
			blockWord(plan.BlockInbound), blockWord(plan.BlockOutbound), len(plan.Rules))
	}
	a.emit("firewall.applied", "firewall", summary, map[string]interface{}{
		"blockInbound": plan.BlockInbound, "blockOutbound": plan.BlockOutbound, "rules": len(plan.Rules), "active": plan.Active()})
}

func blockWord(block bool) string {
	if block {
		return "block"
	}
	return "allow"
}

func applyNftPolicy(rules string) error {
	if rules == "" {
		out, err := exec.Command("nft", "delete", "table", "inet", "fenrir_policy").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such file") && !strings.Contains(string(out), "does not exist") {
			if _, lookErr := exec.LookPath("nft"); lookErr != nil {
				return nil // nothing to remove when nftables is not installed
			}
			return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

const socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func applyMacFirewall(plan FirewallPlan, rules string) error {
	if plan.Enabled {
		// The application firewall is what System Settings and auditors show as "Firewall: on".
		_ = exec.Command(socketFilterFW, "--setglobalstate", "on").Run()
		if plan.BlockInbound {
			_ = exec.Command(socketFilterFW, "--setstealthmode", "on").Run()
		}
	}
	if rules == "" {
		out, err := exec.Command("pfctl", "-a", PFPolicyAnchor, "-F", "all").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such file") {
			return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	_ = exec.Command("pfctl", "-E").Run()
	cmd := exec.Command("pfctl", "-a", PFPolicyAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
