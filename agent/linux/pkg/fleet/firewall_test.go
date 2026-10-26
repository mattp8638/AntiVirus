package fleet

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func firewallPolicy(t *testing.T, fw string) Policy {
	t.Helper()
	var p Policy
	if err := json.Unmarshal([]byte(`{"modules":{"firewall":`+fw+`}}`), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFirewallPlanDropsInvalidRules(t *testing.T) {
	p := firewallPolicy(t, `{"enabled":true,"defaultsOnLinuxMac":true,"defaultInbound":"block","defaultOutbound":"allow","parsedRules":[
		{"action":"allow","direction":"in","protocol":"tcp","ports":[[3389,3389]],"remote":["10.0.0.0/8"]},
		{"action":"allow","direction":"in","protocol":"tcp","ports":[[0,5]],"remote":[]},
		{"action":"allow","direction":"in","protocol":"tcp","ports":[],"remote":["10.0.0.1; drop"]},
		{"action":"rm","direction":"in","protocol":"tcp"},
		{"action":"block","direction":"out","protocol":"any","ports":[[80,80]]}]}`)
	plan := FirewallPlanFromPolicy(p)
	if !plan.Enabled || !plan.BlockInbound || plan.BlockOutbound || len(plan.Rules) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	if off := FirewallPlanFromPolicy(firewallPolicy(t, `{"enabled":true,"defaultInbound":"block","defaultOutbound":"block"}`)); off.BlockInbound || off.BlockOutbound || off.Active() {
		t.Fatalf("default actions must be opt-in on Linux/macOS: %+v", off)
	}
	if plan.Rules[0].Remote[0] != "10.0.0.0/8" || plan.Rules[0].Ports[0] != [2]int{3389, 3389} {
		t.Fatalf("rule = %+v", plan.Rules[0])
	}
}

func TestNftRulesetInactiveAndSSHSafeguard(t *testing.T) {
	if NftFirewallRuleset(FirewallPlan{Enabled: true}, nil) != "" || NftFirewallRuleset(FirewallPlan{BlockInbound: true}, nil) != "" {
		t.Fatal("an inactive plan must produce no rules")
	}
	plan := FirewallPlan{Enabled: true, BlockInbound: true, BlockOutbound: true, Rules: []FirewallRule{
		{Action: "allow", Direction: "in", Protocol: "tcp", Ports: [][2]int{{443, 443}, {8000, 8100}}, Remote: []string{"10.0.0.0/8", "fd00::/8"}},
		{Action: "block", Direction: "out", Protocol: "udp", Remote: []string{"203.0.113.9"}},
	}}
	rules := NftFirewallRuleset(plan, []string{"198.51.100.7", "2001:db8::7"})
	for _, want := range []string{
		"type filter hook input priority 0; policy drop;", "type filter hook output priority 0; policy drop;",
		"tcp dport 22 accept", "ip daddr 198.51.100.7 accept", "ip6 daddr 2001:db8::7 accept",
		"ip saddr { 10.0.0.0/8 } tcp dport { 443, 8000-8100 } accept", "ip6 saddr { fd00::/8 } tcp dport { 443, 8000-8100 } accept",
		"ip daddr { 203.0.113.9 } meta l4proto udp drop",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in\n%s", want, rules)
		}
	}
	// The block rule must come before the DNS safeguard and the allow rules.
	if strings.Index(rules, "203.0.113.9") > strings.Index(rules, "udp dport { 53") {
		t.Error("block rules must precede the safeguards")
	}
	plan.Rules = append(plan.Rules, FirewallRule{Action: "block", Direction: "in", Protocol: "tcp", Ports: [][2]int{{20, 25}}})
	if strings.Contains(NftFirewallRuleset(plan, []string{"198.51.100.7"}), "tcp dport 22 accept") {
		t.Error("an explicit block on port 22 must remove the SSH safeguard")
	}
	if strings.Contains(NftFirewallRuleset(FirewallPlan{Enabled: true, Rules: plan.Rules}, nil), "tcp dport 22 accept") {
		t.Error("no SSH rule is needed when inbound is allowed by default")
	}
	if exec.Command("nft", "--version").Run() == nil {
		check := exec.Command("nft", "-c", "-f", "-")
		check.Stdin = strings.NewReader(rules)
		if out, err := check.CombinedOutput(); err != nil && !strings.Contains(string(out), "Operation not permitted") {
			t.Errorf("nft rejected the ruleset: %v: %s\n%s", err, out, rules)
		}
	}
}

func TestPFFirewallRules(t *testing.T) {
	plan := FirewallPlan{Enabled: true, BlockInbound: true, Rules: []FirewallRule{
		{Action: "allow", Direction: "in", Protocol: "tcp", Ports: [][2]int{{5900, 5900}, {6000, 6010}}, Remote: []string{"10.0.0.0/8"}},
		{Action: "block", Direction: "out", Protocol: "any", Remote: []string{"203.0.113.0/24"}},
	}}
	rules := PFFirewallRules(plan, nil)
	for _, want := range []string{
		"pass out all keep state\nblock drop in all\n", "pass in quick proto tcp from any to any port 22 keep state",
		"pass in quick proto tcp from { 10.0.0.0/8 } to any port { 5900, 6000:6010 } keep state",
		"block drop out quick from any to { 203.0.113.0/24 }",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "block drop out all") {
		t.Error("outbound is allowed by default")
	}
	out := PFFirewallRules(FirewallPlan{Enabled: true, BlockOutbound: true}, []string{"198.51.100.7"})
	if !strings.Contains(out, "block drop out all") || !strings.Contains(out, "pass out quick inet proto { tcp udp } to 198.51.100.7 keep state") {
		t.Errorf("outbound block rules:\n%s", out)
	}
}
