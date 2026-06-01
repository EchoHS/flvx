package nftables

import (
	"strings"
	"testing"
)

func TestRenderTableIncludesDNATAndMasquerade(t *testing.T) {
	script := RenderTable(NodePlan{
		NodeID: 10,
		Rules: []Rule{
			{
				ForwardID:  42,
				InPort:     24000,
				TargetHost: "198.51.100.20",
				TargetPort: 443,
				Protocols:  []string{"tcp", "udp"},
			},
		},
	})

	expectedParts := []string{
		"table inet flvx",
		"type nat hook prerouting priority dstnat; policy accept;",
		"type nat hook postrouting priority srcnat; policy accept;",
		"tcp dport 24000 dnat ip to 198.51.100.20:443 comment \"flvx forward:42 tcp\"",
		"udp dport 24000 dnat ip to 198.51.100.20:443 comment \"flvx forward:42 udp\"",
		"masquerade comment \"flvx masquerade\"",
	}
	for _, part := range expectedParts {
		if !strings.Contains(script, part) {
			t.Fatalf("script missing %q:\n%s", part, script)
		}
	}
}

func TestRenderTableBracketsIPv6Target(t *testing.T) {
	script := RenderTable(NodePlan{
		NodeID: 10,
		Rules: []Rule{
			{ForwardID: 42, InPort: 24000, TargetHost: "2001:db8::1", TargetPort: 443, Protocols: []string{"tcp"}},
		},
	})
	if !strings.Contains(script, "dnat ip6 to [2001:db8::1]:443") {
		t.Fatalf("expected bracketed IPv6 dnat target, got:\n%s", script)
	}
}

func TestRuleHashIsStable(t *testing.T) {
	rule := Rule{ForwardID: 42, InPort: 24000, TargetHost: "198.51.100.20", TargetPort: 443, Protocols: []string{"tcp", "udp"}}
	if RuleHash(rule) != RuleHash(rule) {
		t.Fatalf("expected stable rule hash")
	}
	if RuleHash(rule) == RuleHash(Rule{ForwardID: 42, InPort: 24001, TargetHost: "198.51.100.20", TargetPort: 443, Protocols: []string{"tcp", "udp"}}) {
		t.Fatalf("expected hash to change when port changes")
	}
}

func TestRuleHashIgnoresBindIPWhenRenderingDoesNotUseIt(t *testing.T) {
	base := Rule{
		ForwardID:  42,
		InPort:     24000,
		TargetHost: "198.51.100.20",
		TargetPort: 443,
		Protocols:  []string{"tcp", "udp"},
	}
	withBind := base
	withBind.BindIP = "192.0.2.10"

	if RuleHash(base) != RuleHash(withBind) {
		t.Fatalf("expected bind IP to be ignored by hash when it is not rendered")
	}
}
