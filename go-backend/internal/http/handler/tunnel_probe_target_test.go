package handler

import "testing"

func TestNormalizeTunnelProbeTargetDefaultsWhenEmpty(t *testing.T) {
	target, configured, err := normalizeTunnelProbeTarget("", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if configured {
		t.Fatalf("expected empty input to be default, not configured")
	}
	if target.Host != defaultTunnelProbeTargetHost || target.Port != defaultTunnelProbeTargetPort {
		t.Fatalf("unexpected default target: %+v", target)
	}
}

func TestNormalizeTunnelProbeTargetAcceptsHostPortAndIPv6(t *testing.T) {
	target, configured, err := normalizeTunnelProbeTarget(" [2001:db8::1] ", 8443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !configured {
		t.Fatalf("expected explicit target")
	}
	if target.Host != "2001:db8::1" || target.Port != 8443 {
		t.Fatalf("unexpected normalized target: %+v", target)
	}
	if got := formatTunnelProbeTarget(target); got != "[2001:db8::1]:8443" {
		t.Fatalf("unexpected formatted target: %s", got)
	}
}

func TestNormalizeTunnelProbeTargetRejectsPartialAndInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
	}{
		{name: "missing host", host: "", port: 443},
		{name: "missing port", host: "example.com", port: 0},
		{name: "port too high", host: "example.com", port: 70000},
		{name: "scheme", host: "https://example.com", port: 443},
		{name: "path", host: "example.com/ping", port: 443},
		{name: "space", host: "example .com", port: 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := normalizeTunnelProbeTarget(tt.host, tt.port); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestParseTunnelProbeTargetFromRequest(t *testing.T) {
	req := map[string]interface{}{
		"probeTargetHost": "speed.example.com",
		"probeTargetPort": float64(1443),
	}
	target, configured, err := parseTunnelProbeTargetFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !configured || target.Host != "speed.example.com" || target.Port != 1443 {
		t.Fatalf("unexpected request target: %+v configured=%v", target, configured)
	}
}
