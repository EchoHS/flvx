package socket

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaskSiteRequestNormalizeAndValidateCloudflare(t *testing.T) {
	req := maskSiteRequest{
		TunnelID:           15,
		Domain:             "mask.example.com",
		WSPath:             "ws",
		CloudflareEnabled:  1,
		CloudflareAPIToken: "cf-token",
		PublicIP:           "203.0.113.10",
	}
	req.normalize()

	if req.WSPath != "/ws" || req.SiteRepo != maskDefaultSiteRepo || req.SiteDir != maskDefaultSiteDir || req.InnerPort != 24443 || req.PublicPort != 443 {
		t.Fatalf("unexpected normalized request: %+v", req)
	}
	if req.CloudflareRecordName != req.Domain {
		t.Fatalf("expected record name to default to domain, got %q", req.CloudflareRecordName)
	}
	if err := req.validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	req.PublicIP = ""
	if err := req.validate(); err == nil {
		t.Fatalf("expected cloudflare validation to require publicIP")
	}
}

func TestMaskSiteRequestPortValidation(t *testing.T) {
	req := maskSiteRequest{
		TunnelID:   15,
		Domain:     "mask.example.com",
		WSPath:     "/ws",
		SiteRepo:   maskDefaultSiteRepo,
		SiteDir:    maskDefaultSiteDir,
		InnerPort:  24443,
		PublicPort: 8443,
	}
	if err := req.validate(); err != nil {
		t.Fatalf("expected arbitrary TLS port to be accepted: %v", err)
	}

	req.PublicPort = req.InnerPort
	req.normalize()
	if req.PublicPort == req.InnerPort {
		t.Fatal("expected identical public and inner ports to be separated")
	}
	if err := req.validate(); err != nil {
		t.Fatalf("expected normalized ports to validate: %v", err)
	}

	req.PublicPort = 80
	if err := req.validate(); err == nil {
		t.Fatal("expected port 80 without DNS validation to be rejected")
	}
	req.CloudflareAPIToken = "cf-token"
	req.PublicIP = "203.0.113.10"
	if err := req.validate(); err != nil {
		t.Fatalf("expected port 80 with Cloudflare DNS validation: %v", err)
	}
}

func TestBuildMaskNginxConfigUsesTunnelPublicPort(t *testing.T) {
	req := maskSiteRequest{
		Domain:     "mask.example.com",
		WSPath:     "/ws",
		SiteDir:    maskDefaultSiteDir,
		InnerPort:  24443,
		PublicPort: 8443,
	}
	config := buildMaskNginxConfig(req)
	for _, want := range []string{
		"listen 8443 ssl http2;",
		"listen [::]:8443 ssl http2;",
		"return 301 https://$host:8443$request_uri;",
		"proxy_pass http://127.0.0.1:24443;",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("expected nginx config to contain %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "listen 443 ssl") {
		t.Fatalf("unexpected hard-coded 443 listener:\n%s", config)
	}
}

func TestBuildMaskNginxConfigKeepsStandardHTTPSRedirect(t *testing.T) {
	config := buildMaskNginxConfig(maskSiteRequest{
		Domain:     "mask.example.com",
		WSPath:     "/ws",
		SiteDir:    maskDefaultSiteDir,
		InnerPort:  24443,
		PublicPort: 443,
	})
	if !strings.Contains(config, "return 301 https://$host$request_uri;") {
		t.Fatalf("expected standard HTTPS redirect without explicit port:\n%s", config)
	}
}

func TestRunAcmeIssueCommandTreatsUnchangedCertificateAsSuccess(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "acme.sh")
	body := "#!/bin/sh\nprintf '%s\\n' \"Domains not changed.\" \"Skipping. Next renewal time is: 2026-08-06T22:53:42Z\" \"Add '--force' to force renewal.\"\nexit 2\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	if err := runAcmeIssueCommand(nil, script, "--issue", "-d", "mask.example.com"); err != nil {
		t.Fatalf("expected unchanged certificate output to be accepted: %v", err)
	}
}
