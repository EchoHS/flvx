package socket

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	maskStateRoot       = "/etc/flvx-mask"
	maskNginxAvailable  = "/etc/nginx/sites-available/flvx-mask.conf"
	maskNginxEnabled    = "/etc/nginx/sites-enabled/flvx-mask.conf"
	maskDefaultSiteRepo = "https://github.com/EchoHS/anime.js.git"
	maskDefaultSiteDir  = "/var/www/flvx-mask-site"
)

type maskSiteRequest struct {
	TunnelID             int64  `json:"tunnelId"`
	Domain               string `json:"domain"`
	WSPath               string `json:"wsPath"`
	SiteRepo             string `json:"siteRepo"`
	SiteDir              string `json:"siteDir"`
	ACMEEmail            string `json:"acmeEmail"`
	InnerPort            int    `json:"innerPort"`
	PublicPort           int    `json:"publicPort"`
	PublicIP             string `json:"publicIP"`
	CloudflareEnabled    int    `json:"cloudflareEnabled"`
	CloudflareAPIToken   string `json:"cloudflareApiToken"`
	CloudflareZoneID     string `json:"cloudflareZoneId"`
	CloudflareRecordName string `json:"cloudflareRecordName"`
}

type maskSiteState struct {
	TunnelID   int64  `json:"tunnelId"`
	Domain     string `json:"domain"`
	WSPath     string `json:"wsPath"`
	SiteDir    string `json:"siteDir"`
	InnerPort  int    `json:"innerPort"`
	PublicPort int    `json:"publicPort"`
	PublicIP   string `json:"publicIP"`
	UpdatedAt  int64  `json:"updatedAt"`
}

func (w *WebSocketReporter) handleConfigureMaskSite(data interface{}) error {
	var req maskSiteRequest
	if err := decodeCommandData(data, &req); err != nil {
		return err
	}
	req.normalize()
	if err := req.validate(); err != nil {
		return err
	}
	if req.CloudflareEnabled == 1 || strings.TrimSpace(req.CloudflareAPIToken) != "" {
		if err := configureCloudflareRecord(req); err != nil {
			return err
		}
	}
	if err := installMaskDependencies(); err != nil {
		return err
	}
	if err := prepareMaskSite(req); err != nil {
		return err
	}
	if err := ensureAcme(req); err != nil {
		return err
	}
	if err := writeMaskNginxConfig(req); err != nil {
		return err
	}
	if err := writeMaskState(req); err != nil {
		return err
	}
	return runCommand("systemctl", "reload", "nginx")
}

func (w *WebSocketReporter) handleRemoveMaskSite(data interface{}) error {
	var req struct {
		TunnelID int64 `json:"tunnelId"`
	}
	if err := decodeCommandData(data, &req); err != nil {
		return err
	}
	_ = os.Remove(maskNginxEnabled)
	_ = os.Remove(maskNginxAvailable)
	if req.TunnelID > 0 {
		_ = os.Remove(filepath.Join(maskStateRoot, fmt.Sprintf("tunnel-%d.json", req.TunnelID)))
	}
	if err := runCommand("nginx", "-t"); err != nil {
		return err
	}
	return runCommand("systemctl", "reload", "nginx")
}

func decodeCommandData(data interface{}, dst interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func (r *maskSiteRequest) normalize() {
	r.Domain = strings.TrimSpace(r.Domain)
	if !strings.HasPrefix(r.WSPath, "/") {
		r.WSPath = "/" + strings.TrimSpace(r.WSPath)
	}
	if strings.TrimSpace(r.WSPath) == "" || r.WSPath == "/" {
		r.WSPath = "/ws"
	}
	if strings.TrimSpace(r.SiteRepo) == "" {
		r.SiteRepo = maskDefaultSiteRepo
	}
	if strings.TrimSpace(r.SiteDir) == "" {
		r.SiteDir = maskDefaultSiteDir
	}
	if r.InnerPort <= 0 {
		r.InnerPort = 24443
	}
	if r.PublicPort <= 0 {
		r.PublicPort = 443
	}
	if r.InnerPort == r.PublicPort {
		r.InnerPort = 24443
		if r.InnerPort == r.PublicPort {
			r.InnerPort++
		}
	}
	if strings.TrimSpace(r.CloudflareRecordName) == "" {
		r.CloudflareRecordName = r.Domain
	}
}

func (r maskSiteRequest) validate() error {
	if r.TunnelID <= 0 {
		return errors.New("tunnelId is required")
	}
	if r.Domain == "" {
		return errors.New("domain is required")
	}
	if r.InnerPort <= 0 || r.InnerPort > 65535 {
		return errors.New("innerPort is invalid")
	}
	if r.PublicPort <= 0 || r.PublicPort > 65535 {
		return errors.New("publicPort is invalid")
	}
	if r.PublicPort == 80 && strings.TrimSpace(r.CloudflareAPIToken) == "" {
		return errors.New("publicPort 80 requires Cloudflare DNS certificate issuance")
	}
	if r.CloudflareEnabled == 1 || strings.TrimSpace(r.CloudflareAPIToken) != "" {
		if strings.TrimSpace(r.CloudflareAPIToken) == "" {
			return errors.New("cloudflare api token is required")
		}
		if strings.TrimSpace(r.PublicIP) == "" {
			return errors.New("publicIP is required for cloudflare dns update")
		}
	}
	return nil
}

func installMaskDependencies() error {
	if _, err := os.Stat("/etc/debian_version"); err != nil {
		return errors.New("mask site installer currently supports Debian/Ubuntu only")
	}
	if err := runCommand("apt-get", "update"); err != nil {
		return err
	}
	return runCommand("apt-get", "install", "-y", "nginx", "git", "curl", "ca-certificates", "socat", "cron")
}

func prepareMaskSite(req maskSiteRequest) error {
	if _, err := os.Stat(filepath.Join(req.SiteDir, ".git")); err == nil {
		if err := runCommand("git", "config", "--global", "--add", "safe.directory", req.SiteDir); err != nil {
			return err
		}
		return runCommand("git", "-C", req.SiteDir, "pull", "--ff-only")
	}
	if err := os.RemoveAll(req.SiteDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(req.SiteDir), 0755); err != nil {
		return err
	}
	return runCommand("git", "clone", "--depth", "1", req.SiteRepo, req.SiteDir)
}

func ensureAcme(req maskSiteRequest) error {
	acme := "/root/.acme.sh/acme.sh"
	if _, err := os.Stat(acme); err != nil {
		installer := filepath.Join(os.TempDir(), "flvx-acme-install.sh")
		if err := runCommand("curl", "-fsSL", "https://get.acme.sh", "-o", installer); err != nil {
			return err
		}
		if err := runCommand("sh", installer, "email="+defaultACMEEmail(req.ACMEEmail)); err != nil {
			return err
		}
	}
	certDir := filepath.Join("/etc/nginx/ssl", req.Domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	if strings.TrimSpace(req.CloudflareAPIToken) != "" {
		env := append(os.Environ(), "CF_Token="+req.CloudflareAPIToken)
		if strings.TrimSpace(req.CloudflareZoneID) != "" {
			env = append(env, "CF_Zone_ID="+req.CloudflareZoneID)
		}
		if err := runAcmeIssueCommand(env, acme, "--issue", "--dns", "dns_cf", "-d", req.Domain, "--keylength", "ec-256", "--server", "letsencrypt"); err != nil {
			return err
		}
	} else {
		if err := writeHTTPOnlyNginx(req); err != nil {
			return err
		}
		if err := runCommand("systemctl", "reload", "nginx"); err != nil {
			return err
		}
		if err := runAcmeIssueCommand(nil, acme, "--issue", "-d", req.Domain, "-w", req.SiteDir, "--keylength", "ec-256", "--server", "letsencrypt"); err != nil {
			return err
		}
	}
	return runCommand(acme, "--install-cert", "-d", req.Domain, "--ecc",
		"--fullchain-file", filepath.Join(certDir, "fullchain.pem"),
		"--key-file", filepath.Join(certDir, "privkey.pem"),
		"--reloadcmd", "systemctl reload nginx")
}

func writeHTTPOnlyNginx(req maskSiteRequest) error {
	content := fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    location /.well-known/acme-challenge/ { try_files $uri =404; }
    location / { return 200 "ok\n"; }
}
`, req.Domain, req.SiteDir)
	if err := os.WriteFile(maskNginxAvailable, []byte(content), 0644); err != nil {
		return err
	}
	_ = os.Remove(maskNginxEnabled)
	if err := os.Symlink(maskNginxAvailable, maskNginxEnabled); err != nil && !os.IsExist(err) {
		return err
	}
	return runCommand("nginx", "-t")
}

func writeMaskNginxConfig(req maskSiteRequest) error {
	content := buildMaskNginxConfig(req)
	if err := os.WriteFile(maskNginxAvailable, []byte(content), 0644); err != nil {
		return err
	}
	_ = os.Remove(maskNginxEnabled)
	if err := os.Symlink(maskNginxAvailable, maskNginxEnabled); err != nil && !os.IsExist(err) {
		return err
	}
	return runCommand("nginx", "-t")
}

func buildMaskNginxConfig(req maskSiteRequest) string {
	certDir := filepath.Join("/etc/nginx/ssl", req.Domain)
	redirectURL := "https://$host$request_uri"
	if req.PublicPort != 443 {
		redirectURL = fmt.Sprintf("https://$host:%d$request_uri", req.PublicPort)
	}
	httpServer := ""
	if req.PublicPort != 80 {
		httpServer = fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    location /.well-known/acme-challenge/ { root %s; try_files $uri =404; }
    location / { return 301 %s; }
}

`, req.Domain, req.SiteDir, redirectURL)
	}
	content := fmt.Sprintf(`server {
    listen %d ssl http2;
    listen [::]:%d ssl http2;
    server_name %s;

    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_session_timeout 1d;
    ssl_session_cache shared:FLVXMaskTLS:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    root %s;
    index index.html index.htm;

    location = %s {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
`, req.PublicPort, req.PublicPort, req.Domain,
		filepath.Join(certDir, "fullchain.pem"),
		filepath.Join(certDir, "privkey.pem"),
		req.SiteDir, req.WSPath, req.InnerPort)
	return httpServer + content
}

func writeMaskState(req maskSiteRequest) error {
	if err := os.MkdirAll(maskStateRoot, 0700); err != nil {
		return err
	}
	state := maskSiteState{
		TunnelID:   req.TunnelID,
		Domain:     req.Domain,
		WSPath:     req.WSPath,
		SiteDir:    req.SiteDir,
		InnerPort:  req.InnerPort,
		PublicPort: req.PublicPort,
		PublicIP:   req.PublicIP,
		UpdatedAt:  time.Now().Unix(),
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(maskStateRoot, fmt.Sprintf("tunnel-%d.json", req.TunnelID)), b, 0600)
}

func configureCloudflareRecord(req maskSiteRequest) error {
	zoneID := strings.TrimSpace(req.CloudflareZoneID)
	if zoneID == "" {
		var err error
		zoneID, err = lookupCloudflareZone(req)
		if err != nil {
			return err
		}
	}
	recordName := strings.TrimSpace(req.CloudflareRecordName)
	if recordName == "" {
		recordName = req.Domain
	}
	recordID, err := lookupCloudflareRecord(req, zoneID, recordName)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		"type":    "A",
		"name":    recordName,
		"content": req.PublicIP,
		"ttl":     120,
		"proxied": false,
	}
	if recordID == "" {
		return cloudflareRequest(req, http.MethodPost, fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID), body, nil)
	}
	return cloudflareRequest(req, http.MethodPut, fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID), body, nil)
}

func lookupCloudflareZone(req maskSiteRequest) (string, error) {
	parts := strings.Split(req.Domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		name := strings.Join(parts[i:], ".")
		var res struct {
			Result []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		err := cloudflareRequest(req, http.MethodGet, "https://api.cloudflare.com/client/v4/zones?name="+neturl.QueryEscape(name), nil, &res)
		if err == nil && len(res.Result) > 0 && res.Result[0].ID != "" {
			return res.Result[0].ID, nil
		}
	}
	return "", errors.New("cloudflare zone not found")
}

func lookupCloudflareRecord(req maskSiteRequest, zoneID, name string) (string, error) {
	var res struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	err := cloudflareRequest(req, http.MethodGet, fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", neturl.PathEscape(zoneID), neturl.QueryEscape(name)), nil, &res)
	if err != nil {
		return "", err
	}
	if len(res.Result) == 0 {
		return "", nil
	}
	return res.Result[0].ID, nil
}

func cloudflareRequest(req maskSiteRequest, method, url string, body interface{}, dst interface{}) error {
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	httpReq, err := http.NewRequest(method, url, reader)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.CloudflareAPIToken)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare api failed: %s", strings.TrimSpace(string(b)))
	}
	if dst != nil {
		return json.Unmarshal(b, dst)
	}
	return nil
}

func runCommand(name string, args ...string) error {
	return runCommandEnv(nil, name, args...)
}

func runCommandEnv(env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runAcmeIssueCommand(env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, "Skipping. Next renewal time") ||
		strings.Contains(text, "Domains not changed") ||
		strings.Contains(text, "Add '--force' to force renewal") {
		return nil
	}
	return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, text)
}

func defaultACMEEmail(v string) string {
	if strings.TrimSpace(v) == "" {
		return "admin@example.com"
	}
	return strings.TrimSpace(v)
}
