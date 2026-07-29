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
	"sync"
	"time"
)

const (
	maskStateRoot       = "/etc/flvx-mask"
	maskNginxAvailable  = "/etc/nginx/sites-available/flvx-mask.conf"
	maskNginxEnabled    = "/etc/nginx/sites-enabled/flvx-mask.conf"
	maskDefaultSiteRepo = "https://github.com/EchoHS/anime.js.git"
	maskDefaultSiteDir  = "/var/www/flvx-mask-site"
	maskRootHome        = "/root"
	maskAcmeScript      = "/root/.acme.sh/acme.sh"
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
	PublicIPSource       string `json:"publicIPSource,omitempty"`
	CloudflareEnabled    int    `json:"cloudflareEnabled"`
	CloudflareAPIToken   string `json:"cloudflareApiToken"`
	CloudflareAccountID  string `json:"cloudflareAccountId"`
	CloudflareZoneID     string `json:"cloudflareZoneId"`
	CloudflareRecordName string `json:"cloudflareRecordName"`
}

type maskSiteState struct {
	TunnelID             int64  `json:"tunnelId"`
	Domain               string `json:"domain"`
	WSPath               string `json:"wsPath"`
	SiteRepo             string `json:"siteRepo"`
	SiteDir              string `json:"siteDir"`
	ACMEEmail            string `json:"acmeEmail"`
	InnerPort            int    `json:"innerPort"`
	PublicPort           int    `json:"publicPort"`
	PublicIP             string `json:"publicIP"`
	PublicIPSource       string `json:"publicIPSource"`
	CloudflareEnabled    int    `json:"cloudflareEnabled"`
	CloudflareAPIToken   string `json:"cloudflareApiToken"`
	CloudflareAccountID  string `json:"cloudflareAccountId"`
	CloudflareZoneID     string `json:"cloudflareZoneId"`
	CloudflareRecordName string `json:"cloudflareRecordName"`
	UpdatedAt            int64  `json:"updatedAt"`
}

var maskSiteMu sync.Mutex

func (w *WebSocketReporter) handleConfigureMaskSite(data interface{}) error {
	maskSiteMu.Lock()
	defer maskSiteMu.Unlock()

	var req maskSiteRequest
	if err := decodeCommandData(data, &req); err != nil {
		return err
	}
	req.normalize()
	if err := req.validate(); err != nil {
		return err
	}
	if req.usesCloudflare() {
		publicIP, err := resolveMaskPublicIPv4(req.PublicIPSource)
		if err != nil {
			return err
		}
		req.PublicIP = publicIP
		zoneID, err := configureCloudflareRecord(req)
		if err != nil {
			return err
		}
		req.CloudflareZoneID = zoneID
	}
	if err := installMaskDependencies(); err != nil {
		return err
	}
	if err := prepareMaskSite(req); err != nil {
		return err
	}
	if req.usesCloudflare() {
		if err := ensureNativeCloudflareCertificate(req); err != nil {
			return err
		}
	} else {
		if err := ensureAcme(req); err != nil {
			return err
		}
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
	maskSiteMu.Lock()
	defer maskSiteMu.Unlock()

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
	if strings.TrimSpace(r.PublicIPSource) == "" {
		r.PublicIPSource = strings.TrimSpace(r.PublicIP)
	}
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
	r.CloudflareAccountID = strings.TrimSpace(r.CloudflareAccountID)
	r.CloudflareZoneID = strings.TrimSpace(r.CloudflareZoneID)
}

func (r maskSiteRequest) usesCloudflare() bool {
	return r.CloudflareEnabled == 1 || strings.TrimSpace(r.CloudflareAPIToken) != ""
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
	if r.usesCloudflare() {
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
	if req.usesCloudflare() {
		return errors.New("acme.sh must not be used for Cloudflare DNS certificate issuance")
	}
	acme := maskAcmeScript
	acmeEnv := maskAcmeEnvironment(req)
	if _, err := os.Stat(acme); err != nil {
		installer := filepath.Join(os.TempDir(), "flvx-acme-install.sh")
		if err := runCommand("curl", "-fsSL", "https://get.acme.sh", "-o", installer); err != nil {
			return err
		}
		defer os.Remove(installer)
		if err := runCommandEnv(acmeEnv, "sh", installer, "email="+defaultACMEEmail(req.ACMEEmail, req.Domain)); err != nil {
			return err
		}
	}
	info, err := os.Stat(acme)
	if err != nil {
		return fmt.Errorf("acme.sh installation did not create %s with HOME=%s: %w", acme, maskRootHome, err)
	}
	if info.IsDir() {
		return fmt.Errorf("acme.sh path is a directory: %s", acme)
	}
	if info.Mode().Perm()&0111 == 0 {
		if err := os.Chmod(acme, info.Mode().Perm()|0700); err != nil {
			return fmt.Errorf("make acme.sh executable: %w", err)
		}
	}
	if email := strings.TrimSpace(req.ACMEEmail); email != "" {
		if err := syncAcmeAccountEmail(acmeEnv, acme, email); err != nil {
			return err
		}
	}
	certDir := filepath.Join("/etc/nginx/ssl", req.Domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	if err := writeHTTPOnlyNginx(req); err != nil {
		return err
	}
	if err := runCommand("systemctl", "reload", "nginx"); err != nil {
		return err
	}
	if err := runAcmeIssueCommand(acmeEnv, acme, "--issue", "-d", req.Domain, "-w", req.SiteDir, "--keylength", "ec-256", "--server", "letsencrypt"); err != nil {
		return err
	}
	return runCommandEnv(acmeEnv, acme, "--install-cert", "-d", req.Domain, "--ecc",
		"--fullchain-file", filepath.Join(certDir, "fullchain.pem"),
		"--key-file", filepath.Join(certDir, "privkey.pem"),
		"--reloadcmd", "systemctl reload nginx")
}

func maskAcmeEnvironment(req maskSiteRequest) []string {
	env := setCommandEnvironment(os.Environ(), "HOME", maskRootHome)
	return removeCommandEnvironment(env, "CF_Token", "CF_Zone_ID")
}

func syncAcmeAccountEmail(env []string, acme, email string) error {
	if err := runCommandEnv(env, acme, "--update-account", "--accountemail", email, "--server", "letsencrypt"); err == nil {
		return nil
	}
	if err := runCommandEnv(env, acme, "--register-account", "-m", email, "--server", "letsencrypt"); err != nil {
		return fmt.Errorf("update acme.sh account email: %w", err)
	}
	return nil
}

func setCommandEnvironment(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func removeCommandEnvironment(env []string, keys ...string) []string {
	prefixes := make([]string, 0, len(keys))
	for _, key := range keys {
		prefixes = append(prefixes, key+"=")
	}
	out := make([]string, 0, len(env))
	for _, item := range env {
		remove := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(item, prefix) {
				remove = true
				break
			}
		}
		if !remove {
			out = append(out, item)
		}
	}
	return out
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
		TunnelID:             req.TunnelID,
		Domain:               req.Domain,
		WSPath:               req.WSPath,
		SiteRepo:             req.SiteRepo,
		SiteDir:              req.SiteDir,
		ACMEEmail:            req.ACMEEmail,
		InnerPort:            req.InnerPort,
		PublicPort:           req.PublicPort,
		PublicIP:             req.PublicIP,
		PublicIPSource:       req.PublicIPSource,
		CloudflareEnabled:    req.CloudflareEnabled,
		CloudflareAPIToken:   req.CloudflareAPIToken,
		CloudflareAccountID:  req.CloudflareAccountID,
		CloudflareZoneID:     req.CloudflareZoneID,
		CloudflareRecordName: req.CloudflareRecordName,
		UpdatedAt:            time.Now().Unix(),
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(maskStateRoot, fmt.Sprintf("tunnel-%d.json", req.TunnelID)), b, 0600)
}

func configureCloudflareRecord(req maskSiteRequest) (string, error) {
	if err := verifyCloudflareToken(req); err != nil {
		return "", err
	}
	zone, err := resolveCloudflareZone(req)
	if err != nil {
		return "", err
	}
	recordName := strings.TrimSpace(req.CloudflareRecordName)
	if recordName == "" {
		recordName = req.Domain
	}
	recordID, err := lookupCloudflareRecord(req, zone.ID, recordName)
	if err != nil {
		return "", err
	}
	body := map[string]interface{}{
		"type":    "A",
		"name":    recordName,
		"content": req.PublicIP,
		"ttl":     120,
		"proxied": false,
	}
	if recordID == "" {
		err = cloudflareRequest(req, http.MethodPost, cloudflareAPIURL("/zones/%s/dns_records", zone.ID), body, nil)
	} else {
		err = cloudflareRequest(req, http.MethodPut, cloudflareAPIURL("/zones/%s/dns_records/%s", zone.ID, recordID), body, nil)
	}
	if err != nil {
		return "", err
	}
	return zone.ID, nil
}

type cloudflareZone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

func verifyCloudflareToken(req maskSiteRequest) error {
	var tokenInfo struct {
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	err := cloudflareRequest(req, http.MethodGet, cloudflareAPIURL("/user/tokens/verify"), nil, &tokenInfo)
	if err != nil && strings.TrimSpace(req.CloudflareAccountID) != "" {
		err = cloudflareRequest(req, http.MethodGet, cloudflareAPIURL("/accounts/%s/tokens/verify", req.CloudflareAccountID), nil, &tokenInfo)
	}
	if err != nil {
		return fmt.Errorf("Cloudflare API Token 验证失败: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(tokenInfo.Result.Status), "active") {
		return fmt.Errorf("Cloudflare API Token 状态不是 active: %s", tokenInfo.Result.Status)
	}
	return nil
}

func resolveCloudflareZone(req maskSiteRequest) (cloudflareZone, error) {
	if zoneID := strings.TrimSpace(req.CloudflareZoneID); zoneID != "" {
		var res struct {
			Result cloudflareZone `json:"result"`
		}
		if err := cloudflareRequest(req, http.MethodGet, cloudflareAPIURL("/zones/%s", zoneID), nil, &res); err != nil {
			return cloudflareZone{}, fmt.Errorf("Cloudflare Zone ID 验证失败: %w", err)
		}
		if err := validateCloudflareZone(req, res.Result); err != nil {
			return cloudflareZone{}, err
		}
		return res.Result, nil
	}

	parts := strings.Split(req.Domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		name := strings.Join(parts[i:], ".")
		var res struct {
			Result []cloudflareZone `json:"result"`
		}
		query := "?name=" + neturl.QueryEscape(name)
		if accountID := strings.TrimSpace(req.CloudflareAccountID); accountID != "" {
			query += "&account.id=" + neturl.QueryEscape(accountID)
		}
		if err := cloudflareRequest(req, http.MethodGet, cloudflareAPIURL("/zones")+query, nil, &res); err != nil {
			return cloudflareZone{}, fmt.Errorf("Cloudflare Zone 查询失败（Token 需要 Zone Read 权限）: %w", err)
		}
		if len(res.Result) > 0 && res.Result[0].ID != "" {
			if err := validateCloudflareZone(req, res.Result[0]); err != nil {
				return cloudflareZone{}, err
			}
			return res.Result[0], nil
		}
	}
	return cloudflareZone{}, fmt.Errorf("Cloudflare 中未找到域名 %s 对应的 Zone；请检查 Token 资源范围、Account ID 和 Zone ID", req.Domain)
}

func validateCloudflareZone(req maskSiteRequest, zone cloudflareZone) error {
	if strings.TrimSpace(zone.ID) == "" || strings.TrimSpace(zone.Name) == "" {
		return errors.New("Cloudflare Zone 响应缺少 ID 或名称")
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	zoneName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone.Name), "."))
	if domain != zoneName && !strings.HasSuffix(domain, "."+zoneName) {
		return fmt.Errorf("Cloudflare Zone %s 不包含伪装域名 %s", zone.Name, req.Domain)
	}
	if accountID := strings.TrimSpace(req.CloudflareAccountID); accountID != "" && zone.Account.ID != accountID {
		return fmt.Errorf("Cloudflare Zone %s 不属于填写的 Account ID", zone.Name)
	}
	return nil
}

func lookupCloudflareRecord(req maskSiteRequest, zoneID, name string) (string, error) {
	var res struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	err := cloudflareRequest(req, http.MethodGet, cloudflareAPIURL("/zones/%s/dns_records", neturl.PathEscape(zoneID))+"?type=A&name="+neturl.QueryEscape(name), nil, &res)
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
	resp, err := cloudflareHTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare API 返回 HTTP %d: %s", resp.StatusCode, cloudflareErrorText(b))
	}
	var status struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(b, &status); err != nil {
		return fmt.Errorf("解析 Cloudflare API 响应失败: %w", err)
	}
	if !status.Success {
		return fmt.Errorf("Cloudflare API 请求失败: %s", cloudflareErrorText(b))
	}
	if dst != nil {
		return json.Unmarshal(b, dst)
	}
	return nil
}

var cloudflareAPIBaseURL = "https://api.cloudflare.com/client/v4"
var cloudflareHTTPClient = http.DefaultClient

func cloudflareAPIURL(format string, args ...interface{}) string {
	return strings.TrimRight(cloudflareAPIBaseURL, "/") + fmt.Sprintf(format, args...)
}

func cloudflareErrorText(body []byte) string {
	var envelope struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Messages []struct {
			Message string `json:"message"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &envelope) == nil {
		parts := make([]string, 0, len(envelope.Errors)+len(envelope.Messages))
		for _, item := range envelope.Errors {
			parts = append(parts, fmt.Sprintf("%d: %s", item.Code, item.Message))
		}
		for _, item := range envelope.Messages {
			parts = append(parts, item.Message)
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 500 {
		text = text[:500] + "..."
	}
	return text
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

func defaultACMEEmail(v, domain string) string {
	if strings.TrimSpace(v) == "" {
		return "admin@" + strings.TrimSpace(domain)
	}
	return strings.TrimSpace(v)
}
