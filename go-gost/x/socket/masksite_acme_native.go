package socket

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	maskNativeACMERoot       = "/etc/flvx-mask/acme"
	maskNativeAccountKeyPath = "/etc/flvx-mask/acme/account.key"
	maskCertificateRenewal   = 30 * 24 * time.Hour
)

var maskPublicIPLookupURLs = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://api.ipify.org",
}
var maskPublicIPHTTPClient = &http.Client{Timeout: 12 * time.Second}

func resolveMaskPublicIPv4(configured string) (string, error) {
	host := strings.Trim(strings.TrimSpace(configured), "[]")
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return ip.String(), nil
	}

	errorsSeen := make([]string, 0, len(maskPublicIPLookupURLs))
	for _, endpoint := range maskPublicIPLookupURLs {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "flvx-agent/public-ip")
		resp, err := maskPublicIPHTTPClient.Do(req)
		if err != nil {
			errorsSeen = append(errorsSeen, err.Error())
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s returned HTTP %d", endpoint, resp.StatusCode))
			continue
		}
		value := strings.TrimSpace(string(body))
		if strings.Contains(value, "ip=") {
			for _, line := range strings.Split(value, "\n") {
				if strings.HasPrefix(line, "ip=") {
					value = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
					break
				}
			}
		}
		if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
		errorsSeen = append(errorsSeen, endpoint+" did not return an IPv4 address")
	}
	return "", fmt.Errorf("agent 无法获取出口节点公网 IPv4（节点地址 %q 不是 IPv4）: %s", configured, strings.Join(errorsSeen, "; "))
}

func ensureNativeCloudflareCertificate(req maskSiteRequest) error {
	if !req.usesCloudflare() {
		return errors.New("native Cloudflare ACME requires Cloudflare mode")
	}
	certDir := filepath.Join("/etc/nginx/ssl", req.Domain)
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")
	if certificateValidFor(certPath, maskCertificateRenewal) {
		return nil
	}
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(maskNativeACMERoot, 0700); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	accountKey, err := loadOrCreateACMEKey(maskNativeAccountKeyPath)
	if err != nil {
		return fmt.Errorf("准备内置 ACME 账户密钥: %w", err)
	}
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: acme.LetsEncryptURL,
		UserAgent:    "flvx-agent/mask-site",
	}
	account := &acme.Account{}
	if email := strings.TrimSpace(req.ACMEEmail); email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil {
		if !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return fmt.Errorf("注册 Let's Encrypt 账户: %w", err)
		}
		if len(account.Contact) > 0 {
			if _, err := client.UpdateReg(ctx, account); err != nil {
				return fmt.Errorf("更新 Let's Encrypt 联系邮箱: %w", err)
			}
		}
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(req.Domain))
	if err != nil {
		return fmt.Errorf("创建 Let's Encrypt 订单: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("读取 ACME 授权: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		challenge := dns01Challenge(authz)
		if challenge == nil {
			return fmt.Errorf("Let's Encrypt 没有为 %s 返回 dns-01 challenge", authz.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return fmt.Errorf("生成 dns-01 challenge: %w", err)
		}
		recordName := "_acme-challenge." + strings.TrimPrefix(authz.Identifier.Value, "*.")
		recordID, created, err := createCloudflareTXTRecord(req, recordName, value)
		if err != nil {
			return fmt.Errorf("创建 Cloudflare ACME TXT 记录: %w", err)
		}
		cleanup := func() {
			if created {
				_ = deleteCloudflareDNSRecord(req, recordID)
			}
		}
		if err := waitForDNS01Record(ctx, recordName, value); err != nil {
			cleanup()
			return err
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			cleanup()
			return fmt.Errorf("提交 dns-01 challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			cleanup()
			return fmt.Errorf("等待 dns-01 验证: %w", err)
		}
		cleanup()
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("等待 Let's Encrypt 订单就绪: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Domain},
		DNSNames: []string{req.Domain},
	}, certKey)
	if err != nil {
		return fmt.Errorf("创建证书 CSR: %w", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("签发 Let's Encrypt 证书: %w", err)
	}
	fullchain := make([]byte, 0)
	for _, der := range chain {
		fullchain = append(fullchain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(certPath, fullchain, 0644); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	return nil
}

func dns01Challenge(authz *acme.Authorization) *acme.Challenge {
	if authz == nil {
		return nil
	}
	for _, challenge := range authz.Challenges {
		if challenge != nil && challenge.Type == "dns-01" {
			return challenge
		}
	}
	return nil
}

func createCloudflareTXTRecord(req maskSiteRequest, name, value string) (string, bool, error) {
	var list struct {
		Result []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	query := "?type=TXT&name=" + neturl.QueryEscape(name)
	if err := cloudflareRequest(req, http.MethodGet, cloudflareAPIURL("/zones/%s/dns_records", req.CloudflareZoneID)+query, nil, &list); err != nil {
		return "", false, err
	}
	for _, record := range list.Result {
		if record.Content == value {
			return record.ID, false, nil
		}
	}
	var created struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	body := map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     120,
	}
	if err := cloudflareRequest(req, http.MethodPost, cloudflareAPIURL("/zones/%s/dns_records", req.CloudflareZoneID), body, &created); err != nil {
		return "", false, err
	}
	if created.Result.ID == "" {
		return "", false, errors.New("Cloudflare 创建 TXT 记录后未返回记录 ID")
	}
	return created.Result.ID, true, nil
}

func deleteCloudflareDNSRecord(req maskSiteRequest, recordID string) error {
	if strings.TrimSpace(recordID) == "" {
		return nil
	}
	return cloudflareRequest(req, http.MethodDelete, cloudflareAPIURL("/zones/%s/dns_records/%s", req.CloudflareZoneID, recordID), nil, nil)
}

func waitForDNS01Record(ctx context.Context, name, expected string) error {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		values, err := resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, value := range values {
				if value == expected {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待 ACME TXT 记录传播: %w", ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("等待 ACME TXT 记录 %s 传播超时", name)
		case <-ticker.C:
		}
	}
}

func certificateValidFor(path string, minimum time.Duration) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err == nil && time.Until(cert.NotAfter) > minimum
}

func loadOrCreateACMEKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("ACME 账户密钥 PEM 无效")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".flvx-mask-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func runMaskCertificateRenewalLoop(ctx context.Context) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			renewMaskCertificates()
			timer.Reset(12 * time.Hour)
		}
	}
}

func renewMaskCertificates() {
	maskSiteMu.Lock()
	defer maskSiteMu.Unlock()

	paths, _ := filepath.Glob(filepath.Join(maskStateRoot, "tunnel-*.json"))
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var state maskSiteState
		if jsonErr := jsonUnmarshalMaskState(b, &state); jsonErr != nil || state.CloudflareEnabled != 1 || strings.TrimSpace(state.CloudflareAPIToken) == "" {
			continue
		}
		req := maskRequestFromState(state)
		if certificateValidFor(filepath.Join("/etc/nginx/ssl", req.Domain, "fullchain.pem"), maskCertificateRenewal) {
			continue
		}
		publicIP, err := resolveMaskPublicIPv4(req.PublicIPSource)
		if err == nil {
			req.PublicIP = publicIP
			if zoneID, configureErr := configureCloudflareRecord(req); configureErr == nil {
				req.CloudflareZoneID = zoneID
				err = ensureNativeCloudflareCertificate(req)
			} else {
				err = configureErr
			}
		}
		if err != nil {
			fmt.Printf("mask-site: renew certificate for %s failed: %v\n", req.Domain, err)
			continue
		}
		_ = writeMaskState(req)
		_ = runCommand("systemctl", "reload", "nginx")
	}
}

func jsonUnmarshalMaskState(data []byte, state *maskSiteState) error {
	return json.Unmarshal(data, state)
}

func maskRequestFromState(state maskSiteState) maskSiteRequest {
	publicIPSource := strings.TrimSpace(state.PublicIPSource)
	if publicIPSource == "" {
		publicIPSource = state.PublicIP
	}
	return maskSiteRequest{
		TunnelID:             state.TunnelID,
		Domain:               state.Domain,
		WSPath:               state.WSPath,
		SiteRepo:             state.SiteRepo,
		SiteDir:              state.SiteDir,
		ACMEEmail:            state.ACMEEmail,
		InnerPort:            state.InnerPort,
		PublicPort:           state.PublicPort,
		PublicIP:             state.PublicIP,
		PublicIPSource:       publicIPSource,
		CloudflareEnabled:    state.CloudflareEnabled,
		CloudflareAPIToken:   state.CloudflareAPIToken,
		CloudflareAccountID:  state.CloudflareAccountID,
		CloudflareZoneID:     state.CloudflareZoneID,
		CloudflareRecordName: state.CloudflareRecordName,
	}
}
