package socket

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type maskRoundTripFunc func(*http.Request) (*http.Response, error)

func (f maskRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func maskHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestConfigureCloudflareRecordUsesProvidedZoneAndAccount(t *testing.T) {
	var recordBody map[string]interface{}
	client := &http.Client{Transport: maskRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer cf-token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/user/tokens/verify":
			return maskHTTPResponse(http.StatusOK, `{"success":true,"result":{"status":"active"}}`), nil
		case r.URL.Path == "/zones/zone-id":
			return maskHTTPResponse(http.StatusOK, `{"success":true,"result":{"id":"zone-id","name":"gekzi.com","account":{"id":"account-id"}}}`), nil
		case r.URL.Path == "/zones/zone-id/dns_records" && r.Method == http.MethodGet:
			return maskHTTPResponse(http.StatusOK, `{"success":true,"result":[]}`), nil
		case r.URL.Path == "/zones/zone-id/dns_records" && r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&recordBody); err != nil {
				t.Fatalf("decode record body: %v", err)
			}
			return maskHTTPResponse(http.StatusOK, `{"success":true,"result":{"id":"record-id"}}`), nil
		default:
			return maskHTTPResponse(http.StatusNotFound, `{"success":false,"errors":[{"code":1000,"message":"not found"}]}`), nil
		}
	})}

	previousBase := cloudflareAPIBaseURL
	previousClient := cloudflareHTTPClient
	cloudflareAPIBaseURL = "https://api.test"
	cloudflareHTTPClient = client
	t.Cleanup(func() {
		cloudflareAPIBaseURL = previousBase
		cloudflareHTTPClient = previousClient
	})

	zoneID, err := configureCloudflareRecord(maskSiteRequest{
		Domain:               "cdn.gekzi.com",
		PublicIP:             "203.0.113.20",
		CloudflareEnabled:    1,
		CloudflareAPIToken:   "cf-token",
		CloudflareAccountID:  "account-id",
		CloudflareZoneID:     "zone-id",
		CloudflareRecordName: "cdn.gekzi.com",
	})
	if err != nil {
		t.Fatalf("configure Cloudflare record: %v", err)
	}
	if zoneID != "zone-id" {
		t.Fatalf("zone id = %q", zoneID)
	}
	if recordBody["type"] != "A" || recordBody["content"] != "203.0.113.20" || recordBody["proxied"] != false {
		t.Fatalf("unexpected record body: %#v", recordBody)
	}
}

func TestCloudflareZoneLookupPreservesPermissionError(t *testing.T) {
	client := &http.Client{Transport: maskRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/user/tokens/verify" {
			return maskHTTPResponse(http.StatusOK, `{"success":true,"result":{"status":"active"}}`), nil
		}
		return maskHTTPResponse(http.StatusForbidden, `{"success":false,"errors":[{"code":9109,"message":"Invalid access rights"}]}`), nil
	})}

	previousBase := cloudflareAPIBaseURL
	previousClient := cloudflareHTTPClient
	cloudflareAPIBaseURL = "https://api.test"
	cloudflareHTTPClient = client
	t.Cleanup(func() {
		cloudflareAPIBaseURL = previousBase
		cloudflareHTTPClient = previousClient
	})

	_, err := configureCloudflareRecord(maskSiteRequest{
		Domain:             "cdn.gekzi.com",
		PublicIP:           "203.0.113.20",
		CloudflareEnabled:  1,
		CloudflareAPIToken: "cf-token",
	})
	if err == nil || !strings.Contains(err.Error(), "Zone Read") || !strings.Contains(err.Error(), "Invalid access rights") {
		t.Fatalf("expected actionable permission error, got %v", err)
	}
}

func TestResolveMaskPublicIPv4FromAgent(t *testing.T) {
	previousURLs := maskPublicIPLookupURLs
	previousClient := maskPublicIPHTTPClient
	maskPublicIPLookupURLs = []string{"https://trace.test"}
	maskPublicIPHTTPClient = &http.Client{Transport: maskRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString("fl=1\nip=198.51.100.42\n")),
		}, nil
	})}
	t.Cleanup(func() {
		maskPublicIPLookupURLs = previousURLs
		maskPublicIPHTTPClient = previousClient
	})

	ip, err := resolveMaskPublicIPv4("exit.gekzi.com")
	if err != nil {
		t.Fatalf("resolve public IPv4: %v", err)
	}
	if ip != "198.51.100.42" {
		t.Fatalf("ip = %q", ip)
	}
}

func TestCloudflareModeNeverUsesAcmeSh(t *testing.T) {
	err := ensureAcme(maskSiteRequest{CloudflareEnabled: 1, CloudflareAPIToken: "cf-token"})
	if err == nil || !strings.Contains(err.Error(), "must not be used") {
		t.Fatalf("expected acme.sh guard, got %v", err)
	}
	if got := defaultACMEEmail("", "gekzi.com"); got != "admin@gekzi.com" {
		t.Fatalf("default email = %q", got)
	}
}
