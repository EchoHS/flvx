package handler

import (
	"database/sql"
	"testing"

	"go-backend/internal/store/model"
)

func TestParseTunnelMaskConfigOnlySupportsSingleWebSocketExit(t *testing.T) {
	baseState := &tunnelCreateState{
		OutNodes: []tunnelRuntimeNode{{
			NodeID:    2,
			Protocol:  "mwss",
			ChainType: 3,
			Port:      443,
		}},
	}
	req := map[string]interface{}{
		"maskConfig": map[string]interface{}{
			"enabled":            1,
			"domain":             "mask.example.com",
			"wsPath":             "tunnel",
			"innerPort":          24443,
			"cloudflareApiToken": "cf-token",
		},
	}

	cfg, err := parseTunnelMaskConfigFromRequest(req, baseState, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Domain != "mask.example.com" || cfg.WSPath != "/tunnel" || cfg.InnerPort != 24443 {
		t.Fatalf("unexpected mask config: %+v", cfg)
	}
	if cfg.CloudflareEnabled != 1 || !cfg.CloudflareAPIToken.Valid || cfg.CloudflareAPIToken.String != "cf-token" {
		t.Fatalf("expected cloudflare token to enable DNS automation: %+v", cfg)
	}

	tlsState := &tunnelCreateState{
		OutNodes: []tunnelRuntimeNode{{
			NodeID:    2,
			Protocol:  "mtls",
			ChainType: 3,
			Port:      443,
		}},
	}
	if _, err := parseTunnelMaskConfigFromRequest(req, tlsState, 2); err == nil {
		t.Fatalf("expected mtls mask config to be rejected")
	}

	multiExitState := &tunnelCreateState{
		OutNodes: []tunnelRuntimeNode{
			{NodeID: 2, Protocol: "mwss", ChainType: 3, Port: 443},
			{NodeID: 3, Protocol: "mwss", ChainType: 3, Port: 443},
		},
	}
	if _, err := parseTunnelMaskConfigFromRequest(req, multiExitState, 2); err == nil {
		t.Fatalf("expected multi-exit mask config to be rejected")
	}
}

func TestBuildTunnelConfigsForMaskedMWSS(t *testing.T) {
	cfg := &model.TunnelMaskConfig{
		Enabled:   1,
		Domain:    "mask.example.com",
		WSPath:    "/ws",
		InnerPort: 24443,
	}

	dialer := buildTunnelDialerConfig("mwss", cfg)
	meta, ok := dialer["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected dialer metadata")
	}
	if dialer["type"] != "mwss" || meta["ws.path"] != "/ws" || meta["ws.host"] != "mask.example.com" || meta["tls.fingerprint"] != "chrome" {
		t.Fatalf("unexpected dialer config: %#v", dialer)
	}

	listener := buildTunnelListenerConfig("mws", cfg)
	listenerMeta, ok := listener["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected listener metadata")
	}
	if listener["type"] != "mws" || listenerMeta["ws.path"] != "/ws" || listenerMeta["ws.host"] != "mask.example.com" {
		t.Fatalf("unexpected listener config: %#v", listener)
	}
}

func TestParseTunnelMaskConfigSeparatesPublicAndInnerPorts(t *testing.T) {
	state := &tunnelCreateState{
		OutNodes: []tunnelRuntimeNode{{
			NodeID:    2,
			Protocol:  "mwss",
			ChainType: 3,
			Port:      defaultMaskInnerPort,
		}},
	}
	req := map[string]interface{}{
		"maskConfig": map[string]interface{}{
			"enabled":   1,
			"domain":    "mask.example.com",
			"innerPort": defaultMaskInnerPort,
		},
	}

	cfg, err := parseTunnelMaskConfigFromRequest(req, state, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.InnerPort == defaultMaskInnerPort || cfg.InnerPort == state.OutNodes[0].Port {
		t.Fatalf("expected inner port to move away from public port, got %d", cfg.InnerPort)
	}
}

func TestBuildTunnelChainServiceUsesLocalPortWhenMaskEnabled(t *testing.T) {
	cfg := &model.TunnelMaskConfig{
		Enabled:   1,
		Domain:    "mask.example.com",
		WSPath:    "/ws",
		InnerPort: 24443,
	}
	services := buildTunnelChainServiceConfig(15, tunnelRuntimeNode{
		NodeID:    2,
		Protocol:  "mwss",
		ChainType: 3,
		Port:      443,
		Mask:      cfg,
	}, &nodeRecord{TCPListenAddr: "0.0.0.0"}, 1)

	if len(services) != 1 {
		t.Fatalf("expected one service, got %d", len(services))
	}
	service := services[0]
	if service["addr"] != "127.0.0.1:24443" {
		t.Fatalf("expected local mws listener, got %#v", service["addr"])
	}
	listener := service["listener"].(map[string]interface{})
	if listener["type"] != "mws" {
		t.Fatalf("expected public mwss to become local mws, got %#v", listener)
	}
}

func TestSaveTunnelMaskConfigPreservesCloudflareToken(t *testing.T) {
	old := &model.TunnelMaskConfig{
		TunnelID:           9,
		Enabled:            1,
		Domain:             "mask.example.com",
		CloudflareAPIToken: sql.NullString{String: "secret-token", Valid: true},
	}
	next := &model.TunnelMaskConfig{
		TunnelID: 9,
		Enabled:  1,
		Domain:   "mask.example.com",
	}

	if !next.CloudflareAPIToken.Valid && old.CloudflareAPIToken.Valid {
		next.CloudflareAPIToken = old.CloudflareAPIToken
	}
	if !next.CloudflareAPIToken.Valid || next.CloudflareAPIToken.String != "secret-token" {
		t.Fatalf("expected saved token to be preserved, got %+v", next.CloudflareAPIToken)
	}
}

func TestParseTunnelMaskConfigDefaultsToExitNodeDomain(t *testing.T) {
	state := &tunnelCreateState{
		OutNodes: []tunnelRuntimeNode{{
			NodeID:    2,
			Protocol:  "mwss",
			ChainType: 3,
			Port:      443,
		}},
		Nodes: map[int64]*nodeRecord{
			2: {ID: 2, ServerIP: "edge.gekzi.com"},
		},
	}
	req := map[string]interface{}{
		"maskConfig": map[string]interface{}{
			"enabled":             1,
			"cloudflareEnabled":   1,
			"cloudflareApiToken":  "cf-token",
			"cloudflareAccountId": "account-id",
		},
	}

	cfg, err := parseTunnelMaskConfigFromRequest(req, state, 2)
	if err != nil {
		t.Fatalf("parse mask config: %v", err)
	}
	if cfg.Domain != "edge.gekzi.com" || cfg.CloudflareRecordName.String != "edge.gekzi.com" {
		t.Fatalf("expected node domain defaults, got %+v", cfg)
	}
	if !cfg.CloudflareAccountID.Valid || cfg.CloudflareAccountID.String != "account-id" {
		t.Fatalf("expected Cloudflare account id, got %+v", cfg.CloudflareAccountID)
	}
}

func TestParseTunnelMaskConfigRejectsEmptyDomainForIPNode(t *testing.T) {
	state := &tunnelCreateState{
		OutNodes: []tunnelRuntimeNode{{NodeID: 2, Protocol: "mwss", ChainType: 3, Port: 443}},
		Nodes:    map[int64]*nodeRecord{2: {ID: 2, ServerIP: "203.0.113.20", ServerIPv4: "203.0.113.20"}},
	}
	_, err := parseTunnelMaskConfigFromRequest(map[string]interface{}{
		"maskConfig": map[string]interface{}{"enabled": 1},
	}, state, 2)
	if err == nil || err.Error() != "伪装站域名为空，且出口节点连接地址不是域名" {
		t.Fatalf("expected missing domain error, got %v", err)
	}
}
