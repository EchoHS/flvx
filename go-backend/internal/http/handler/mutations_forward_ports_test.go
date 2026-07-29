package handler

import (
	"path/filepath"
	"testing"
	"time"

	"go-backend/internal/store/repo"
)

func TestBuildForwardPortEntriesWithPreservedInIP(t *testing.T) {
	entryNodeIDs := []int64{10, 20, 30}
	oldPorts := []forwardPortRecord{
		{NodeID: 10, Port: 10001, InIP: ""},
		{NodeID: 10, Port: 10002, InIP: "10.0.0.10"},
		{NodeID: 20, Port: 10003, InIP: "10.0.0.20"},
	}

	entries := buildForwardPortEntriesWithPreservedInIP(entryNodeIDs, oldPorts, 18080)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	if entries[0].NodeID != 10 || entries[0].Port != 18080 || entries[0].InIP != "10.0.0.10" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].NodeID != 20 || entries[1].Port != 18080 || entries[1].InIP != "10.0.0.20" {
		t.Fatalf("unexpected second entry: %+v", entries[1])
	}
	if entries[2].NodeID != 30 || entries[2].Port != 18080 || entries[2].InIP != "" {
		t.Fatalf("unexpected third entry: %+v", entries[2])
	}
}

func TestBuildForwardPortEntriesWithPreservedInIP_EmptyOldPorts(t *testing.T) {
	entryNodeIDs := []int64{99}
	entries := buildForwardPortEntriesWithPreservedInIP(entryNodeIDs, nil, 17000)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].NodeID != 99 || entries[0].Port != 17000 || entries[0].InIP != "" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
}

func TestSyncTunnelForwardsEntryPortsPreservesExistingEntryMapping(t *testing.T) {
	h, forwardID := setupTunnelForwardPortSyncTest(t)

	if err := h.syncTunnelForwardsEntryPorts(50, []int64{10, 20}); err != nil {
		t.Fatalf("sync entry ports: %v", err)
	}
	ports, err := h.listForwardPorts(forwardID)
	if err != nil {
		t.Fatalf("list forward ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected two entry mappings, got %+v", ports)
	}
	if ports[0].NodeID != 10 || ports[0].Port != 12001 || ports[0].InIP != "10.0.0.10" {
		t.Fatalf("existing entry mapping changed: %+v", ports[0])
	}
	if ports[1].NodeID != 20 || ports[1].Port != 12001 || ports[1].InIP != "" {
		t.Fatalf("unexpected new entry mapping: %+v", ports[1])
	}
}

func TestSyncTunnelForwardsEntryPortsRollsBackOnInvalidEntry(t *testing.T) {
	h, forwardID := setupTunnelForwardPortSyncTest(t)

	if err := h.syncTunnelForwardsEntryPorts(50, []int64{10, 999}); err == nil {
		t.Fatal("expected missing entry node to fail")
	}
	ports, err := h.listForwardPorts(forwardID)
	if err != nil {
		t.Fatalf("list forward ports: %v", err)
	}
	if len(ports) != 1 || ports[0].NodeID != 10 || ports[0].Port != 12001 || ports[0].InIP != "10.0.0.10" {
		t.Fatalf("failed sync left partial mappings: %+v", ports)
	}
}

func TestSelectForwardPortsForNodesOnlyReturnsNewEntries(t *testing.T) {
	ports := []forwardPortRecord{{NodeID: 10, Port: 12001}, {NodeID: 20, Port: 12001}}
	selected, err := selectForwardPortsForNodes(ports, []int64{20})
	if err != nil {
		t.Fatalf("select ports: %v", err)
	}
	if len(selected) != 1 || selected[0].NodeID != 20 {
		t.Fatalf("expected only new entry node, got %+v", selected)
	}

	selected, err = selectForwardPortsForNodes(ports, []int64{})
	if err != nil {
		t.Fatalf("select empty target: %v", err)
	}
	if len(selected) != 0 {
		t.Fatalf("expected removal-only update to skip retained entries, got %+v", selected)
	}
}

func setupTunnelForwardPortSyncTest(t *testing.T) (*Handler, int64) {
	t.Helper()
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	h := &Handler{repo: r}
	now := time.Now().UnixMilli()
	if err := r.DB().Exec(`
		INSERT INTO node(id, name, secret, server_ip, port, created_time, status, tcp_listen_addr, udp_listen_addr, is_remote)
		VALUES
			(10, 'entry-a', 'secret-a', '10.0.0.10', '12000-12010', ?, 1, '[::]', '[::]', 0),
			(20, 'entry-b', 'secret-b', '10.0.0.20', '12000-12010', ?, 1, '[::]', '[::]', 0)
	`, now, now).Error; err != nil {
		t.Fatalf("insert nodes: %v", err)
	}
	if err := r.DB().Exec(`
		INSERT INTO tunnel(id, name, traffic_ratio, type, protocol, flow, created_time, updated_time, status, inx)
		VALUES(50, 'tunnel', 1, 2, 'mwss', 1, ?, ?, 1, 1)
	`, now, now).Error; err != nil {
		t.Fatalf("insert tunnel: %v", err)
	}
	if err := r.DB().Exec(`
		INSERT INTO forward(id, user_id, user_name, name, tunnel_id, remote_addr, strategy, created_time, updated_time, status, inx)
		VALUES(70, 1, 'tester', 'forward', 50, '203.0.113.10:443', 'fifo', ?, ?, 1, 1)
	`, now, now).Error; err != nil {
		t.Fatalf("insert forward: %v", err)
	}
	if err := r.DB().Exec(`
		INSERT INTO forward_port(forward_id, node_id, port, in_ip)
		VALUES(70, 10, 12001, '10.0.0.10')
	`).Error; err != nil {
		t.Fatalf("insert forward port: %v", err)
	}
	return h, 70
}
