package handler

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go-backend/internal/store/repo"
	"go-backend/internal/ws"
)

func TestSyncForwardServicesOnNodesDoesNotRestartExistingEntry(t *testing.T) {
	h, forward := setupForwardEntryRuntimeSyncTest(t)
	calledNodes := make([]int64, 0)
	h.nodeCommandHook = func(nodeID int64, commandType string, data interface{}, timeout time.Duration) (ws.CommandResult, error) {
		if commandType == "UpdateService" {
			calledNodes = append(calledNodes, nodeID)
		}
		return ws.CommandResult{Success: true}, nil
	}

	warnings, err := h.syncForwardServicesOnNodesWithWarnings(forward, "UpdateService", true, []int64{20})
	if err != nil {
		t.Fatalf("sync new entry: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(calledNodes) != 1 || calledNodes[0] != 20 {
		t.Fatalf("expected only new entry node 20 to be updated, got %v", calledNodes)
	}
}

func TestSyncForwardServicesOnNodesReturnsAgentFailure(t *testing.T) {
	h, forward := setupForwardEntryRuntimeSyncTest(t)
	h.nodeCommandHook = func(nodeID int64, commandType string, data interface{}, timeout time.Duration) (ws.CommandResult, error) {
		return ws.CommandResult{}, errors.New("injected agent failure")
	}

	_, err := h.syncForwardServicesOnNodesWithWarnings(forward, "UpdateService", true, []int64{20})
	if err == nil {
		t.Fatal("expected agent failure to be returned")
	}
}

func setupForwardEntryRuntimeSyncTest(t *testing.T) (*Handler, *forwardRecord) {
	t.Helper()
	r, err := repo.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	h := New(r, "secret")
	now := time.Now().UnixMilli()
	userID, err := r.CreateUser("tester", "hash", 1, now+86400000, 1, 1, 100, 1, 0, now)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := r.DB().Exec(`
		INSERT INTO node(id, name, secret, server_ip, port, created_time, status, tcp_listen_addr, udp_listen_addr, is_remote, forward_mode)
		VALUES
			(10, 'entry-a', 'secret-a', '10.0.0.10', '12000-12010', ?, 1, '[::]', '[::]', 0, 'gost'),
			(20, 'entry-b', 'secret-b', '10.0.0.20', '12000-12010', ?, 1, '[::]', '[::]', 0, 'gost')
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
		INSERT INTO chain_tunnel(tunnel_id, chain_type, node_id, port, strategy, inx, protocol)
		VALUES
			(50, '1', 10, 24443, 'round', 1, 'mwss'),
			(50, '1', 20, 24443, 'round', 2, 'mwss')
	`).Error; err != nil {
		t.Fatalf("insert chain nodes: %v", err)
	}
	if err := r.DB().Exec(`
		INSERT INTO forward(id, user_id, user_name, name, tunnel_id, remote_addr, strategy, created_time, updated_time, status, inx)
		VALUES(70, ?, 'tester', 'forward', 50, '203.0.113.10:443', 'fifo', ?, ?, 1, 1)
	`, userID, now, now).Error; err != nil {
		t.Fatalf("insert forward: %v", err)
	}
	if err := r.DB().Exec(`
		INSERT INTO forward_port(forward_id, node_id, port)
		VALUES(70, 10, 12001), (70, 20, 12001)
	`).Error; err != nil {
		t.Fatalf("insert forward ports: %v", err)
	}
	forward, err := h.getForwardRecord(70)
	if err != nil {
		t.Fatalf("get forward: %v", err)
	}
	return h, forward
}
