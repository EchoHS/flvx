package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
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

func TestFullTunnelReconcileRestoresEveryRuntimeNodeWithoutDeletes(t *testing.T) {
	h, _ := setupForwardEntryRuntimeSyncTest(t)
	seedTestTunnelMaskConfig(t, h)
	type commandCall struct {
		nodeID  int64
		command string
	}
	var calls []commandCall
	var exitService []map[string]interface{}
	h.nodeCommandHook = func(nodeID int64, commandType string, data interface{}, _ time.Duration) (ws.CommandResult, error) {
		calls = append(calls, commandCall{nodeID: nodeID, command: commandType})
		if nodeID == 30 && commandType == "UpdateService" {
			exitService, _ = data.([]map[string]interface{})
		}
		return ws.CommandResult{Success: true}, nil
	}

	if err := h.reconcileTunnelAndForwards(50, 20); err != nil {
		t.Fatalf("reconcile tunnel: %v", err)
	}
	want := []commandCall{
		{nodeID: 10, command: "UpdateChains"},
		{nodeID: 20, command: "UpdateChains"},
		{nodeID: 30, command: "UpdateService"},
		{nodeID: 10, command: "UpdateService"},
		{nodeID: 20, command: "UpdateService"},
	}
	if len(calls) != len(want) {
		t.Fatalf("unexpected full redeploy commands: got %#v want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("unexpected full redeploy command %d: got %#v want %#v", i, calls[i], want[i])
		}
	}
	if len(exitService) != 1 || exitService[0]["addr"] != "127.0.0.1:24444" {
		t.Fatalf("entry recovery changed masked exit listener: %#v", exitService)
	}
	listener := asMap(exitService[0]["listener"])
	if listener["type"] != "mws" {
		t.Fatalf("entry recovery changed masked exit protocol: %#v", listener)
	}
}

func TestExitTunnelReconcileRestoresMaskSite(t *testing.T) {
	h, _ := setupForwardEntryRuntimeSyncTest(t)
	seedTestTunnelMaskConfig(t, h)
	type commandCall struct {
		nodeID  int64
		command string
	}
	var calls []commandCall
	h.nodeCommandHook = func(nodeID int64, commandType string, _ interface{}, _ time.Duration) (ws.CommandResult, error) {
		calls = append(calls, commandCall{nodeID: nodeID, command: commandType})
		return ws.CommandResult{Success: true}, nil
	}

	if err := h.reconcileTunnelAndForwards(50, 30); err != nil {
		t.Fatalf("reconcile exit: %v", err)
	}
	want := []commandCall{
		{nodeID: 10, command: "UpdateChains"},
		{nodeID: 20, command: "UpdateChains"},
		{nodeID: 30, command: "UpdateService"},
		{nodeID: 30, command: "ConfigureMaskSite"},
		{nodeID: 10, command: "UpdateService"},
		{nodeID: 20, command: "UpdateService"},
	}
	if len(calls) != len(want) {
		t.Fatalf("unexpected exit reconcile commands: got %#v want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("unexpected exit reconcile command %d: got %#v want %#v", i, calls[i], want[i])
		}
	}
}

func TestConcurrentTunnelReconcilesAreSerialized(t *testing.T) {
	h, _ := setupForwardEntryRuntimeSyncTest(t)
	firstCommandEntered := make(chan struct{})
	releaseFirstCommand := make(chan struct{})
	overlapped := make(chan struct{}, 1)
	var firstCommand sync.Once
	var activeMu sync.Mutex
	activeCommands := 0

	h.nodeCommandHook = func(_ int64, _ string, _ interface{}, _ time.Duration) (ws.CommandResult, error) {
		activeMu.Lock()
		activeCommands++
		if activeCommands > 1 {
			select {
			case overlapped <- struct{}{}:
			default:
			}
		}
		activeMu.Unlock()

		firstCommand.Do(func() {
			close(firstCommandEntered)
			<-releaseFirstCommand
		})

		activeMu.Lock()
		activeCommands--
		activeMu.Unlock()
		return ws.CommandResult{Success: true}, nil
	}

	errs := make(chan error, 2)
	go func() { errs <- h.reconcileTunnelAndForwards(50, 10) }()
	select {
	case <-firstCommandEntered:
	case <-time.After(time.Second):
		t.Fatal("first reconcile did not issue a command")
	}
	go func() { errs <- h.reconcileTunnelAndForwards(50, 20) }()

	select {
	case <-overlapped:
		t.Fatal("same tunnel reconciles executed concurrently")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirstCommand)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("reconcile tunnel: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("serialized reconcile did not complete")
		}
	}
}

func TestTunnelUpdateAddingEntryReconcilesEveryChainWithoutDeletingRuntime(t *testing.T) {
	h, _ := setupForwardEntryRuntimeSyncTest(t)
	if err := h.repo.DB().Exec("DELETE FROM chain_tunnel WHERE tunnel_id = ? AND node_id = ?", 50, 20).Error; err != nil {
		t.Fatalf("remove second entry from initial tunnel: %v", err)
	}
	if err := h.repo.DB().Exec("DELETE FROM forward_port WHERE forward_id = ? AND node_id = ?", 70, 20).Error; err != nil {
		t.Fatalf("remove second entry forward port: %v", err)
	}

	type commandCall struct {
		nodeID  int64
		command string
	}
	var calls []commandCall
	h.nodeCommandHook = func(nodeID int64, commandType string, _ interface{}, _ time.Duration) (ws.CommandResult, error) {
		calls = append(calls, commandCall{nodeID: nodeID, command: commandType})
		return ws.CommandResult{Success: true}, nil
	}

	body := bytes.NewBufferString(`{
		"id":50,
		"name":"tunnel",
		"type":2,
		"flow":1,
		"trafficRatio":1,
		"status":1,
		"inNodeId":[
			{"nodeId":10,"protocol":"mwss","strategy":"round"},
			{"nodeId":20,"protocol":"mwss","strategy":"round"}
		],
		"chainNodes":[],
		"outNodeId":[
			{"nodeId":30,"protocol":"mwss","strategy":"round","port":24443}
		]
	}`)
	res := httptest.NewRecorder()
	h.tunnelUpdate(res, httptest.NewRequest(http.MethodPost, "/api/v1/tunnel/update", body))
	var response struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode tunnel update response: %v", err)
	}
	if response.Code != 0 {
		t.Fatalf("tunnel update failed: code=%d msg=%s", response.Code, response.Msg)
	}

	want := []commandCall{
		{nodeID: 10, command: "UpdateChains"},
		{nodeID: 20, command: "UpdateChains"},
		{nodeID: 30, command: "UpdateService"},
		{nodeID: 20, command: "UpdateService"},
	}
	if len(calls) != len(want) {
		t.Fatalf("unexpected tunnel update commands: got %#v want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("unexpected tunnel update command %d: got %#v want %#v", i, calls[i], want[i])
		}
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
			(20, 'entry-b', 'secret-b', '10.0.0.20', '12000-12010', ?, 1, '[::]', '[::]', 0, 'gost'),
			(30, 'exit', 'secret-c', '10.0.0.30', '24443', ?, 1, '[::]', '[::]', 0, 'gost')
	`, now, now, now).Error; err != nil {
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
			(50, '1', 20, 24443, 'round', 2, 'mwss'),
			(50, '3', 30, 24443, 'round', 3, 'mwss')
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

func seedTestTunnelMaskConfig(t *testing.T, h *Handler) {
	t.Helper()
	now := time.Now().UnixMilli()
	if err := h.repo.DB().Exec(`
		INSERT INTO tunnel_mask_config(tunnel_id, enabled, domain, ws_path, site_repo, site_dir, acme_email, inner_port, status, last_error, created_time, updated_time)
		VALUES(50, 1, 'mask.example.com', '/ws', 'https://example.com/site.git', '/var/www/mask', 'admin@example.com', 24444, 'active', '', ?, ?)
	`, now, now).Error; err != nil {
		t.Fatalf("insert mask config: %v", err)
	}
}
