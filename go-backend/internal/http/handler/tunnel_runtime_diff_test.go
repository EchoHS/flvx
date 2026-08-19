package handler

import (
	"testing"
	"time"

	"go-backend/internal/ws"
)

func TestApplyTunnelRuntimeUpsertReconcilesAllEntriesAndExit(t *testing.T) {
	h := &Handler{bestExit: newBestExitManager()}
	var calls []struct {
		nodeID int64
		name   string
	}
	h.nodeCommandHook = func(nodeID int64, commandType string, _ interface{}, _ time.Duration) (ws.CommandResult, error) {
		calls = append(calls, struct {
			nodeID int64
			name   string
		}{nodeID: nodeID, name: commandType})
		return ws.CommandResult{Success: true}, nil
	}

	if _, _, err := h.applyTunnelRuntimeUpsert(testTunnelRuntimeState([]int64{10, 20})); err != nil {
		t.Fatalf("apply upsert: %v", err)
	}

	want := []struct {
		nodeID int64
		name   string
	}{
		{nodeID: 10, name: "UpdateChains"},
		{nodeID: 20, name: "UpdateChains"},
		{nodeID: 30, name: "UpdateService"},
	}
	if len(calls) != len(want) {
		t.Fatalf("expected full tunnel runtime reconcile, got %#v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("unexpected command %d: got %#v want %#v", i, calls[i], want[i])
		}
	}
}

func TestApplyTunnelRuntimeUpsertReconcilesUnchangedRuntime(t *testing.T) {
	h := &Handler{bestExit: newBestExitManager()}
	var calls []struct {
		nodeID int64
		name   string
	}
	h.nodeCommandHook = func(nodeID int64, commandType string, _ interface{}, _ time.Duration) (ws.CommandResult, error) {
		calls = append(calls, struct {
			nodeID int64
			name   string
		}{nodeID: nodeID, name: commandType})
		return ws.CommandResult{Success: true}, nil
	}

	if _, _, err := h.applyTunnelRuntimeUpsert(testTunnelRuntimeState([]int64{10})); err != nil {
		t.Fatalf("apply upsert: %v", err)
	}

	want := []struct {
		nodeID int64
		name   string
	}{
		{nodeID: 10, name: "UpdateChains"},
		{nodeID: 30, name: "UpdateService"},
	}
	if len(calls) != len(want) {
		t.Fatalf("expected unchanged runtime to be reconciled, got %#v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("unexpected command %d: got %#v want %#v", i, calls[i], want[i])
		}
	}
}

func TestLockTunnelRuntimeSerializesSameTunnelOnly(t *testing.T) {
	h := &Handler{}
	releaseFirst := h.lockTunnelRuntime(7)
	acquired := make(chan struct{})
	go func() {
		releaseSecond := h.lockTunnelRuntime(7)
		close(acquired)
		releaseSecond()
	}()

	select {
	case <-acquired:
		t.Fatal("same tunnel runtime lock was not serialized")
	case <-time.After(20 * time.Millisecond):
	}
	releaseFirst()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("same tunnel runtime lock did not become available")
	}

	releaseOther := h.lockTunnelRuntime(8)
	releaseOther()
}

func testTunnelRuntimeState(entryIDs []int64) *tunnelCreateState {
	nodes := map[int64]*nodeRecord{
		10: testRuntimeNode(10, "entry-a", "10.0.0.10"),
		20: testRuntimeNode(20, "entry-b", "10.0.0.20"),
		30: testRuntimeNode(30, "exit", "10.0.0.30"),
	}
	inNodes := make([]tunnelRuntimeNode, 0, len(entryIDs))
	for _, id := range entryIDs {
		inNodes = append(inNodes, tunnelRuntimeNode{NodeID: id, Protocol: "mwss", Strategy: "round", ChainType: 1})
	}
	return &tunnelCreateState{
		TunnelID:     70,
		Type:         2,
		InNodes:      inNodes,
		OutNodes:     []tunnelRuntimeNode{{NodeID: 30, Protocol: "mwss", Strategy: "round", ChainType: 3, Port: 24443}},
		Nodes:        nodes,
		IPPreference: "",
	}
}

func testRuntimeNode(id int64, name, ip string) *nodeRecord {
	return &nodeRecord{
		ID:            id,
		Name:          name,
		ServerIP:      ip,
		ServerIPv4:    ip,
		Status:        1,
		TCPListenAddr: "0.0.0.0",
	}
}
