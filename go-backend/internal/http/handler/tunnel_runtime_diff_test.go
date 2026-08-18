package handler

import (
	"testing"
	"time"

	"go-backend/internal/ws"
)

func TestApplyTunnelRuntimeDiffOnlyDeploysAddedEntry(t *testing.T) {
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

	oldState := testTunnelRuntimeState([]int64{10})
	newState := testTunnelRuntimeState([]int64{10, 20})
	if _, _, err := h.applyTunnelRuntimeDiff(oldState, newState); err != nil {
		t.Fatalf("apply diff: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected only delete/add on new entry, got %#v", calls)
	}
	if calls[0].nodeID != 20 || calls[0].name != "DeleteChains" {
		t.Fatalf("unexpected first command: %#v", calls[0])
	}
	if calls[1].nodeID != 20 || calls[1].name != "AddChains" {
		t.Fatalf("unexpected second command: %#v", calls[1])
	}
}

func TestApplyTunnelRuntimeDiffUpdatesChangedChainAndServiceOnly(t *testing.T) {
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

	oldState := testTunnelRuntimeState([]int64{10})
	newState := testTunnelRuntimeState([]int64{10})
	newState.OutNodes[0].Port = 24444
	if _, _, err := h.applyTunnelRuntimeDiff(oldState, newState); err != nil {
		t.Fatalf("apply diff: %v", err)
	}

	if len(calls) != 3 {
		t.Fatalf("expected changed entry chain and exit service, got %#v", calls)
	}
	if calls[0].nodeID != 10 || calls[0].name != "DeleteChains" {
		t.Fatalf("unexpected chain delete: %#v", calls[0])
	}
	if calls[1].nodeID != 10 || calls[1].name != "AddChains" {
		t.Fatalf("unexpected chain add: %#v", calls[1])
	}
	if calls[2].nodeID != 30 || calls[2].name != "UpdateService" {
		t.Fatalf("unexpected exit service update: %#v", calls[2])
	}
}

func TestApplyTunnelRuntimeOnNodeOnlyRebuildsSelectedEntry(t *testing.T) {
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

	if err := h.applyTunnelRuntimeOnNode(testTunnelRuntimeState([]int64{10, 20}), 20); err != nil {
		t.Fatalf("apply node runtime: %v", err)
	}
	if len(calls) != 2 || calls[0].nodeID != 20 || calls[0].name != "DeleteChains" || calls[1].nodeID != 20 || calls[1].name != "AddChains" {
		t.Fatalf("expected only selected entry chain rebuild, got %#v", calls)
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
