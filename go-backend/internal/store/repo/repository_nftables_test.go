package repo

import (
	"strings"
	"testing"
	"time"
)

func TestNftablesNodeModeSSHConfigAndBindingPersistence(t *testing.T) {
	r, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	now := time.Now().UnixMilli()
	if err := r.CreateNode(
		"nft-node",
		"secret",
		"203.0.113.10",
		nil,
		nil,
		"10000-20000",
		nil,
		nil,
		nil,
		nil,
		nil,
		0,
		0,
		0,
		now,
		1,
		"[::]",
		"[::]",
		1,
		0,
		nil,
		nil,
		nil,
		nil,
		"nftables",
	); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	nodes, err := r.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	nodeID := nodes[0]["id"].(int64)
	if got := nodes[0]["forwardMode"]; got != "nftables" {
		t.Fatalf("expected forwardMode nftables, got %#v", got)
	}

	cfg := NftSSHConfigInput{
		Host:       "203.0.113.10",
		Port:       22,
		Username:   "root",
		AuthType:   "private_key",
		PrivateKey: "encrypted-private-key",
		SudoMode:   "none",
	}
	if err := r.UpsertNodeSSHConfig(nodeID, cfg, now); err != nil {
		t.Fatalf("UpsertNodeSSHConfig: %v", err)
	}
	loaded, err := r.GetNodeSSHConfig(nodeID)
	if err != nil {
		t.Fatalf("GetNodeSSHConfig: %v", err)
	}
	if loaded.Host != cfg.Host || loaded.Port != cfg.Port || loaded.Username != cfg.Username || loaded.AuthType != cfg.AuthType {
		t.Fatalf("unexpected ssh config: %+v", loaded)
	}

	binding := NftRuleBindingInput{
		ForwardID:  42,
		NodeID:     nodeID,
		InPort:     24000,
		Protocols:  "tcp,udp",
		TargetAddr: "198.51.100.20:443",
		BindIP:     "",
		RuleHash:   "hash-a",
		Status:     "applied",
		LastError:  "",
	}
	if err := r.UpsertNftRuleBinding(binding, now); err != nil {
		t.Fatalf("UpsertNftRuleBinding: %v", err)
	}
	bindings, err := r.ListNftRuleBindingsByNode(nodeID)
	if err != nil {
		t.Fatalf("ListNftRuleBindingsByNode: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].ForwardID != 42 || bindings[0].RuleHash != "hash-a" || bindings[0].Status != "applied" {
		t.Fatalf("unexpected binding: %+v", bindings[0])
	}

	if err := r.MarkNftRuleBindingError(42, nodeID, "nft failed", now+1); err != nil {
		t.Fatalf("MarkNftRuleBindingError: %v", err)
	}
	bindings, err = r.ListNftRuleBindingsByNode(nodeID)
	if err != nil {
		t.Fatalf("ListNftRuleBindingsByNode after error: %v", err)
	}
	if bindings[0].Status != "error" || !strings.Contains(bindings[0].LastError, "nft failed") {
		t.Fatalf("expected error binding, got %+v", bindings[0])
	}

	if err := r.DeleteNftRuleBindingsByForward(42); err != nil {
		t.Fatalf("DeleteNftRuleBindingsByForward: %v", err)
	}
	bindings, err = r.ListNftRuleBindingsByNode(nodeID)
	if err != nil {
		t.Fatalf("ListNftRuleBindingsByNode after delete: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("expected no bindings after delete, got %+v", bindings)
	}
}

func TestUpdateNodeWithoutForwardModePreservesExistingMode(t *testing.T) {
	r, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	now := time.Now().UnixMilli()
	if err := r.CreateNode(
		"nft-node",
		"secret",
		"203.0.113.11",
		nil,
		nil,
		"10000-20000",
		nil,
		nil,
		nil,
		nil,
		nil,
		0,
		0,
		0,
		now,
		1,
		"[::]",
		"[::]",
		1,
		0,
		nil,
		nil,
		nil,
		nil,
		"nftables",
	); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	nodes, err := r.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	nodeID := nodes[0]["id"].(int64)

	if err := r.UpdateNode(
		nodeID,
		"nft-node-updated",
		"203.0.113.11",
		nil,
		nil,
		"10000-20000",
		nil,
		nil,
		nil,
		nil,
		nil,
		"",
		0,
		0,
		0,
		"[::]",
		"[::]",
		now+1,
	); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	gotNode, err := r.GetNodeRecord(nodeID)
	if err != nil {
		t.Fatalf("GetNodeRecord: %v", err)
	}
	if gotNode == nil {
		t.Fatal("expected node record, got nil")
	}
	if gotNode.ForwardMode != "nftables" {
		t.Fatalf("expected mapped forward mode nftables, got %q", gotNode.ForwardMode)
	}

	nodes, err = r.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes after update: %v", err)
	}
	if got := nodes[0]["forwardMode"]; got != "nftables" {
		t.Fatalf("expected persisted forwardMode nftables after update, got %#v", got)
	}
}
