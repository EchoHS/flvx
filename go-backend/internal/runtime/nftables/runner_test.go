package nftables

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestAuthMethodsDefaultToPrivateKey(t *testing.T) {
	privateKey := mustGeneratePrivateKey(t)
	methods, err := authMethods(SSHConfig{PrivateKey: privateKey})
	if err != nil {
		t.Fatalf("authMethods: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(methods))
	}
}

func TestAuthMethodsDefaultPrivateKeyRequiresKey(t *testing.T) {
	_, err := authMethods(SSHConfig{})
	if err == nil || !strings.Contains(err.Error(), "SSH 私钥不能为空") {
		t.Fatalf("expected private key required error, got %v", err)
	}
}

func mustGeneratePrivateKey(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}
