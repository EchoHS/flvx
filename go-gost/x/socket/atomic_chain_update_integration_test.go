package socket

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	corelogger "github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	_ "github.com/go-gost/x/connector/http"
	_ "github.com/go-gost/x/connector/relay"
	_ "github.com/go-gost/x/dialer/mws"
	_ "github.com/go-gost/x/dialer/tcp"
	_ "github.com/go-gost/x/handler/forward/local"
	_ "github.com/go-gost/x/handler/relay"
	_ "github.com/go-gost/x/listener/mws"
	_ "github.com/go-gost/x/listener/tcp"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/registry"
)

func TestAtomicChainUpdatePreservesForwarding(t *testing.T) {
	corelogger.SetDefault(xlogger.Nop())

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	chainName := "runtime_chain_" + suffix
	entryName := "runtime_entry_" + suffix
	exitAName := "runtime_exit_a_" + suffix
	exitBName := "runtime_exit_b_" + suffix

	originalConfig := config.Global()
	config.Set(&config.Config{})
	t.Cleanup(func() {
		_ = deleteServices(deleteServicesRequest{Services: []string{entryName, exitAName, exitBName}})
		registry.ChainRegistry().Unregister(chainName)
		config.Set(originalConfig)
	})

	echoAddr, closeEcho := startRuntimeEchoServer(t)
	defer closeEcho()

	exitAAddr := createRuntimeRelayService(t, exitAName)
	exitBAddr := createRuntimeRelayService(t, exitBName)
	if err := createChain(createChainRequest{Data: runtimeRelayChain(chainName, "exit-a", exitAAddr)}); err != nil {
		t.Fatalf("create chain: %v", err)
	}

	entryConfig := config.ServiceConfig{
		Name:     entryName,
		Addr:     "127.0.0.1:0",
		Handler:  &config.HandlerConfig{Type: "tcp", Chain: chainName},
		Listener: &config.ListenerConfig{Type: "tcp"},
		Forwarder: &config.ForwarderConfig{
			Nodes: []*config.ForwardNodeConfig{{Name: "echo", Addr: echoAddr}},
		},
	}
	if err := createServices(createServicesRequest{Data: []config.ServiceConfig{entryConfig}}); err != nil {
		t.Fatalf("create entry service: %v", err)
	}
	entryAddr := runtimeServiceAddr(t, entryName)
	assertRuntimeRoundTrip(t, entryAddr, []byte("before-update"))

	if err := updateChain(updateChainRequest{
		Chain: chainName,
		Data:  runtimeRelayChain(chainName, "exit-b", exitBAddr),
	}); err != nil {
		t.Fatalf("atomic chain update: %v", err)
	}
	if err := deleteServices(deleteServicesRequest{Services: []string{exitAName}}); err != nil {
		t.Fatalf("remove old exit: %v", err)
	}

	for i := 0; i < 20; i++ {
		assertRuntimeRoundTrip(t, entryAddr, []byte(fmt.Sprintf("after-update-%d", i)))
	}
}

func runtimeRelayChain(name, nodeName, addr string) config.ChainConfig {
	return config.ChainConfig{
		Name: name,
		Hops: []*config.HopConfig{{
			Name: "hop",
			Nodes: []*config.NodeConfig{{
				Name:      nodeName,
				Addr:      addr,
				Connector: &config.ConnectorConfig{Type: "relay"},
				Dialer:    &config.DialerConfig{Type: "mws"},
			}},
		}},
	}
}

func createRuntimeRelayService(t *testing.T, name string) string {
	t.Helper()
	serviceConfig := config.ServiceConfig{
		Name:     name,
		Addr:     "127.0.0.1:0",
		Handler:  &config.HandlerConfig{Type: "relay"},
		Listener: &config.ListenerConfig{Type: "mws"},
	}
	if err := createServices(createServicesRequest{Data: []config.ServiceConfig{serviceConfig}}); err != nil {
		t.Fatalf("create relay service %s: %v", name, err)
	}
	return runtimeServiceAddr(t, name)
}

func runtimeServiceAddr(t *testing.T, name string) string {
	t.Helper()
	service := registry.ServiceRegistry().Get(name)
	if service == nil || service.Addr() == nil {
		t.Fatalf("service %s has no runtime address", name)
	}
	return service.Addr().String()
}

func startRuntimeEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func assertRuntimeRoundTrip(t *testing.T, addr string, payload []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial entry runtime: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through runtime: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read through runtime: %v", err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("unexpected runtime response: got %q want %q", response, payload)
	}
}
