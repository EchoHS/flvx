package socket

import (
	"errors"
	"net"
	"testing"

	corelogger "github.com/go-gost/core/logger"
	"github.com/go-gost/core/service"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/registry"
)

type recordingService struct {
	closed int
}

func TestUpdateServicesRestoresOldRuntimeWhenLaterServiceFails(t *testing.T) {
	corelogger.SetDefault(xlogger.Nop())

	oldName := "rollback_old_service_tdd"
	newName := "rollback_failing_service_tdd"
	existing := &recordingService{}
	registry.ServiceRegistry().Unregister(oldName)
	registry.ServiceRegistry().Unregister(newName)
	defer registry.ServiceRegistry().Unregister(oldName)
	defer registry.ServiceRegistry().Unregister(newName)
	if err := registry.ServiceRegistry().Register(oldName, service.Service(existing)); err != nil {
		t.Fatalf("register existing service: %v", err)
	}

	originalConfig := config.Global()
	defer config.Set(originalConfig)
	oldConfig := config.ServiceConfig{Name: oldName, Addr: "127.0.0.1:10001"}
	config.Set(&config.Config{Services: []*config.ServiceConfig{&oldConfig}})

	originalParser := parseServiceConfig
	defer func() { parseServiceConfig = originalParser }()
	parseServiceConfig = func(cfg *config.ServiceConfig) (service.Service, error) {
		if cfg.Addr == "invalid" {
			return nil, errors.New("injected parse failure")
		}
		return &recordingService{}, nil
	}

	err := updateServices(updateServicesRequest{Data: []config.ServiceConfig{
		{Name: oldName, Addr: "127.0.0.1:10002"},
		{Name: newName, Addr: "invalid"},
	}})
	if err == nil {
		t.Fatal("expected update failure")
	}
	if registry.ServiceRegistry().Get(oldName) == nil {
		t.Fatal("expected old service runtime to be restored")
	}
	if registry.ServiceRegistry().Get(newName) != nil {
		t.Fatal("failing upsert left a partial service runtime")
	}
	if existing.closed == 0 {
		t.Fatal("expected original runtime to be closed during attempted update")
	}
	if got := findServiceConfig(oldName); got == nil || got.Addr != oldConfig.Addr {
		t.Fatalf("expected old config to remain active, got %+v", got)
	}
}

func (s *recordingService) Serve() error   { return nil }
func (s *recordingService) Addr() net.Addr { return nil }
func (s *recordingService) Close() error {
	s.closed++
	return nil
}

func TestUpdateServicesSkipsUnchangedServiceWithoutRestart(t *testing.T) {
	corelogger.SetDefault(xlogger.Nop())

	name := "unchanged_service_tdd"
	existing := &recordingService{}

	registry.ServiceRegistry().Unregister(name)
	defer registry.ServiceRegistry().Unregister(name)
	if err := registry.ServiceRegistry().Register(name, service.Service(existing)); err != nil {
		t.Fatalf("register existing service: %v", err)
	}

	originalConfig := config.Global()
	defer config.Set(originalConfig)
	serviceConfig := config.ServiceConfig{Name: name, Addr: "127.0.0.1:0"}
	config.Set(&config.Config{Services: []*config.ServiceConfig{&serviceConfig}})

	if err := updateServices(updateServicesRequest{Data: []config.ServiceConfig{serviceConfig}}); err != nil {
		t.Fatalf("unchanged update should succeed without parsing/restarting: %v", err)
	}
	if existing.closed != 0 {
		t.Fatalf("unchanged service was restarted, closed %d times", existing.closed)
	}
	if got := registry.ServiceRegistry().Get(name); got != service.Service(existing) {
		t.Fatalf("expected existing service to remain registered")
	}
}
