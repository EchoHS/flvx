package handler

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"go-backend/internal/store/model"
)

const (
	defaultTunnelProbeTargetHost = "www.bing.com"
	defaultTunnelProbeTargetPort = 443
)

type tunnelProbeTarget struct {
	Host string
	Port int
}

func defaultTunnelProbeTarget() tunnelProbeTarget {
	return tunnelProbeTarget{Host: defaultTunnelProbeTargetHost, Port: defaultTunnelProbeTargetPort}
}

func normalizeTunnelProbeTarget(host string, port int) (tunnelProbeTarget, bool, error) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}

	if host == "" && port == 0 {
		return defaultTunnelProbeTarget(), false, nil
	}
	if host == "" {
		return tunnelProbeTarget{}, false, errors.New("测试目标 Host 不能为空")
	}
	if port <= 0 || port > 65535 {
		return tunnelProbeTarget{}, false, errors.New("测试目标端口必须是 1-65535")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#") || strings.ContainsAny(host, " \t\r\n") {
		return tunnelProbeTarget{}, false, errors.New("测试目标 Host 不能包含协议或路径")
	}

	return tunnelProbeTarget{Host: host, Port: port}, true, nil
}

func parseTunnelProbeTargetFromRequest(req map[string]interface{}) (tunnelProbeTarget, bool, error) {
	if req == nil {
		return defaultTunnelProbeTarget(), false, nil
	}
	return normalizeTunnelProbeTarget(asString(req["probeTargetHost"]), asInt(req["probeTargetPort"], 0))
}

func effectiveTunnelProbeTarget(tunnel *model.Tunnel) tunnelProbeTarget {
	if tunnel == nil {
		return defaultTunnelProbeTarget()
	}
	return defaultTunnelProbeTarget()
}

func effectiveTunnelProbeTargetValues(host string, port int) tunnelProbeTarget {
	target, configured, err := normalizeTunnelProbeTarget(host, port)
	if err != nil || !configured {
		return defaultTunnelProbeTarget()
	}
	return target
}

func formatTunnelProbeTarget(target tunnelProbeTarget) string {
	if addr, err := netip.ParseAddr(target.Host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", target.Host, target.Port)
	}
	return fmt.Sprintf("%s:%d", target.Host, target.Port)
}
