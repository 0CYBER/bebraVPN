//go:build windows

package singtun

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/0CYBER/bebravpn/internal/utils"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sbjson "github.com/sagernet/sing/common/json"
)

const (
	InterfaceName = "bebraTun"
	tunAddress    = "172.19.0.1/30"
)

type Manager struct {
	instance *box.Box
	cancel   context.CancelFunc
}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) Start(sys *config.System, logLevel string) error {
	if err := utils.EnsureWintun(); err != nil {
		return fmt.Errorf("failed to ensure wintun.dll: %w", err)
	}

	if m.instance != nil {
		_ = m.Stop()
	}

	configJSON, err := buildConfig(sys, logLevel)
	if err != nil {
		return err
	}
	_ = persistConfig(configJSON)

	parseCtx := include.Context(context.Background())
	options, err := sbjson.UnmarshalExtendedContext[option.Options](parseCtx, configJSON)
	if err != nil {
		return fmt.Errorf("failed to decode sing-box config: %w", err)
	}

	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create sing-box TUN frontend: %w", err)
	}

	if err := instance.Start(); err != nil {
		cancel()
		_ = instance.Close()
		return fmt.Errorf("failed to start sing-box TUN frontend: %w", err)
	}

	m.instance = instance
	m.cancel = cancel
	return nil
}

func (m *Manager) Stop() error {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if m.instance != nil {
		err := m.instance.Close()
		m.instance = nil
		return err
	}
	return nil
}

func (m *Manager) WaitUntilReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = checkReady()
		if lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tun frontend did not become ready before timeout")
	}
	return lastErr
}

func checkReady() error {
	script := fmt.Sprintf(`
$adapter = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue
if (-not $adapter) { throw 'adapter not found' }
$addr = Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
	Where-Object { $_.IPAddress -eq '172.19.0.1' } |
	Select-Object -First 1
if (-not $addr) { throw 'adapter IPv4 not configured' }
$route = Get-NetRoute -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
	Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1') } |
	Select-Object -First 1
if (-not $route) { throw 'default route is not attached to tun' }
Write-Output ready
`, InterfaceName, InterfaceName, InterfaceName)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(strings.TrimSpace(string(output)), "ready") {
		return fmt.Errorf("unexpected readiness output: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func buildConfig(sys *config.System, logLevel string) ([]byte, error) {
	socksPort := sys.SocksPort
	if socksPort == 0 {
		socksPort = 10808
	}

	domainExact, domainSuffix := buildDomainMatchers(sys.BypassDomains)
	rules := []map[string]interface{}{}

	if len(sys.BypassApps) > 0 {
		rules = append(rules, map[string]interface{}{
			"process_name": sys.BypassApps,
			"action":       "route",
			"outbound":     "direct",
		})
	}

	if len(domainExact) > 0 {
		rules = append(rules, map[string]interface{}{
			"domain":   domainExact,
			"action":   "route",
			"outbound": "direct",
		})
	}

	if len(domainSuffix) > 0 {
		rules = append(rules, map[string]interface{}{
			"domain_suffix": domainSuffix,
			"action":        "route",
			"outbound":      "direct",
		})
	}

	rules = append(rules,
		map[string]interface{}{
			"ip_is_private": true,
			"action":        "route",
			"outbound":      "direct",
		},
		map[string]interface{}{
			"network": []string{"tcp", "udp"},
			"port":    []int{53},
			"action":  "hijack-dns",
		},
	)

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level": normalizeLogLevel(logLevel),
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"type":        "udp",
					"tag":         "remote-dns-1",
					"server":      "1.1.1.1",
					"server_port": 53,
				},
				{
					"type":        "udp",
					"tag":         "remote-dns-2",
					"server":      "8.8.8.8",
					"server_port": 53,
				},
			},
			"final":           "remote-dns-1",
			"strategy":        "prefer_ipv4",
			"reverse_mapping": true,
		},
		"inbounds": []map[string]interface{}{
			{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": InterfaceName,
				"address":        []string{tunAddress},
				"mtu":            1500,
				"auto_route":     true,
				"strict_route":   true,
				"stack":          "system",
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"type":        "socks",
				"tag":         "proxy",
				"server":      "127.0.0.1",
				"server_port": socksPort,
				"version":     "5",
			},
			{
				"type": "direct",
				"tag":  "direct",
			},
			{
				"type": "block",
				"tag":  "block",
			},
		},
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"find_process":          true,
			"final":                 "proxy",
			"rules":                 rules,
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func buildDomainMatchers(input []string) ([]string, []string) {
	exactSeen := make(map[string]struct{})
	suffixSeen := make(map[string]struct{})
	var exact []string
	var suffix []string

	for _, raw := range input {
		domain := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"'`)))
		domain = strings.TrimPrefix(domain, "full:")
		domain = strings.TrimPrefix(domain, "domain:")
		domain = strings.TrimPrefix(domain, ".")
		if domain == "" {
			continue
		}
		if _, ok := exactSeen[domain]; !ok {
			exactSeen[domain] = struct{}{}
			exact = append(exact, domain)
		}
		suffixValue := "." + domain
		if _, ok := suffixSeen[suffixValue]; !ok {
			suffixSeen[suffixValue] = struct{}{}
			suffix = append(suffix, suffixValue)
		}
	}

	return exact, suffix
}

func normalizeLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "error":
		return "error"
	default:
		return "warn"
	}
}

func persistConfig(configJSON []byte) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	configPath := filepath.Join(filepath.Dir(exePath), "config-pre.json")
	return os.WriteFile(configPath, configJSON, 0644)
}
