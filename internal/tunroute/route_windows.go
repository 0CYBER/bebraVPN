package tunroute

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const InterfaceName = "bebraTun"
const ipv6FirewallRuleName = "bebraVPN Block IPv6 While TUN"

type defaultRoute struct {
	InterfaceIndex int    `json:"InterfaceIndex"`
	NextHop        string `json:"NextHop"`
}

type Manager struct {
	tunIndex  int
	baseRoute defaultRoute
	serverIPs []string
}

func New() *Manager {
	return &Manager{}
}

func runPowerShell(script string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.CombinedOutput()
}

func runRoute(args ...string) error {
	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *Manager) detectDefaultRoute() error {
	output, err := runPowerShell(`$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 InterfaceIndex,NextHop | ConvertTo-Json -Compress; Write-Output $route`)
	if err != nil {
		return err
	}

	var route defaultRoute
	if err := json.Unmarshal(output, &route); err != nil {
		return fmt.Errorf("failed to parse default route: %w", err)
	}
	if route.InterfaceIndex == 0 || route.NextHop == "" {
		return fmt.Errorf("default route not found")
	}

	m.baseRoute = route
	return nil
}

func (m *Manager) detectTunIndex() error {
	var lastErr error
	for range 20 {
		output, err := runPowerShell(fmt.Sprintf(`$adapter = Get-NetAdapter -Name '%s' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty ifIndex; Write-Output $adapter`, InterfaceName))
		if err == nil {
			value := strings.TrimSpace(string(output))
			idx, convErr := strconv.Atoi(value)
			if convErr == nil && idx > 0 {
				m.tunIndex = idx
				return nil
			}
			lastErr = convErr
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tun adapter not found")
	}
	return lastErr
}

func (m *Manager) resolveServerIPs(host string) error {
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	m.serverIPs = nil
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			value := v4.String()
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			m.serverIPs = append(m.serverIPs, value)
		}
	}
	if len(m.serverIPs) == 0 {
		return fmt.Errorf("no IPv4 addresses resolved for %s", host)
	}
	return nil
}

func (m *Manager) Setup(serverHost string) error {
	if err := m.detectDefaultRoute(); err != nil {
		return err
	}
	if err := m.resolveServerIPs(serverHost); err != nil {
		return err
	}
	if err := m.detectTunIndex(); err != nil {
		return err
	}

	for _, ip := range m.serverIPs {
		_ = runRoute("delete", ip, "mask", "255.255.255.255")
		if err := runRoute("add", ip, "mask", "255.255.255.255", m.baseRoute.NextHop, "if", strconv.Itoa(m.baseRoute.InterfaceIndex), "metric", "3"); err != nil {
			return err
		}
	}

	_ = runRoute("delete", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", strconv.Itoa(m.tunIndex))
	if err := runRoute("add", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", strconv.Itoa(m.tunIndex), "metric", "1"); err != nil {
		return err
	}

	_, _ = runPowerShell(fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, ipv6FirewallRuleName))
	if _, err := runPowerShell(fmt.Sprintf(`New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -RemoteAddress ::/0 -Enabled True`, ipv6FirewallRuleName)); err != nil {
		return err
	}

	return nil
}

func (m *Manager) Cleanup() {
	if m.tunIndex > 0 {
		_ = runRoute("delete", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", strconv.Itoa(m.tunIndex))
	}
	for _, ip := range m.serverIPs {
		_ = runRoute("delete", ip, "mask", "255.255.255.255")
	}
	_, _ = runPowerShell(fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, ipv6FirewallRuleName))
}
