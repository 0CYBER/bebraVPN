//go:build !windows

package singtun

import (
	"fmt"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
)

const InterfaceName = "bebraTun"

type Manager struct{}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) Start(sys *config.System, logLevel string) error {
	return fmt.Errorf("TUN frontend is only supported on Windows in this build")
}

func (m *Manager) Stop() error {
	return nil
}

func (m *Manager) WaitUntilReady(timeout time.Duration) error {
	return fmt.Errorf("TUN frontend is only supported on Windows in this build")
}
