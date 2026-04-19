package proxy

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"syscall"
)

const (
	internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	INTERNET_OPTION_SETTINGS_CHANGED   = 39
	INTERNET_OPTION_REFRESH            = 37
)

var (
	wininet         = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

type WindowsProxy struct{}

func New() *WindowsProxy {
	return &WindowsProxy{}
}

func (p *WindowsProxy) SetProxy(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}

	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return err
	}

	// Disable manual proxy override for some connections if needed
	// k.SetStringValue("ProxyOverride", "<local>")

	return p.refresh()
}

func (p *WindowsProxy) UnsetProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}

	return p.refresh()
}

func (p *WindowsProxy) refresh() error {
	// Call InternetSetOption twice to notify the system.
	ret, _, err := internetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	if ret == 0 {
		return fmt.Errorf("InternetSetOption (Settings Changed) failed: %v", err)
	}

	ret, _, err = internetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
	if ret == 0 {
		return fmt.Errorf("InternetSetOption (Refresh) failed: %v", err)
	}

	return nil
}
