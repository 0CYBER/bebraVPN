package proxy

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"syscall"
)

const (
	internetSettingsKey              = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

type WindowsProxy struct {
	originalCaptured bool
	originalEnabled  uint64
	originalServer   string
	originalOverride string
	hadServerValue   bool
	hadOverrideValue bool
}

func New() *WindowsProxy {
	return &WindowsProxy{}
}

func (p *WindowsProxy) SetProxy(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if !p.originalCaptured {
		if value, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
			p.originalEnabled = value
		}
		if value, _, err := k.GetStringValue("ProxyServer"); err == nil {
			p.originalServer = value
			p.hadServerValue = true
		}
		if value, _, err := k.GetStringValue("ProxyOverride"); err == nil {
			p.originalOverride = value
			p.hadOverrideValue = true
		}
		p.originalCaptured = true
	}

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

	if p.originalCaptured {
		if err := k.SetDWordValue("ProxyEnable", uint32(p.originalEnabled)); err != nil {
			return err
		}
		if p.hadServerValue {
			if err := k.SetStringValue("ProxyServer", p.originalServer); err != nil {
				return err
			}
		} else {
			_ = k.DeleteValue("ProxyServer")
		}
		if p.hadOverrideValue {
			if err := k.SetStringValue("ProxyOverride", p.originalOverride); err != nil {
				return err
			}
		}
	} else if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
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
