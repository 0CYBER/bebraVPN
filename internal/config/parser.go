package config

import (
	"fmt"
	"net/url"
	"strings"
)

type VlessInfo struct {
	UUID     string
	Address  string
	Port     string
	Security string
	Type     string
	Host     string
	Path     string
	SNI      string
	Flow     string
	Name     string
	PBK      string // Reality public key
	SID      string // Reality short id
	FP       string // Fingerprint
}

func ParseVless(link string) (*VlessInfo, error) {
	if !strings.HasPrefix(link, "vless://") {
		return nil, fmt.Errorf("invalid vless link prefix")
	}

	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	info := &VlessInfo{
		UUID:    u.User.Username(),
		Address: u.Hostname(),
		Port:    u.Port(),
		Name:    u.Fragment,
	}

	q := u.Query()
	info.Security = q.Get("security")
	info.Type = q.Get("type")
	info.Host = q.Get("host")
	info.Path = q.Get("path")
	info.SNI = q.Get("sni")
	info.Flow = q.Get("flow")
	info.PBK = q.Get("pbk")
	info.SID = q.Get("sid")
	info.FP = q.Get("fp")

	return info, nil
}
