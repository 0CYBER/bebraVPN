package engine

import (
	"encoding/json"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/xtls/xray-core/core"

	// Register protocols
	_ "github.com/xtls/xray-core/main/distro/all"
)

type Engine struct {
	instance *core.Instance
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Start(info *config.VlessInfo, localPort int) error {
	xrayConfig := e.buildConfig(info, localPort)
	configJSON, err := json.Marshal(xrayConfig)
	if err != nil {
		return err
	}

	serverConfig, err := core.LoadConfig("json", configJSON)
	if err != nil {
		return err
	}

	server, err := core.New(serverConfig)
	if err != nil {
		return err
	}

	if err := server.Start(); err != nil {
		return err
	}

	e.instance = server
	return nil
}

func (e *Engine) Stop() error {
	if e.instance != nil {
		return e.instance.Close()
	}
	return nil
}

func (e *Engine) buildConfig(info *config.VlessInfo, localPort int) map[string]interface{} {
	// Minimal Xray config for VLESS connection
	return map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"port":     localPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
				},
				"sniffing": map[string]interface{}{
					"enabled": true,
					"destOverride": []string{"http", "tls"},
				},
			},
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": info.Address,
							"port":    info.Port,
							"users": []interface{}{
								map[string]interface{}{
									"id":       info.UUID,
									"encryption": "none",
									"flow":     info.Flow,
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network":  info.Type,
					"security": info.Security,
					"tlsSettings": map[string]interface{}{
						"serverName": info.SNI,
						"allowInsecure": false,
						"fingerprint": info.FP,
					},
					"realitySettings": map[string]interface{}{
						"publicKey": info.PBK,
						"shortId":   info.SID,
						"serverName": info.SNI,
						"fingerprint": info.FP,
					},
				},
			},
		},
	}
}
