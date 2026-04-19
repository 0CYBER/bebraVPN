package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

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
		log.Printf("Xray Config JSON: %s", string(configJSON))
		return fmt.Errorf("load config failed: %v", err)
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
				"port": func() int {
					if localPort == 0 {
						return 10808
					}
					return localPort
				}(),
				"listen": "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"routeOnly":    true,
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
							"port": func() int {
								p, _ := strconv.Atoi(info.Port)
								if p == 0 {
									return 443
								}
								return p
							}(),
							"users": []interface{}{
								func() map[string]interface{} {
									user := map[string]interface{}{
										"id":         info.UUID,
										"encryption": "none",
									}
									if info.Flow != "" {
										user["flow"] = info.Flow
									}
									return user
								}(),
							},
						},
					},
				},
				"streamSettings": func() map[string]interface{} {
					ss := map[string]interface{}{
						"network": func() string {
							if info.Type == "" {
								return "tcp"
							}
							return info.Type
						}(),
						"security": func() string {
							if info.Security == "" {
								return "none"
							}
							return info.Security
						}(),
						"sockopt": map[string]interface{}{
							"dialerProxy": "fragment",
						},
					}
					switch info.Security {
					case "tls":
						ss["tlsSettings"] = map[string]interface{}{
							"serverName":    info.SNI,
							"allowInsecure": false,
							"fingerprint":   info.FP,
						}
					case "reality":
						ss["realitySettings"] = map[string]interface{}{
							"publicKey":   info.PBK,
							"shortId":     info.SID,
							"serverName":  info.SNI,
							"fingerprint": info.FP,
						}
					}
					return ss
				}(),
			},
			map[string]interface{}{
				"protocol": "freedom",
				"tag":      "fragment",
				"settings": map[string]interface{}{
					"fragment": map[string]interface{}{
						"packets":  "tlshello",
						"length":   "100-200",
						"interval": "10-20",
					},
				},
				"streamSettings": map[string]interface{}{
					"sockopt": map[string]interface{}{
						"TcpNoDelay": true,
					},
				},
			},
		},
	}
}
