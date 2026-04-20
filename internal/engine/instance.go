package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Register protocols
	_ "github.com/xtls/xray-core/main/distro/all"
)

type Engine struct {
	instance *core.Instance
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Start(info *config.VlessInfo, sysConfig *config.System) error {
	xrayConfig := e.buildConfig(info, sysConfig)
	configJSON, err := json.Marshal(xrayConfig)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(configJSON)
	cfg, err := serial.DecodeJSONConfig(reader)
	if err != nil {
		log.Printf("Xray Config JSON: %s", string(configJSON))
		return fmt.Errorf("json config validation failed: %v", err)
	}

	serverConfig, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("build config failed: %v", err)
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
		err := e.instance.Close()
		e.instance = nil
		return err
	}
	return nil
}

func splitAndTrimCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var result []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func randomRange(min, max int) string {
	if max <= min {
		return strconv.Itoa(min)
	}
	return fmt.Sprintf("%d-%d", min+rand.IntN(6), max+rand.IntN(8))
}

func chooseRandom(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return values[rand.IntN(len(values))]
}

func defaultFingerprint(info *config.VlessInfo) string {
	if info.FP != "" {
		return info.FP
	}
	return "chrome"
}

func buildProtectionDomains(info *config.VlessInfo) []string {
	var domains []string
	if info.Address != "" && !strings.EqualFold(info.Address, "localhost") && !strings.Contains(info.Address, ":") {
		domains = append(domains, "full:"+info.Address)
	}
	if info.SNI != "" {
		domains = append(domains, "full:"+info.SNI)
	}
	return uniqueStrings(domains)
}

func buildRemoteDNSDomains() []string {
	return []string{
		"full:cloudflare-dns.com",
		"full:dns.google",
		"full:dns.quad9.net",
	}
}

func buildFinalMask(info *config.VlessInfo) map[string]interface{} {
	return map[string]interface{}{
		"tcp": []interface{}{
			map[string]interface{}{
				"type": "fragment",
				"settings": map[string]interface{}{
					"packets": "tlshello",
					"length":  randomRange(40, 120),
					"delay":   randomRange(8, 24),
				},
			},
		},
		"udp": []interface{}{
			map[string]interface{}{
				"type": "noise",
				"settings": map[string]interface{}{
					"length": randomRange(8, 24),
					"delay":  randomRange(8, 18),
				},
			},
		},
	}
}

func buildStreamSettings(info *config.VlessInfo) map[string]interface{} {
	network := info.Type
	if network == "" {
		network = "tcp"
	}

	security := info.Security
	if security == "" {
		security = "none"
	}

	streamSettings := map[string]interface{}{
		"network":  network,
		"security": security,
		"sockopt": map[string]interface{}{
			"dialerProxy": "fragment",
		},
	}

	if security == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName":    info.SNI,
			"allowInsecure": info.AllowInsecure,
			"fingerprint":   defaultFingerprint(info),
		}
		if alpn := splitAndTrimCSV(info.ALPN); len(alpn) > 0 {
			tlsSettings["alpn"] = alpn
		} else {
			tlsSettings["alpn"] = []string{"h2", "http/1.1"}
		}
		if info.ECHConfigList != "" {
			tlsSettings["echConfigList"] = info.ECHConfigList
		}
		if info.ECHForceQuery != "" {
			tlsSettings["echForceQuery"] = info.ECHForceQuery
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	if security == "reality" {
		streamSettings["realitySettings"] = map[string]interface{}{
			"publicKey":   info.PBK,
			"shortId":     info.SID,
			"serverName":  info.SNI,
			"fingerprint": defaultFingerprint(info),
			"spiderX": func() string {
				if info.SpiderX != "" {
					return info.SpiderX
				}
				return "/"
			}(),
			"show": false,
		}
	}

	switch network {
	case "ws":
		wsSettings := map[string]interface{}{}
		if info.Host != "" {
			wsSettings["host"] = info.Host
		}
		if info.Path != "" {
			wsSettings["path"] = info.Path
		}
		if len(wsSettings) > 0 {
			streamSettings["wsSettings"] = wsSettings
		}
	case "grpc":
		grpcSettings := map[string]interface{}{
			"multiMode": info.Mode == "multi",
		}
		if info.ServiceName != "" {
			grpcSettings["serviceName"] = info.ServiceName
		}
		if info.Authority != "" {
			grpcSettings["authority"] = info.Authority
		} else if info.Host != "" {
			grpcSettings["authority"] = info.Host
		}
		streamSettings["grpcSettings"] = grpcSettings
	case "httpupgrade":
		httpupgradeSettings := map[string]interface{}{}
		if info.Host != "" {
			httpupgradeSettings["host"] = info.Host
		}
		if info.Path != "" {
			httpupgradeSettings["path"] = info.Path
		}
		if len(httpupgradeSettings) > 0 {
			streamSettings["httpupgradeSettings"] = httpupgradeSettings
		}
	case "xhttp", "splithttp":
		xhttpSettings := map[string]interface{}{}
		if info.Host != "" {
			xhttpSettings["host"] = info.Host
		}
		if info.Path != "" {
			xhttpSettings["path"] = info.Path
		}
		if info.Mode != "" {
			xhttpSettings["mode"] = info.Mode
		}
		if len(xhttpSettings) > 0 {
			streamSettings["xhttpSettings"] = xhttpSettings
		}
	default:
		if info.HeaderType == "http" {
			streamSettings["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": "http",
				},
			}
		}
	}

	if security == "tls" || security == "reality" {
		streamSettings["finalmask"] = buildFinalMask(info)
	}

	return streamSettings
}

func buildDNSConfig(enableTun bool) map[string]interface{} {
	servers := []interface{}{
		"1.1.1.1",
		"1.0.0.1",
		"8.8.8.8",
		"8.8.4.4",
		"9.9.9.9",
		"149.112.112.112",
	}
	servers = append(servers, "localhost")
	return map[string]interface{}{
		"hosts": map[string]interface{}{
			"dns.google":         []string{"8.8.8.8", "8.8.4.4"},
			"cloudflare-dns.com": []string{"1.1.1.1", "1.0.0.1"},
			"dns.quad9.net":      []string{"9.9.9.9", "149.112.112.112"},
		},
		"queryStrategy":   "UseIPv4",
		"disableFallback": false,
		"servers":         servers,
	}
}

func (e *Engine) buildConfig(info *config.VlessInfo, sysConfig *config.System) map[string]interface{} {
	// Minimal Xray config for VLESS connection
	proxyOutbound := map[string]interface{}{
		"tag":      "proxy",
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
		"streamSettings": buildStreamSettings(info),
	}
	fragmentOutbound := map[string]interface{}{
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
	}
	directOutbound := map[string]interface{}{
		"protocol": "freedom",
		"tag":      "direct",
		"settings": map[string]interface{}{
			"domainStrategy": "UseIP",
		},
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag": "socks-in",
				"port": func() int {
					if sysConfig.SocksPort == 0 {
						return 10808
					}
					return sysConfig.SocksPort
				}(),
				"listen":   "127.0.0.1",
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
			proxyOutbound,
			fragmentOutbound,
			directOutbound,
			map[string]interface{}{
				"protocol": "dns",
				"tag":      "dns-out",
			},
			map[string]interface{}{
				"protocol": "blackhole",
				"tag":      "block",
			},
		},
	}

	routingRules := []interface{}{
		map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"socks-in"},
			"outboundTag": "proxy",
		},
	}

	cfg["dns"] = buildDNSConfig(false)

	cfg["routing"] = map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          routingRules,
	}

	return cfg
}
