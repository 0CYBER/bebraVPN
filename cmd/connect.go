package cmd

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/0CYBER/bebravpn/internal/engine"
	"github.com/0CYBER/bebravpn/internal/prober"
	"github.com/0CYBER/bebravpn/internal/proxy"
	"github.com/0CYBER/bebravpn/internal/tunroute"
	"github.com/spf13/cobra"
	xnetproxy "golang.org/x/net/proxy"
)

var bestFlag bool
var lastBestOrdered []config.Server

func nextHealthInterval() time.Duration {
	return time.Duration(45+rand.IntN(46)) * time.Second
}

func connectivityProbeTargets() []string {
	return []string{
		"http://www.msftconnecttest.com/connecttest.txt",
		"http://connectivitycheck.gstatic.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
	}
}

func verifyProxyConnectivity(socksPort int, timeout time.Duration) error {
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	dialer, err := xnetproxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return err
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			type contextDialer interface {
				DialContext(ctx context.Context, network, address string) (net.Conn, error)
			}
			if cd, ok := dialer.(contextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	var lastErr error
	for _, target := range connectivityProbeTargets() {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "bebravpn-connect-check/1.0")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return nil
		}
		lastErr = fmt.Errorf("unexpected HTTP status %d from %s", resp.StatusCode, target)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("connectivity probe failed")
	}
	return lastErr
}

func waitForProxyConnectivity(socksPort int, totalTimeout time.Duration) error {
	deadline := time.Now().Add(totalTimeout)
	var lastErr error
	for {
		lastErr = verifyProxyConnectivity(socksPort, 5*time.Second)
		if lastErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("connectivity probe timed out")
			}
			return lastErr
		}
		time.Sleep(1200 * time.Millisecond)
	}
}

var connectCmd = &cobra.Command{
	Use:   "connect [server-name]",
	Short: "Connect to a VLESS server",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		if len(cfg.Servers) == 0 {
			fmt.Println("No servers found. Use 'add' first.")
			return
		}

		var targetServer *config.Server
		var targetIndex int = -1
		lastBestOrdered = nil
		if bestFlag {
			fmt.Println("Finding the best server...")
			p := prober.New(1500 * time.Millisecond)
			ordered, results := p.BestByLatency(cfg.Servers, 64)
			lastBestOrdered = ordered

			if len(ordered) > 0 {
				best := ordered[0]
				if l, ok := results[best.URL]; ok && l > 0 {
					for i := range cfg.Servers {
						if cfg.Servers[i].URL == best.URL {
							targetServer = &cfg.Servers[i]
							targetIndex = i
							break
						}
					}
					fmt.Printf("Selected best server: %s (%dms)\n", best.Name, l)
				}
			}
			if targetServer == nil {
				fmt.Println("Could not determine best server. Using default.")
			} else {
				targetServer.Latency = results[targetServer.URL]
			}
		}

		if targetServer == nil {
			if len(args) > 0 {
				for i := range cfg.Servers {
					if cfg.Servers[i].Name == args[0] {
						targetServer = &cfg.Servers[i]
						targetIndex = i
						break
					}
				}
			} else {
				// Select first one as fallback
				targetServer = &cfg.Servers[0]
				targetIndex = 0
				fmt.Printf("Using server: %s\n", targetServer.Name)
			}
		}

		if targetServer == nil {
			fmt.Printf("Server '%s' not found.\n", args[0])
			return
		}

		var xray *engine.Engine
		defer func() {
			if xray != nil {
				_ = xray.Stop()
			}
		}()
		var routeManager *tunroute.Manager
		disconnectCurrent := func() {
			if routeManager != nil {
				routeManager.Cleanup()
				routeManager = nil
			}
			if xray != nil {
				_ = xray.Stop()
				xray = nil
			}
			if cfg.System.EnableTun {
				time.Sleep(2500 * time.Millisecond)
			}
		}

		orderedCandidates := []config.Server{}
		if bestFlag && len(lastBestOrdered) > 0 {
			orderedCandidates = append(orderedCandidates, lastBestOrdered...)
		} else {
			orderedCandidates = append([]config.Server(nil), cfg.Servers...)
			if targetIndex >= 0 && targetIndex < len(cfg.Servers) {
				selected := cfg.Servers[targetIndex]
				orderedCandidates = append([]config.Server{selected}, append(cfg.Servers[:targetIndex], cfg.Servers[targetIndex+1:]...)...)
			}
		}
		socksPort := cfg.System.SocksPort
		if socksPort == 0 {
			socksPort = 10808
		}

		connectServer := func(server config.Server) (*config.VlessInfo, error) {
			disconnectCurrent()

			info, err := config.ParseVless(server.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid server URL: %v", err)
			}
			xray = engine.New()
			if err := xray.Start(info, &cfg.System); err != nil {
				xray = nil
				return nil, err
			}
			if err := waitForProxyConnectivity(socksPort, 8*time.Second); err != nil {
				disconnectCurrent()
				return nil, fmt.Errorf("proxy connectivity check failed: %v", err)
			}
			if cfg.System.EnableTun {
				rm := tunroute.New()
				routeManager = rm
				if err := rm.Setup(info.Address); err != nil {
					disconnectCurrent()
					return nil, fmt.Errorf("failed to configure TUN routes: %v", err)
				}
				if err := waitForProxyConnectivity(socksPort, 12*time.Second); err != nil {
					disconnectCurrent()
					return nil, fmt.Errorf("proxy connectivity check after TUN setup failed: %v", err)
				}
			}
			return info, nil
		}

		tryFailover := func(preferred []config.Server, reason string) (*config.Server, *config.VlessInfo, error) {
			if len(preferred) == 0 {
				return nil, nil, fmt.Errorf("no servers available")
			}

			for _, candidate := range preferred {
				info, err := connectServer(candidate)
				if err == nil {
					fmt.Printf("%sSwitched to %s\n", reason, candidate.Name)
					return &candidate, info, nil
				}
				fmt.Printf("Candidate %s failed: %v\n", candidate.Name, err)
			}

			return nil, nil, fmt.Errorf("all candidate servers failed")
		}

		currentServer, _, err := tryFailover(orderedCandidates, "")
		if err != nil {
			fmt.Printf("Failed to start Xray: %v\n", err)
			return
		}

		var winProxy *proxy.WindowsProxy
		if !cfg.System.EnableTun {
			winProxy = proxy.New()
			proxyAddr := fmt.Sprintf("socks=127.0.0.1:%d", cfg.System.SocksPort)
			if err := winProxy.SetProxy(proxyAddr); err != nil {
				fmt.Printf("Failed to set system proxy: %v\n", err)
				return
			}

			fmt.Printf("Connected to %s! Proxy active on %s\n", currentServer.Name, proxyAddr)
		} else {
			fmt.Printf("Connected to %s! TUN mode is active; bypass rules are applied through Xray routing.\n", currentServer.Name)
		}
		fmt.Println("Press Ctrl+C to disconnect...")

		// Wait for signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		healthTimer := time.NewTimer(nextHealthInterval())
		defer healthTimer.Stop()

		consecutiveFailures := 0
		for {
			select {
			case <-sigChan:
				fmt.Println("\nDisconnecting...")
				disconnectCurrent()
				if winProxy != nil {
					winProxy.UnsetProxy()
					fmt.Println("System proxy restored.")
				}
				return
			case <-healthTimer.C:
				if err := verifyProxyConnectivity(socksPort, 5*time.Second); err != nil {
					consecutiveFailures++
				} else {
					consecutiveFailures = 0
				}

				if consecutiveFailures >= 2 {
					disconnectCurrent()
					candidates := append([]config.Server(nil), cfg.Servers...)
					sort.SliceStable(candidates, func(i, j int) bool {
						if candidates[i].URL == currentServer.URL {
							return false
						}
						if candidates[j].URL == currentServer.URL {
							return true
						}
						return candidates[i].Latency < candidates[j].Latency
					})

					nextServer, nextInfo, failoverErr := tryFailover(candidates, fmt.Sprintf("Current server %s is unavailable. ", currentServer.Name))
					if failoverErr == nil {
						currentServer = nextServer
						_ = nextInfo
						consecutiveFailures = 0
					}
				}

				healthTimer.Reset(nextHealthInterval())
			}
		}
	},
}

func init() {
	connectCmd.Flags().BoolVarP(&bestFlag, "best", "b", false, "Connect to the server with lowest latency")
	rootCmd.AddCommand(connectCmd)
}
