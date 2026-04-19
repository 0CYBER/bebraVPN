package cmd

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/0CYBER/bebravpn/internal/engine"
	"github.com/0CYBER/bebravpn/internal/prober"
	"github.com/0CYBER/bebravpn/internal/proxy"
	"github.com/spf13/cobra"
)

var bestFlag bool

func nextHealthInterval() time.Duration {
	return time.Duration(45+rand.IntN(46)) * time.Second
}

func nextDeepCheckInterval() time.Duration {
	return time.Duration(180+rand.IntN(181)) * time.Second
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
		if bestFlag {
			fmt.Println("Finding the best server...")
			p := prober.New(1500 * time.Millisecond)
			ordered, results := p.BestByLatency(cfg.Servers, 64)

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

		xray := engine.New()
		defer xray.Stop()

		orderedCandidates := append([]config.Server(nil), cfg.Servers...)
		if targetIndex >= 0 && targetIndex < len(cfg.Servers) {
			selected := cfg.Servers[targetIndex]
			orderedCandidates = append([]config.Server{selected}, append(cfg.Servers[:targetIndex], cfg.Servers[targetIndex+1:]...)...)
		}

		fastProber := prober.New(1500 * time.Millisecond)
		healthProber := prober.New(3 * time.Second)
		socksPort := cfg.System.SocksPort
		if socksPort == 0 {
			socksPort = 10808
		}

		connectServer := func(server config.Server) (*config.VlessInfo, error) {
			info, err := config.ParseVless(server.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid server URL: %v", err)
			}
			if err := xray.Start(info, &cfg.System); err != nil {
				return nil, err
			}
			return info, nil
		}

		tryFailover := func(preferred []config.Server, reason string) (*config.Server, *config.VlessInfo, error) {
			if len(preferred) == 0 {
				return nil, nil, fmt.Errorf("no servers available")
			}

			ordered, results := fastProber.BestByLatency(preferred, 64)
			for _, candidate := range ordered {
				if l := results[candidate.URL]; l > 0 {
					candidate.Latency = l
				}
			}

			for _, candidate := range ordered {
				if results[candidate.URL] <= 0 {
					continue
				}
				info, err := connectServer(candidate)
				if err == nil {
					fmt.Printf("%sSwitched to %s (%dms)\n", reason, candidate.Name, results[candidate.URL])
					return &candidate, info, nil
				}
			}

			for _, candidate := range preferred {
				info, err := connectServer(candidate)
				if err == nil {
					fmt.Printf("%sSwitched to %s\n", reason, candidate.Name)
					return &candidate, info, nil
				}
			}

			return nil, nil, fmt.Errorf("all candidate servers failed")
		}

		currentServer, currentInfo, err := tryFailover(orderedCandidates, "")
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
		nextDeepCheckAt := time.Now().Add(nextDeepCheckInterval())
		for {
			select {
			case <-sigChan:
				fmt.Println("\nDisconnecting...")
				if winProxy != nil {
					winProxy.UnsetProxy()
					fmt.Println("System proxy restored.")
				}
				return
			case <-healthTimer.C:
				localConn, localErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 700*time.Millisecond)
				if localErr == nil {
					_ = localConn.Close()
				}

				remoteErr := error(nil)
				if time.Now().After(nextDeepCheckAt) {
					_, remoteErr = healthProber.Ping(currentInfo)
					nextDeepCheckAt = time.Now().Add(nextDeepCheckInterval())
				}

				if localErr != nil || remoteErr != nil {
					consecutiveFailures++
				} else {
					consecutiveFailures = 0
				}

				if consecutiveFailures >= 2 {
					_ = xray.Stop()
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
						currentInfo = nextInfo
						consecutiveFailures = 0
						nextDeepCheckAt = time.Now().Add(nextDeepCheckInterval())
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
