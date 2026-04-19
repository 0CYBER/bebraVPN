package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/0CYBER/bebravpn/internal/engine"
	"github.com/0CYBER/bebravpn/internal/proxy"
	"github.com/spf13/cobra"
)

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
		if len(args) > 0 {
			for i := range cfg.Servers {
				if cfg.Servers[i].Name == args[0] {
					targetServer = &cfg.Servers[i]
					break
				}
			}
		} else {
			// Select best server or first one
			targetServer = &cfg.Servers[0]
			fmt.Printf("No server specified, using first one: %s\n", targetServer.Name)
		}

		if targetServer == nil {
			fmt.Printf("Server '%s' not found.\n", args[0])
			return
		}

		info, err := config.ParseVless(targetServer.URL)
		if err != nil {
			fmt.Printf("Invalid server URL: %v\n", err)
			return
		}

		// Initialize Engine
		xray := engine.New()
		err = xray.Start(info, cfg.System.SocksPort)
		if err != nil {
			fmt.Printf("Failed to start Xray: %v\n", err)
			return
		}
		defer xray.Stop()

		// Set Proxy
		winProxy := proxy.New()
		proxyAddr := fmt.Sprintf("socks=127.0.0.1:%d", cfg.System.SocksPort)
		if err := winProxy.SetProxy(proxyAddr); err != nil {
			fmt.Printf("Failed to set system proxy: %v\n", err)
			return
		}
		
		fmt.Printf("Connected to %s! Proxy active on %s\n", targetServer.Name, proxyAddr)
		fmt.Println("Press Ctrl+C to disconnect...")

		// Wait for signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nDisconnecting...")
		winProxy.UnsetProxy()
		fmt.Println("System proxy restored.")
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)
}
