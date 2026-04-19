package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/spf13/cobra"
)

func normalizeAppTarget(target string) string {
	target = strings.TrimSpace(strings.Trim(target, `"'`))
	target = strings.ToLower(filepath.Base(target))
	if target != "" && filepath.Ext(target) == "" {
		target += ".exe"
	}
	return target
}

func normalizeDomainTarget(target string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(target, `"'`)))
}

var excludeCmd = &cobra.Command{
	Use:   "exclude",
	Short: "Manage the application exclusion list (Split Tunneling / TUN mode)",
}

var excludeTunOnCmd = &cobra.Command{
	Use:   "on",
	Short: "Enable TUN mode to support app exclusion",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		cfg.System.EnableTun = true
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Println("TUN mode enabled. App exclusion is now active.")
		fmt.Println("Note: You must run bebravpn as Administrator to connect in TUN mode.")
	},
}

var excludeTunOffCmd = &cobra.Command{
	Use:   "off",
	Short: "Disable TUN mode and revert to standard SOCKS proxy",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		cfg.System.EnableTun = false
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Println("TUN mode disabled.")
	},
}

var isDomain bool

var excludeAddCmd = &cobra.Command{
	Use:   "add [target]",
	Short: "Add an application or domain to the bypass list",
	Long: `Add an application executable name or a domain to the bypass list. 
By default, it adds an application. Use --domain to add a domain.
If you add 'anydesk', it will automatically add both the process and its common domains.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		rawTarget := strings.ToLower(strings.TrimSpace(strings.Trim(args[0], `"'`)))
		target := normalizeAppTarget(args[0])
		if isDomain {
			target = normalizeDomainTarget(args[0])
		}
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		if !isDomain && (rawTarget == "anydesk" || target == "anydesk.exe") {
			// Preset for AnyDesk
			anydeskDomains := []string{"anydesk.com", "net.anydesk.com", "boot.anydesk.com", "relay.anydesk.com"}
			anydeskApp := "anydesk.exe"

			addedAny := false
			// Add app
			exists := false
			for _, app := range cfg.System.BypassApps {
				if normalizeAppTarget(app) == anydeskApp {
					exists = true
					break
				}
			}
			if !exists {
				cfg.System.BypassApps = append(cfg.System.BypassApps, anydeskApp)
				addedAny = true
			}

			// Add domains
			for _, d := range anydeskDomains {
				dExists := false
				for _, existing := range cfg.System.BypassDomains {
					if normalizeDomainTarget(existing) == d {
						dExists = true
						break
					}
				}
				if !dExists {
					cfg.System.BypassDomains = append(cfg.System.BypassDomains, d)
					addedAny = true
				}
			}

			if addedAny {
				if err := manager.Save(cfg); err != nil {
					fmt.Printf("Error saving config: %v\n", err)
					return
				}
				fmt.Println("AnyDesk preset applied: anydesk.exe and related domains added to bypass list.")
			} else {
				fmt.Println("AnyDesk is already in the bypass list (app and domains).")
			}
			return
		}

		if isDomain {
			for _, d := range cfg.System.BypassDomains {
				if normalizeDomainTarget(d) == target {
					fmt.Printf("Domain '%s' is already in the bypass list.\n", target)
					return
				}
			}
			cfg.System.BypassDomains = append(cfg.System.BypassDomains, target)
			fmt.Printf("Domain '%s' added to the bypass list.\n", target)
		} else {
			for _, app := range cfg.System.BypassApps {
				if normalizeAppTarget(app) == target {
					fmt.Printf("App '%s' is already in the bypass list.\n", target)
					return
				}
			}
			cfg.System.BypassApps = append(cfg.System.BypassApps, target)
			fmt.Printf("App '%s' added to the bypass list.\n", target)
		}

		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
	},
}

var excludeRemoveCmd = &cobra.Command{
	Use:   "remove [target]",
	Short: "Remove an application or domain from the bypass list",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := normalizeAppTarget(args[0])
		if isDomain {
			target = normalizeDomainTarget(args[0])
		}
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		found := false
		if isDomain {
			var newBypass []string
			for _, d := range cfg.System.BypassDomains {
				if normalizeDomainTarget(d) != target {
					newBypass = append(newBypass, d)
				} else {
					found = true
				}
			}
			cfg.System.BypassDomains = newBypass
		} else {
			var newBypass []string
			for _, app := range cfg.System.BypassApps {
				if normalizeAppTarget(app) != target {
					newBypass = append(newBypass, app)
				} else {
					found = true
				}
			}
			cfg.System.BypassApps = newBypass
		}

		if !found {
			fmt.Printf("Target '%s' not found in the bypass list.\n", target)
			return
		}

		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("Target '%s' removed from the bypass list.\n", target)
	},
}

var excludeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all items in the bypass list",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		fmt.Println("=== Split Tunneling Configuration ===")
		fmt.Printf("TUN Mode Enabled: %v\n", cfg.System.EnableTun)
		fmt.Println("\nBypassed Applications:")
		if len(cfg.System.BypassApps) == 0 {
			fmt.Println("  (none)")
		} else {
			for idx, app := range cfg.System.BypassApps {
				fmt.Printf("  %d. %s\n", idx+1, app)
			}
		}

		fmt.Println("\nBypassed Domains:")
		if len(cfg.System.BypassDomains) == 0 {
			fmt.Println("  (none)")
		} else {
			for idx, domain := range cfg.System.BypassDomains {
				fmt.Printf("  %d. %s\n", idx+1, domain)
			}
		}
	},
}

func init() {
	excludeAddCmd.Flags().BoolVarP(&isDomain, "domain", "d", false, "Add a domain instead of an application")
	excludeRemoveCmd.Flags().BoolVarP(&isDomain, "domain", "d", false, "Remove a domain instead of an application")

	excludeCmd.AddCommand(excludeTunOnCmd)
	excludeCmd.AddCommand(excludeTunOffCmd)
	excludeCmd.AddCommand(excludeAddCmd)
	excludeCmd.AddCommand(excludeRemoveCmd)
	excludeCmd.AddCommand(excludeListCmd)

	rootCmd.AddCommand(excludeCmd)
}
