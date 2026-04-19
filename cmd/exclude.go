package cmd

import (
	"fmt"
	"strings"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/spf13/cobra"
)

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

var excludeAddCmd = &cobra.Command{
	Use:   "add [app_name.exe]",
	Short: "Add an application to the bypass list",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appName := strings.ToLower(args[0])
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		for _, app := range cfg.System.BypassApps {
			if strings.ToLower(app) == appName {
				fmt.Printf("App '%s' is already in the bypass list.\n", appName)
				return
			}
		}

		cfg.System.BypassApps = append(cfg.System.BypassApps, appName)
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("App '%s' added to the bypass list.\n", appName)
	},
}

var excludeRemoveCmd = &cobra.Command{
	Use:   "remove [app_name.exe]",
	Short: "Remove an application from the bypass list",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appName := strings.ToLower(args[0])
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		var newBypass []string
		found := false
		for _, app := range cfg.System.BypassApps {
			if strings.ToLower(app) != appName {
				newBypass = append(newBypass, app)
			} else {
				found = true
			}
		}

		if !found {
			fmt.Printf("App '%s' not found in the bypass list.\n", appName)
			return
		}

		cfg.System.BypassApps = newBypass
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("App '%s' removed from the bypass list.\n", appName)
	},
}

var excludeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all applications currently in the bypass list",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		fmt.Println("=== App Exclusion List ===")
		fmt.Printf("TUN Mode Enabled: %v\n", cfg.System.EnableTun)
		if len(cfg.System.BypassApps) == 0 {
			fmt.Println("No apps bypassed.")
		} else {
			for idx, app := range cfg.System.BypassApps {
				fmt.Printf("%d. %s\n", idx+1, app)
			}
		}
	},
}

func init() {
	excludeCmd.AddCommand(excludeTunOnCmd)
	excludeCmd.AddCommand(excludeTunOffCmd)
	excludeCmd.AddCommand(excludeAddCmd)
	excludeCmd.AddCommand(excludeRemoveCmd)
	excludeCmd.AddCommand(excludeListCmd)
	
	rootCmd.AddCommand(excludeCmd)
}
