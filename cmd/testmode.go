package cmd

import (
	"fmt"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/spf13/cobra"
)

var testModeCmd = &cobra.Command{
	Use:   "testmode",
	Short: "Manage safe auto-disconnect test mode",
}

var testModeOnCmd = &cobra.Command{
	Use:   "on",
	Short: "Enable test mode with automatic disconnect after 5 minutes",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		cfg.System.TestMode = true
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Println("Test mode enabled. Any connection will auto-disconnect after 5 minutes.")
	},
}

var testModeOffCmd = &cobra.Command{
	Use:   "off",
	Short: "Disable test mode",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		cfg.System.TestMode = false
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Println("Test mode disabled.")
	},
}

var testModeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show test mode status",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		fmt.Printf("Test mode enabled: %v\n", cfg.System.TestMode)
		if cfg.System.TestMode {
			fmt.Println("Auto-disconnect timeout: 5 minutes")
		}
	},
}

func init() {
	testModeCmd.AddCommand(testModeOnCmd)
	testModeCmd.AddCommand(testModeOffCmd)
	testModeCmd.AddCommand(testModeStatusCmd)
	rootCmd.AddCommand(testModeCmd)
}
