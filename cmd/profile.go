package cmd

import (
	"fmt"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage the network security profile",
}

var profileStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the active security profile",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}
		fmt.Printf("Security profile: %s\n", config.NormalizeSecurityProfile(cfg.System.SecurityProfile))
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available security profiles",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Available security profiles:")
		for _, profile := range config.SecurityProfiles() {
			fmt.Printf("  - %s\n", profile)
		}
	},
}

var profileSetCmd = &cobra.Command{
	Use:   "set [balanced|hard|rkn-hard]",
	Short: "Set the active security profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}
		cfg.System.SecurityProfile = config.NormalizeSecurityProfile(args[0])
		if err := manager.Save(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("Security profile set to %s.\n", cfg.System.SecurityProfile)
	},
}

func init() {
	profileCmd.AddCommand(profileStatusCmd)
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileSetCmd)
	rootCmd.AddCommand(profileCmd)
}

