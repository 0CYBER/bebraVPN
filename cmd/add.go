package cmd

import (
	"fmt"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add [vless-link]",
	Short: "Add a new VLESS server",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		if err := manager.AddServer(args[0]); err != nil {
			fmt.Printf("Error adding server: %v\n", err)
			return
		}
		fmt.Println("Server added successfully!")
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
