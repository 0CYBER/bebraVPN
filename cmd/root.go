package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bebravpn",
	Short: "bebraVPN is a high-performance VLESS CLI client for Windows",
	Long: `bebraVPN embeds Xray-core to provide secure VLESS+Reality connections 
with automatic system proxy management and smart server selection.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Root flags if any
}
