package cmd

import (
	"fmt"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
	"github.com/0CYBER/bebravpn/internal/prober"
	"github.com/spf13/cobra"
)

var pingFlag bool

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved servers",
	Run: func(cmd *cobra.Command, args []string) {
		manager := config.NewManager()
		cfg, err := manager.Load()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		if len(cfg.Servers) == 0 {
			fmt.Println("No servers found. Use 'add' to add some.")
			return
		}

		p := prober.New(5 * time.Second)

		fmt.Printf("%-20s %-10s %s\n", "NAME", "LATENCY", "URL")
		fmt.Printf("%-20s %-10s %s\n", "----", "-------", "---")

		for i, s := range cfg.Servers {
			latencyStr := "N/A"
			if pingFlag {
				info, _ := config.ParseVless(s.URL)
				if info != nil {
					l, err := p.Ping(info)
					if err == nil {
						latencyStr = fmt.Sprintf("%dms", l)
						cfg.Servers[i].Latency = l
					} else {
						latencyStr = "Error"
					}
				}
			} else if s.Latency > 0 {
				latencyStr = fmt.Sprintf("%dms", s.Latency)
			}

			fmt.Printf("%-20s %-10s %s\n", s.Name, latencyStr, s.URL)
		}

		if pingFlag {
			manager.Save(cfg)
		}
	},
}

func init() {
	listCmd.Flags().BoolVarP(&pingFlag, "ping", "p", false, "Ping all servers to update latency")
	rootCmd.AddCommand(listCmd)
}
