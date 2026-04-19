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

		p := prober.New(10 * time.Second)

		var results map[string]int64
		if pingFlag {
			fmt.Println("Pinging servers in parallel...")
			results = p.PingBatch(cfg.Servers, 20)
		}

		fmt.Printf("%-20s %-10s %s\n", "NAME", "LATENCY", "URL")
		fmt.Printf("%-20s %-10s %s\n", "----", "-------", "---")

		for i := range cfg.Servers {
			s := &cfg.Servers[i]
			latencyStr := "N/A"
			
			if pingFlag {
				if l, ok := results[s.URL]; ok && l > 0 {
					latencyStr = fmt.Sprintf("%dms", l)
					s.Latency = l
				} else if l == -1 {
					latencyStr = "Error"
					s.Latency = -1
				}
			} else if s.Latency > 0 {
				latencyStr = fmt.Sprintf("%dms", s.Latency)
			} else if s.Latency == -1 {
				latencyStr = "Error"
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
