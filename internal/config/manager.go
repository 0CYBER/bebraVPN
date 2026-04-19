package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Manager struct {
	configPath string
	serversDir string
}

func NewManager() *Manager {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".bebravpn")
	os.MkdirAll(configDir, 0755)

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	serversDir := filepath.Join(exeDir, "servers")
	os.MkdirAll(serversDir, 0755)

	// Defaults using global viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".")

	viper.SetDefault("system.proxy_port", 10809)
	viper.SetDefault("system.socks_port", 10808)
	viper.SetDefault("system.enable_proxy", true)
	viper.SetDefault("log_level", "warning")

	return &Manager{
		configPath: filepath.Join(configDir, "config.yaml"),
		serversDir: serversDir,
	}
}

func (m *Manager) Load() (*Config, error) {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Dynamic servers loading
	scannedServers := m.scanServersDir()
	cfg.Servers = append(cfg.Servers, scannedServers...)

	return &cfg, nil
}

func (m *Manager) scanServersDir() []Server {
	var servers []Server
	files, err := os.ReadDir(m.serversDir)
	if err != nil {
		return servers
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".txt") {
			continue
		}

		filePath := filepath.Join(m.serversDir, file.Name())
		f, err := os.Open(filePath)
		if err != nil {
			continue
		}
		
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if info, err := ParseVless(line); err == nil {
				name := info.Name
				if name == "" {
					name = strings.TrimSuffix(file.Name(), ".txt")
				}
				servers = append(servers, Server{
					Name: name,
					URL:  line,
				})
			}
		}
		f.Close()
	}

	return servers
}

func (m *Manager) Save(cfg *Config) error {
	viper.Set("servers", cfg.Servers)
	viper.Set("system", cfg.System)
	viper.Set("log_level", cfg.LogLevel)
	
	return viper.WriteConfigAs(m.configPath)
}

func (m *Manager) AddServer(link string) error {
	info, err := ParseVless(link)
	if err != nil {
		return err
	}

	cfg, err := m.Load()
	if err != nil {
		return err
	}

	name := info.Name
	if name == "" {
		name = fmt.Sprintf("Server-%d", len(cfg.Servers)+1)
	}

	cfg.Servers = append(cfg.Servers, Server{
		Name: name,
		URL:  link,
	})

	return m.Save(cfg)
}
