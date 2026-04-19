package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Manager struct {
	configPath string
}

func NewManager() *Manager {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".bebravpn")
	os.MkdirAll(configDir, 0755)
	
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(configDir)
	v.AddConfigPath(".")
	
	// Defaults
	v.SetDefault("system.proxy_port", 10809)
	v.SetDefault("system.socks_port", 10808)
	v.SetDefault("system.enable_proxy", true)
	v.SetDefault("log_level", "warning")

	return &Manager{configPath: filepath.Join(configDir, "config.yaml")}
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

	return &cfg, nil
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
