package config

type Config struct {
	Servers  []Server `mapstructure:"servers" yaml:"servers" json:"servers"`
	System   System   `mapstructure:"system" yaml:"system" json:"system"`
	LogLevel string   `mapstructure:"log_level" yaml:"log_level" json:"log_level"`
}

type Server struct {
	Name     string `mapstructure:"name" yaml:"name" json:"name"`
	URL      string `mapstructure:"url" yaml:"url" json:"url"` // vless:// link
	Selected bool   `mapstructure:"selected" yaml:"selected" json:"selected"`
	Latency  int64  `mapstructure:"latency" yaml:"latency" json:"latency"` // in ms
}

type System struct {
	ProxyPort     int      `mapstructure:"proxy_port" yaml:"proxy_port" json:"proxy_port"`
	SocksPort     int      `mapstructure:"socks_port" yaml:"socks_port" json:"socks_port"`
	EnableProxy   bool     `mapstructure:"enable_proxy" yaml:"enable_proxy" json:"enable_proxy"`
	EnableTun     bool     `mapstructure:"enable_tun" yaml:"enable_tun" json:"enable_tun"`
	TestMode      bool     `mapstructure:"test_mode" yaml:"test_mode" json:"test_mode"`
	SecurityProfile string `mapstructure:"security_profile" yaml:"security_profile" json:"security_profile"`
	BypassApps    []string `mapstructure:"bypass_apps" yaml:"bypass_apps" json:"bypass_apps"`
	BypassDomains []string `mapstructure:"bypass_domains" yaml:"bypass_domains" json:"bypass_domains"`
}
