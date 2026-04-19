package config

type Config struct {
	Servers  []Server `mapstructure:"servers"`
	System   System   `mapstructure:"system"`
	LogLevel string   `mapstructure:"log_level"`
}

type Server struct {
	Name     string `mapstructure:"name"`
	URL      string `mapstructure:"url"` // vless:// link
	Selected bool   `mapstructure:"selected"`
	Latency  int64  `mapstructure:"latency"` // in ms
}

type System struct {
	ProxyPort   int  `mapstructure:"proxy_port"`
	SocksPort   int  `mapstructure:"socks_port"`
	EnableProxy bool `mapstructure:"enable_proxy"`
}
