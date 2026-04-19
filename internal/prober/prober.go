package prober

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
)

type Prober struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Prober {
	return &Prober{Timeout: timeout}
}

func (p *Prober) Ping(info *config.VlessInfo) (int64, error) {
	start := time.Now()
	
	// Use a dialer with timeout
	dialer := &net.Dialer{Timeout: p.Timeout}
	
	// Perform TCP connection
	address := net.JoinHostPort(info.Address, info.Port)
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return -1, err
	}
	defer conn.Close()

	// If it's a TLS/Reality server, we can try to do a minimal TLS peek
	// but for generic prober, measuring TCP + Handshake is best.
	// For now, let's do a basic TCP RTT as a baseline, 
	// but the plan mentioned TLS Handshake.
	
	if info.Security == "tls" || info.Security == "reality" {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         info.SNI,
		})
		
		err = tlsConn.Handshake()
		if err != nil {
			return -1, fmt.Errorf("tls handshake failed: %v", err)
		}
	}

	latency := time.Since(start).Milliseconds()
	return latency, nil
}
