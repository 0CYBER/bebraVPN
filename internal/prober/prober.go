package prober

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/0CYBER/bebravpn/internal/config"
	utls "github.com/refraction-networking/utls"
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
		tlsConn := utls.UClient(conn, &utls.Config{
			InsecureSkipVerify: true,
			ServerName:         info.SNI,
		}, utls.HelloChrome_Auto)
		
		err = tlsConn.Handshake()
		if err != nil {
			return -1, fmt.Errorf("utls handshake failed: %v", err)
		}
	}

	latency := time.Since(start).Milliseconds()
	return latency, nil
}

func (p *Prober) PingBatch(servers []config.Server, concurrency int) map[string]int64 {
	results := make(map[string]int64)
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	sem := make(chan struct{}, concurrency)

	for _, s := range servers {
		wg.Add(1)
		go func(s config.Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info, err := config.ParseVless(s.URL)
			if err != nil {
				mu.Lock()
				results[s.URL] = -1
				mu.Unlock()
				return
			}

			latency, err := p.Ping(info)
			mu.Lock()
			if err != nil {
				results[s.URL] = -1
			} else {
				results[s.URL] = latency
			}
			mu.Unlock()
		}(s)
	}

	wg.Wait()
	return results
}
