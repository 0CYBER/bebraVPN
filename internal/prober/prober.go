package prober

import (
	"net"
	"sort"
	"sync"
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

	dialer := &net.Dialer{Timeout: p.Timeout}
	address := net.JoinHostPort(info.Address, info.Port)
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return -1, err
	}
	defer conn.Close()

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

func (p *Prober) BestByLatency(servers []config.Server, concurrency int) ([]config.Server, map[string]int64) {
	results := p.PingBatch(servers, concurrency)
	ordered := append([]config.Server(nil), servers...)

	sort.SliceStable(ordered, func(i, j int) bool {
		li := results[ordered[i].URL]
		lj := results[ordered[j].URL]

		if li <= 0 && lj <= 0 {
			return ordered[i].Name < ordered[j].Name
		}
		if li <= 0 {
			return false
		}
		if lj <= 0 {
			return true
		}
		if li == lj {
			return ordered[i].Name < ordered[j].Name
		}
		return li < lj
	})

	return ordered, results
}
