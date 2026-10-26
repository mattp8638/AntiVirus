package fleet

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

type probeTarget struct {
	MonitorID string `json:"monitorId"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
}

// probeAllowed refuses targets a LAN probe has no business checking (this host, link-local/metadata, multicast).
func probeAllowed(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() && !ip.IsUnspecified()
}

// NetworkProbe checks TCP services for the cloud's network monitors (at most 100 targets, 2 s each, in parallel).
func NetworkProbe(raw string, dial func(network, address string, timeout time.Duration) (net.Conn, error)) (map[string]interface{}, error) {
	var payload struct {
		Targets []probeTarget `json:"targets"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, errors.New("invalid probe payload")
	}
	if len(payload.Targets) > 100 {
		payload.Targets = payload.Targets[:100]
	}
	if dial == nil {
		dial = net.DialTimeout
	}
	results := make([]map[string]interface{}, len(payload.Targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, target := range payload.Targets {
		wg.Add(1)
		go func(i int, t probeTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result := map[string]interface{}{"monitorId": t.MonitorID, "up": false}
			if !probeAllowed(t.Address) || t.Port < 1 || t.Port > 65535 {
				result["error"] = "target not allowed"
				results[i] = result
				return
			}
			started := time.Now()
			conn, err := dial("tcp", net.JoinHostPort(t.Address, strconv.Itoa(t.Port)), 2*time.Second)
			if err != nil {
				result["error"] = err.Error()
			} else {
				_ = conn.Close()
				result["up"] = true
				result["latencyMs"] = float64(time.Since(started).Microseconds()) / 1000
			}
			results[i] = result
		}(i, target)
	}
	wg.Wait()
	return map[string]interface{}{"results": results}, nil
}
