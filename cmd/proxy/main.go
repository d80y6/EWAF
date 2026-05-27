package main

import (
	"log"
	"net/http"
	"os"

	"github.com/sentinel-waf/sentinel-waf/internal/proxy"
	"github.com/sentinel-waf/sentinel-waf/pkg/ebpf"
	"github.com/sentinel-waf/sentinel-waf/pkg/engine"
)

func main() {
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "http://localhost:8080"
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":80"
	}

	wafEngine := engine.NewEngine()

	cpURL := os.Getenv("CONTROL_PLANE_URL")
	if cpURL == "" {
		cpURL = "http://localhost:8081"
	}

    redisAddr := os.Getenv("REDIS_ADDR")
    if redisAddr == "" {
        redisAddr = "localhost:6379"
    }

	// Initialize eBPF/XDP (Phase 3)
	xdpManger := ebpf.NewXDPManager()

    // Initialize Rate Limiter (M-07)
    ratelimiter := engine.NewRateLimiter(redisAddr)

	p, err := proxy.NewProxy(targetURL, wafEngine, cpURL, xdpManger, ratelimiter)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	p.StartRuleUpdater(cpURL)
	if iface := os.Getenv("XDP_INTERFACE"); iface != "" {
		if err := xdpManger.Load(iface); err != nil {
			log.Printf("Warning: failed to load XDP: %v", err)
		} else {
			defer xdpManger.Close()
		}
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("Sentinel WAF Proxy listening on %s, forwarding to %s", listenAddr, targetURL)
	if err := http.ListenAndServe(listenAddr, p); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
