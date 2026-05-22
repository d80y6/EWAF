package main

import (
	"log"
	"net/http"
	"os"

	"github.com/sentinel-waf/sentinel-waf/internal/proxy"
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

	p, err := proxy.NewProxy(targetURL, wafEngine)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	cpURL := os.Getenv("CONTROL_PLANE_URL")
	if cpURL == "" {
		cpURL = "http://localhost:8081"
	}
	p.StartRuleUpdater(cpURL)

	log.Printf("Sentinel WAF Proxy listening on %s, forwarding to %s", listenAddr, targetURL)
	if err := http.ListenAndServe(listenAddr, p); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
