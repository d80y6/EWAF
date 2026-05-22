package proxy

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (p *Proxy) StartStatsReporter(controlPlaneURL string) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			p.reportStats(controlPlaneURL)
		}
	}()
}

func (p *Proxy) reportStats(url string) {
	// For now, proxy reports its own local stats to CP
	// In a real distributed system, this would be more complex
}
