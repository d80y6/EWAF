package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (p *Proxy) StartRuleUpdater(controlPlaneURL string) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			p.updateRules(controlPlaneURL)
		}
	}()
	// Initial update
	p.updateRules(controlPlaneURL)
}

func (p *Proxy) updateRules(url string) {
	resp, err := http.Get(url + "/api/rules")
	if err != nil {
		log.Printf("Failed to fetch rules from control plane: %v", err)
		return
	}
	defer resp.Body.Close()

	var rules []model.Rule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		log.Printf("Failed to decode rules: %v", err)
		return
	}

	if err := p.engine.LoadRules(rules); err != nil {
		log.Printf("Failed to load rules into engine: %v", err)
		return
	}
	log.Printf("Successfully updated %d rules from control plane", len(rules))
}
