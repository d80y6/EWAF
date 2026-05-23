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
			p.updateAPIPolicies(controlPlaneURL)
		}
	}()
	// Initial update
	p.updateRules(controlPlaneURL)
	p.updateAPIPolicies(controlPlaneURL)
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

func (p *Proxy) updateAPIPolicies(url string) {
	resp, err := http.Get(url + "/api/policies")
	if err != nil {
		log.Printf("Failed to fetch API policies from control plane: %v", err)
		return
	}
	defer resp.Body.Close()

	var policies []model.APISecurityPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		log.Printf("Failed to decode API policies: %v", err)
		return
	}

	p.mu.Lock()
	p.apiPolicies = policies
	p.mu.Unlock()
	log.Printf("Successfully updated %d API policies from control plane", len(policies))
}
