package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

const CacheFile = "/tmp/sentinel_rules_cache.json"

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
		log.Printf("Failed to fetch rules from control plane: %v. Attempting to load from cache.", err)
		p.loadRulesFromCache()
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
	p.saveRulesToCache(rules)
}

func (p *Proxy) saveRulesToCache(rules []model.Rule) {
	data, err := json.Marshal(rules)
	if err != nil {
		return
	}
	os.WriteFile(CacheFile, data, 0644)
}

func (p *Proxy) loadRulesFromCache() {
	data, err := os.ReadFile(CacheFile)
	if err != nil {
		return
	}
	var rules []model.Rule
	if err := json.Unmarshal(data, &rules); err == nil {
		p.engine.LoadRules(rules)
		log.Printf("Successfully loaded %d rules from local cache", len(rules))
	}
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
