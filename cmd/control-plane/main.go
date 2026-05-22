package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

import (
	"sync/atomic"
)

type ControlPlane struct {
	mu              sync.RWMutex
	rules           []model.Rule
	tenants         map[string]model.Tenant
	totalRequests   int64
	blockedRequests int64
	mlAnomalies     int64
	apiViolations   int64
}

func NewControlPlane() *ControlPlane {
	return &ControlPlane{
		rules:   rules.GetDefaultRules(),
		tenants: make(map[string]model.Tenant),
	}
}

func (cp *ControlPlane) GetRules(w http.ResponseWriter, r *http.Request) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(cp.rules)
}

func (cp *ControlPlane) GetStats(w http.ResponseWriter, r *http.Request) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRequests":   atomic.LoadInt64(&cp.totalRequests),
		"blockedRequests": atomic.LoadInt64(&cp.blockedRequests),
		"threatLevel":     "Low",
		"mlAnomalies":     atomic.LoadInt64(&cp.mlAnomalies),
		"apiViolations":   atomic.LoadInt64(&cp.apiViolations),
		"maliciousIPs":    1240,
		"activeTenants":   len(cp.tenants) + 1,
	})
}

func (cp *ControlPlane) PostStats(w http.ResponseWriter, r *http.Request) {
	var s struct {
		Blocked       bool `json:"blocked"`
		Anomaly       bool `json:"anomaly"`
		APIViolation  bool `json:"apiViolation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		return
	}

	atomic.AddInt64(&cp.totalRequests, 1)
	if s.Blocked {
		atomic.AddInt64(&cp.blockedRequests, 1)
	}
	if s.Anomaly {
		atomic.AddInt64(&cp.mlAnomalies, 1)
	}
	if s.APIViolation {
		atomic.AddInt64(&cp.apiViolations, 1)
	}
}

func main() {
	cp := NewControlPlane()
	http.HandleFunc("/api/rules", cp.GetRules)
	http.HandleFunc("/api/stats", cp.GetStats)
	http.HandleFunc("/api/stats/report", cp.PostStats)

	log.Println("Control Plane API listening on :8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}
}
