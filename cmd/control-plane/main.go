package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

type ControlPlane struct {
	mu    sync.RWMutex
	rules []model.Rule
}

func NewControlPlane() *ControlPlane {
	return &ControlPlane{
		rules: rules.GetDefaultRules(),
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRequests":   125430,
		"blockedRequests": 432,
		"threatLevel":     "Low",
	})
}

func main() {
	cp := NewControlPlane()
	http.HandleFunc("/api/rules", cp.GetRules)
	http.HandleFunc("/api/stats", cp.GetStats)

	log.Println("Control Plane API listening on :8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}
}
