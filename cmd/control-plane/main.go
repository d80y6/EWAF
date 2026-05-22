package main

import (
	"log"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"encoding/json"
)

type ControlPlane struct {
	db              *gorm.DB
	totalRequests   int64
	blockedRequests int64
	mlAnomalies     int64
	apiViolations   int64
}

func NewControlPlane(dsn string) (*ControlPlane, error) {
	var db *gorm.DB
	var err error
	if dsn == "sqlite://sentinel.db" {
		db, err = gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
	} else {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}
	if err != nil {
		return nil, err
	}

	// Auto-migrate
	if err := db.AutoMigrate(&model.Tenant{}, &model.Rule{}); err != nil {
		return nil, err
	}

	// Seed default rules if empty
	var count int64
	db.Model(&model.Rule{}).Count(&count)
	if count == 0 {
		defaultRules := rules.GetDefaultRules()
		for _, r := range defaultRules {
			db.Create(&r)
		}
	}

	return &ControlPlane{db: db}, nil
}

func (cp *ControlPlane) GetRules(w http.ResponseWriter, r *http.Request) {
	var rules []model.Rule
	if err := cp.db.Find(&rules).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(rules)
}

func (cp *ControlPlane) GetStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRequests":   atomic.LoadInt64(&cp.totalRequests),
		"blockedRequests": atomic.LoadInt64(&cp.blockedRequests),
		"threatLevel":     "Low",
		"mlAnomalies":     atomic.LoadInt64(&cp.mlAnomalies),
		"apiViolations":   atomic.LoadInt64(&cp.apiViolations),
		"maliciousIPs":    1240,
		"activeTenants":   1,
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
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "sqlite://sentinel.db"
	}

	cp, err := NewControlPlane(dsn)
	if err != nil {
		log.Fatalf("Failed to initialize control plane: %v", err)
	}

	http.HandleFunc("/api/rules", cp.GetRules)
	http.HandleFunc("/api/stats", cp.GetStats)
	http.HandleFunc("/api/stats/report", cp.PostStats)

	log.Println("Control Plane API listening on :8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}
}
