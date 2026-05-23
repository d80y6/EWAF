package main

import (
	"log"
	"net/http"
	"os"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"encoding/json"
	"strings"
	"time"
)

type ControlPlane struct {
	db *gorm.DB
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
	if err := db.AutoMigrate(&model.Tenant{}, &model.Rule{}, &model.SecurityEvent{}, &model.GlobalStats{}); err != nil {
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
	var total, blocked, anomaly, api int64
	cp.db.Model(&model.GlobalStats{}).Where("key = ?", "total_requests").Select("value").Scan(&total)
	cp.db.Model(&model.GlobalStats{}).Where("key = ?", "blocked_requests").Select("value").Scan(&blocked)
	cp.db.Model(&model.GlobalStats{}).Where("key = ?", "ml_anomalies").Select("value").Scan(&anomaly)
	cp.db.Model(&model.GlobalStats{}).Where("key = ?", "api_violations").Select("value").Scan(&api)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRequests":   total,
		"blockedRequests": blocked,
		"threatLevel":     "Low",
		"mlAnomalies":     anomaly,
		"apiViolations":   api,
		"maliciousIPs":    1240,
		"activeTenants":   1,
	})
}

func (cp *ControlPlane) PostStats(w http.ResponseWriter, r *http.Request) {
	var s struct {
		Blocked      bool     `json:"blocked"`
		Anomaly      bool     `json:"anomaly"`
		APIViolation bool     `json:"apiViolation"`
		RequestID    string   `json:"requestID"`
		RemoteAddr   string   `json:"remoteAddr"`
		Method       string   `json:"method"`
		URL          string   `json:"url"`
		Score        int      `json:"score"`
		MatchedRules []string `json:"matchedRules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		return
	}

	cp.incrementStat("total_requests")
	if s.Blocked {
		cp.incrementStat("blocked_requests")
	}
	if s.Anomaly {
		cp.incrementStat("ml_anomalies")
	}
	if s.APIViolation {
		cp.incrementStat("api_violations")
	}

	// Persist security event if blocked or anomaly
	if s.Blocked || s.Anomaly || s.APIViolation {
		event := model.SecurityEvent{
			Timestamp:      time.Now(),
			RequestID:      s.RequestID,
			RemoteAddr:     s.RemoteAddr,
			Method:         s.Method,
			URL:            s.URL,
			MatchedRules:   strings.Join(s.MatchedRules, ","),
			Score:          s.Score,
			IsAnomaly:      s.Anomaly,
			IsAPIViolation: s.APIViolation,
		}
		cp.db.Create(&event)
	}
}

func (cp *ControlPlane) incrementStat(key string) {
	cp.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"value": gorm.Expr("value + ?", 1)}),
	}).Create(&model.GlobalStats{Key: key, Value: 1})
}

func (cp *ControlPlane) GetAPIPolicies(w http.ResponseWriter, r *http.Request) {
	// For now, return a default policy. In a full implementation, this would be from DB.
	policies := []model.APISecurityPolicy{
		{
			ID:            "1",
			PathPrefix:    "/api",
			JWTVaildation: true,
			JWTSecret:     "sentinel-default-secret",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(policies)
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
	http.HandleFunc("/api/policies", cp.GetAPIPolicies)
	http.HandleFunc("/api/stats", cp.GetStats)
	http.HandleFunc("/api/stats/report", cp.PostStats)

	log.Println("Control Plane API listening on :8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}
}
