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
	if err := db.AutoMigrate(&model.Tenant{}, &model.Rule{}, &model.SecurityEvent{}, &model.GlobalStats{}, &model.APISecurityPolicyDB{}); err != nil {
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

func (cp *ControlPlane) PostRule(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := cp.db.Create(&rule).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
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
	var stats []model.GlobalStats
	if err := cp.db.Find(&stats).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := map[string]interface{}{
		"totalRequests":   int64(0),
		"blockedRequests": int64(0),
		"threatLevel":     "Low",
		"mlAnomalies":     int64(0),
		"apiViolations":   int64(0),
		"maliciousIPs":    1240,
		"activeTenants":   1,
	}

	for _, s := range stats {
		switch s.Key {
		case "total_requests":
			res["totalRequests"] = s.Value
		case "blocked_requests":
			res["blockedRequests"] = s.Value
		case "ml_anomalies":
			res["mlAnomalies"] = s.Value
		case "api_violations":
			res["apiViolations"] = s.Value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(res)
}

func (cp *ControlPlane) GetEvents(w http.ResponseWriter, r *http.Request) {
	var events []model.SecurityEvent
	if err := cp.db.Order("timestamp desc").Limit(100).Find(&events).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Format for frontend
	type UIEvent struct {
		ID     uint      `json:"id"`
		Time   time.Time `json:"time"`
		IP     string    `json:"ip"`
		Method string    `json:"method"`
		URL    string    `json:"url"`
		Rule   string    `json:"rule"`
		Score  int       `json:"score"`
	}
	res := make([]UIEvent, len(events))
	for i, e := range events {
		res[i] = UIEvent{
			ID:     e.ID,
			Time:   e.Timestamp,
			IP:     e.RemoteAddr,
			Method: e.Method,
			URL:    e.URL,
			Rule:   e.MatchedRules,
			Score:  e.Score,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(res)
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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

func (cp *ControlPlane) SimulateRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Rule model.Rule `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Fetch recent events to simulate against
	var events []model.SecurityEvent
	cp.db.Order("timestamp desc").Limit(1000).Find(&events)

	matches := 0
	for _, event := range events {
		// Mock engine context for simulation
		// In a real implementation, we'd reconstruct model.RequestContext and use engine.evaluateCondition
		if strings.Contains(event.URL, req.Rule.Conditions[0].Value) {
			matches++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalAnalyzed": len(events),
		"matches":       matches,
		"impactPercent": float64(matches) / float64(len(events)) * 100,
	})
}

func (cp *ControlPlane) incrementStat(key string) {
	err := cp.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"value": gorm.Expr("value + ?", 1)}),
	}).Create(&model.GlobalStats{Key: key, Value: 1}).Error
	if err != nil {
		log.Printf("Error incrementing stat %s: %v", key, err)
	}
}

func (cp *ControlPlane) GetAPIPolicies(w http.ResponseWriter, r *http.Request) {
	var policiesDB []model.APISecurityPolicyDB
	if err := cp.db.Find(&policiesDB).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	policies := make([]model.APISecurityPolicy, len(policiesDB))
	for i, p := range policiesDB {
		policies[i] = p.ToModel()
	}

	// Fallback to default if none configured
	if len(policies) == 0 {
		jwtSecret := os.Getenv("SENTINEL_JWT_SECRET")
		if jwtSecret == "" {
			log.Println("WARNING: SENTINEL_JWT_SECRET not set, API security will be bypassed")
		}
		policies = []model.APISecurityPolicy{
			{
				ID:            "1",
				PathPrefix:    "/api",
				JWTVaildation: jwtSecret != "",
				JWTSecret:     jwtSecret,
			},
		}
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

	http.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			cp.PostRule(w, r)
		} else {
			cp.GetRules(w, r)
		}
	})
	http.HandleFunc("/api/policies", cp.GetAPIPolicies)
	http.HandleFunc("/api/stats", cp.GetStats)
	http.HandleFunc("/api/stats/report", cp.PostStats)
	http.HandleFunc("/api/simulate", cp.SimulateRule)
	http.HandleFunc("/api/events", cp.GetEvents)

	log.Println("Control Plane API listening on :8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}
}
