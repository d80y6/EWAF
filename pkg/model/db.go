package model

import (
	"time"
	"gorm.io/gorm"
)

type Rule struct {
	gorm.Model
	RuleID      string `gorm:"uniqueIndex;size:64"`
	Name        string `gorm:"size:255"`
	Description string `gorm:"type:text"`
	Severity    string `gorm:"size:20"`
	Category    string `gorm:"size:50"`
	Action      string `gorm:"size:20"`
	Score       int
	TenantID    uint        `gorm:"index"`
	Conditions  []Condition `gorm:"-"` // Not persisted for now
}

func (r *Rule) GetID() string {
	if r.RuleID != "" {
		return r.RuleID
	}
	return time.Now().Format("20060102150405")
}

type Tenant struct {
	gorm.Model
	Name     string `gorm:"uniqueIndex;size:255"`
	APIKey   string `gorm:"uniqueIndex;size:64"`
	IsActive bool   `gorm:"default:true"`
	Rules    []Rule `gorm:"foreignKey:TenantID"`
}

type SecurityEvent struct {
	gorm.Model
	Timestamp      time.Time
	RequestID      string `gorm:"size:64"`
	TenantID       string `gorm:"size:64"`
	RemoteAddr     string `gorm:"size:64"`
	Method         string `gorm:"size:10"`
	URL            string `gorm:"type:text"`
	MatchedRules   string `gorm:"type:text"` // Comma-separated or JSON
	Score          int
	Action         string `gorm:"size:20"`
	UserAgent      string `gorm:"type:text"`
	MLAnomalyScore float64
	IsAnomaly      bool
	IsAPIViolation bool
}

type GlobalStats struct {
	gorm.Model
	Key   string `gorm:"uniqueIndex;size:64"`
	Value int64
}
