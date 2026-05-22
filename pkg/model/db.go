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
	Timestamp      time.Time
	RequestID      string
	TenantID       string
	RemoteAddr     string
	Method         string
	URL            string
	MatchedRules   []string
	Score          int
	Action         string
	UserAgent      string
	MLAnomalyScore float64
}
