package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestEngine_TenantIsolation(t *testing.T) {
	e := NewEngine()

	// Setup rules:
	// 1. Global rule (Score 1)
	// 2. Tenant 1 rule: "Block All" (Score 100, Action block)
	// 3. Tenant 2 rule: Match "/secret" (Score 100, Action block)

	rules := []model.Rule{
		{
			RuleID: "GLOBAL_1",
			TenantID: 0,
			Action: "allow",
			Score: 1,
			Conditions: []model.Condition{{Target: "url", Operator: "contains", Value: "/"}},
		},
		{
			RuleID: "TENANT_1_BLOCK",
			TenantID: 1,
			Action: "block",
			Score: 100,
			Conditions: []model.Condition{{Target: "url", Operator: "contains", Value: "/"}},
		},
		{
			RuleID: "TENANT_2_SECRET",
			TenantID: 2,
			Action: "block",
			Score: 100,
			Conditions: []model.Condition{{Target: "url", Operator: "contains", Value: "/secret"}},
		},
	}

	e.LoadRules(rules)

	tests := []struct {
		name        string
		tenantID    uint
		url         string
		shouldBlock bool
	}{
		{"Tenant 1: Blocked by its own rule", 1, "/any", true},
		{"Tenant 2: Allowed (not matching secret)", 2, "/any", false},
		{"Tenant 2: Blocked (matching secret)", 2, "/secret", true},
		{"Global (Tenant 0): Allowed", 0, "/any", false},
		{"Tenant 3: Allowed (only global rules apply)", 3, "/any", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &model.RequestContext{
				TenantID: tt.tenantID,
				URL:      tt.url,
				Headers:  make(http.Header),
			}
			_, blocked := e.InspectRequest(context.Background(), req)
			if blocked != tt.shouldBlock {
				t.Errorf("%s: blocked = %v, want %v", tt.name, blocked, tt.shouldBlock)
			}
		})
	}
}
