package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestEngine_InspectRequest(t *testing.T) {
	e := NewEngine()
	rules := []model.Rule{
		{
			ID:     "1",
			Name:   "SQL Injection detection",
			Action: "block",
			Score:  10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)",
				},
			},
		},
	}

	err := e.LoadRules(rules)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	tests := []struct {
		name        string
		req         *model.RequestContext
		shouldBlock bool
	}{
		{
			name: "Safe request",
			req: &model.RequestContext{
				URL:     "/api/v1/health",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
		{
			name: "SQL injection in URL",
			req: &model.RequestContext{
				URL:     "/api/v1/users?id=1' OR '1'='1",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, blocked := e.InspectRequest(context.Background(), tt.req)
			if blocked != tt.shouldBlock {
				t.Errorf("Engine.InspectRequest() blocked = %v, want %v", blocked, tt.shouldBlock)
			}
		})
	}
}
