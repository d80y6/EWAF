package engine

import (
	"context"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestMultiPassNormalization(t *testing.T) {
	e := NewEngine()
	req := &model.RequestContext{
		URL: "/api/test%252e%252e%252fetc/passwd", // Double encoded ../
	}
	e.NormalizeRequest(req)

	expected := "/api/test../etc/passwd"
	if req.NormalizedURL != expected {
		t.Errorf("Expected %s, got %s", expected, req.NormalizedURL)
	}
}

func TestTenantIsolation(t *testing.T) {
	e := NewEngine()

	// Rule for Tenant 1
	rule1 := model.Rule{RuleID: "RULE1", Name: "Rule 1", Action: "block", Score: 100, Conditions: []model.Condition{{Operator: "contains", Target: "url", Value: "malicious"}}}
	e.tenantRules[1] = []model.Rule{rule1}

	// Request for Tenant 2 (should not trigger Tenant 1's rule)
	req := &model.RequestContext{
		TenantID: 2,
		URL: "/malicious",
	}

	_, blocked := e.InspectRequest(context.Background(), req)
	if blocked {
		t.Error("Request for Tenant 2 was blocked by Tenant 1 rule")
	}

	// Request for Tenant 1 (should trigger)
	req1 := &model.RequestContext{
		TenantID: 1,
		URL: "/malicious",
	}
	_, blocked1 := e.InspectRequest(context.Background(), req1)
	if !blocked1 {
		t.Error("Request for Tenant 1 was not blocked by its own rule")
	}
}
