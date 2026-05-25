package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func TestEngine_SQLICRS(t *testing.T) {
	e := NewEngine()

	defaultRules := rules.GetDefaultRules()
	err := e.LoadRules(defaultRules)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	tests := []struct {
		name        string
		req         *model.RequestContext
		shouldBlock bool
	}{
		{
			name: "UNION based SQLi",
			req: &model.RequestContext{
				URL:     "/search?q=foo' union select null,null,null--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "Boolean based SQLi",
			req: &model.RequestContext{
				URL:     "/login?user=admin' AND 1=1--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "Time based SQLi (MySQL)",
			req: &model.RequestContext{
				URL:     "/products?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "Stacked queries",
			req: &model.RequestContext{
				URL:     "/api/item?id=123; DROP TABLE users",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "Safe common request",
			req: &model.RequestContext{
				URL:     "/api/products?category=electronics&sort=price_desc",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
		{
			name: "Double encoding bypass attempt",
			req: &model.RequestContext{
				URL:     "/search?q=%2527%2520UNION%2520SELECT",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        {
			name: "Case mutation evasion",
			req: &model.RequestContext{
				URL:     "/search?q=foo' UnIoN SeLeCt null--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        {
			name: "Comment evasion",
			req: &model.RequestContext{
				URL:     "/search?q=foo'/**/union/**/select/**/null--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        {
			name: "Boolean OR evasion",
			req: &model.RequestContext{
				URL:     "/search?q=admin' OR 1=1--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        {
			name: "Postgres waitfor evasion",
			req: &model.RequestContext{
				URL:     "/search?q=1; select pg_sleep(10);--",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, blocked := e.InspectRequest(context.Background(), tt.req)
			if blocked != tt.shouldBlock {
				t.Errorf("Engine.InspectRequest(%s) blocked = %v, want %v. Matched Rules: %v, Score: %d", tt.name, blocked, tt.shouldBlock, req.MatchedRules, req.Score)
			}
		})
	}
}

func TestEngine_SQLI_Headers(t *testing.T) {
	e := NewEngine()
	e.LoadRules(rules.GetDefaultRules())

	tests := []struct {
		name        string
		req         *model.RequestContext
		shouldBlock bool
	}{
		{
			name: "SQLi in User-Agent",
			req: &model.RequestContext{
				URL:     "/",
				Method:  "GET",
				Headers: http.Header{"User-Agent": []string{"' UNION SELECT 1,2,3--"}},
			},
			shouldBlock: true,
		},
		{
			name: "SQLi in Cookie",
			req: &model.RequestContext{
				URL:     "/",
				Method:  "GET",
				Headers: http.Header{"Cookie": []string{"sessionid=1' OR '1'='1"}},
			},
			shouldBlock: true,
		},
		{
			name: "Safe headers",
			req: &model.RequestContext{
				URL:     "/",
				Method:  "GET",
				Headers: http.Header{"User-Agent": []string{"Mozilla/5.0"}, "X-Request-ID": []string{"abc-123"}},
			},
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, blocked := e.InspectRequest(context.Background(), tt.req)
			if blocked != tt.shouldBlock {
				t.Errorf("Engine.InspectRequest(%s) blocked = %v, want %v", tt.name, blocked, tt.shouldBlock)
			}
		})
	}
}
