package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func TestEngine_FalsePositives(t *testing.T) {
	e := NewEngine()
	err := e.LoadRules(rules.GetDefaultRules())
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	tests := []struct {
		name        string
		req         *model.RequestContext
		shouldBlock bool
	}{
		{
			name: "Safe REST API call",
			req: &model.RequestContext{
				URL:     "/api/v1/users/123/profile",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
		{
			name: "Search query with common words",
			req: &model.RequestContext{
				URL:     "/search?q=union+of+states&sort=name",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
		{
			name: "JSON body with normal text",
			req: &model.RequestContext{
				URL:    "/api/v1/posts",
				Method: "POST",
				Body:   []byte(`{"title": "The OR algorithm", "content": "This is a great update."}`),
				Headers: http.Header{"Content-Type": []string{"application/json"}},
			},
			shouldBlock: false,
		},
		{
			name: "URL with safe symbols",
			req: &model.RequestContext{
				URL:     "/path/to/file!@#$.html",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, blocked := e.InspectRequest(context.Background(), tt.req)
			if blocked != tt.shouldBlock {
				t.Errorf("Engine.InspectRequest(%s) blocked = %v, want %v. Matched Rules: %v", tt.name, blocked, tt.shouldBlock, req.MatchedRules)
			}
		})
	}
}
