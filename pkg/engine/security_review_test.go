package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func TestEngine_SecurityReview_Bypasses(t *testing.T) {
	e := NewEngine()
	e.LoadRules(rules.GetDefaultRules())

	tests := []struct {
		name        string
		req         *model.RequestContext
		shouldBlock bool
	}{
		{
			name: "Unicode evasion (Fullwidth)",
			req: &model.RequestContext{
				URL:     "/search?q=1' ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2,3--", // Unicode U+FF35 etc.
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "JSON nesting evasion",
			req: &model.RequestContext{
				URL:    "/api",
				Method: "POST",
				Body:   []byte(`{"data": {"nested": {"query": "SELECT * FROM users"}}}`),
				Headers: http.Header{"Content-Type": []string{"application/json"}},
			},
			shouldBlock: true,
		},
		{
			name: "Mixed encoding evasion",
			req: &model.RequestContext{
				URL:     "/search?q=%27%20UNION%20SEL%45CT", // SEL%45CT -> SELECT
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
				t.Errorf("Engine.InspectRequest(%s) blocked = %v, want %v", tt.name, blocked, tt.shouldBlock)
			}
		})
	}
}
