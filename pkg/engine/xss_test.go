package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func TestEngine_XSSCRS(t *testing.T) {
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
			name: "Basic script tag",
			req: &model.RequestContext{
				URL:     "/search?q=<script>alert(1)</script>",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "Attribute-based XSS (onerror)",
			req: &model.RequestContext{
				URL:     "/profile?name='><img src=x onerror=alert(1)>",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "Javascript protocol in href",
			req: &model.RequestContext{
				URL:     "/redirect?url=javascript:alert(1)",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "SVG onbegin XSS",
			req: &model.RequestContext{
				URL:     "/api/v1/upload?content=<svg/onbegin=alert(1)>",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        {
			name: "Safe request with HTML-like content",
			req: &model.RequestContext{
				URL:     "/blog/post?title=how-to-use-the-script-command",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
        {
			name: "Fullwidth character evasion",
			req: &model.RequestContext{
				URL:     "/search?q=＜ｓｃｒｉｐｔ＞ａｌｅｒｔ（１）＜／ｓｃｒｉｐｔ＞",
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
