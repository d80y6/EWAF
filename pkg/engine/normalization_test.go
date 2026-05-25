package engine

import (
	"testing"
    "net/http"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestEngine_Normalization(t *testing.T) {
	e := NewEngine()

	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Double encoding",
			url:      "/search?q=%2527%2520OR%25201%253D1",
			expected: "/search?q=' or 1=1",
		},
		{
			name:     "Null byte",
			url:      "/admin\x00/login",
			expected: "/admin/login",
		},
		{
			name:     "Multiple slashes",
			url:      "///admin//config",
			expected: "/admin/config",
		},
		{
			name:     "Whitespace collapsing",
			url:      "/search?q=select    *   from  users",
			expected: "/search?q=select * from users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &model.RequestContext{URL: tt.url}
			e.NormalizeRequest(req)
			if req.NormalizedURL != tt.expected {
				t.Errorf("NormalizeRequest() = %v, want %v", req.NormalizedURL, tt.expected)
			}
		})
	}
}

func TestEngine_XMLNormalization(t *testing.T) {
	e := NewEngine()

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "Flatten XML attributes and text",
			body:     `<user id="1' or '1'='1">admin</user>`,
			expected: "1' or '1'='1 admin ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &model.RequestContext{
				Body:    []byte(tt.body),
				Headers: http.Header{"Content-Type": []string{"application/xml"}},
			}
			e.ParseBody(req)
			if req.NormalizedBody != tt.expected {
				t.Errorf("ParseBody() = %q, want %q", req.NormalizedBody, tt.expected)
			}
		})
	}
}
