package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestEngine_ThreatIntel(t *testing.T) {
	e := NewEngine()

	reputation := map[string]int{
		"1.2.3.4": 100, // Malicious
		"5.6.7.8": 10,  // Safe-ish
	}
	e.SetIPReputation(reputation)

	tests := []struct {
		ip          string
		shouldBlock bool
	}{
		{"1.2.3.4", true},
		{"5.6.7.8", false},
		{"9.9.9.9", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			req := &model.RequestContext{
				RemoteAddr: tt.ip,
				URL: "/",
				Headers: make(http.Header),
			}
			_, blocked := e.InspectRequest(context.Background(), req)
			if blocked != tt.shouldBlock {
				t.Errorf("IP %s: blocked = %v, want %v", tt.ip, blocked, tt.shouldBlock)
			}
		})
	}
}
