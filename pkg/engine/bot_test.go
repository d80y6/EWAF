package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestEngine_BotDetection(t *testing.T) {
	e := NewEngine()

	// 1. Block a specific "JA3" fingerprint (simulated by req.ID)
	badFingerprint := "malicious-bot-123"
	e.botDetector.BlockJA3(badFingerprint)

	tests := []struct {
		name        string
		id          string
		shouldBlock bool
	}{
		{"Blocked bot", badFingerprint, true},
		{"Legitimate user", "browser-chrome-456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &model.RequestContext{
				ID:         tt.id,
				URL:        "/",
				Headers:    make(http.Header),
				RemoteAddr: "1.1.1.1",
			}
			_, blocked := e.InspectRequest(context.Background(), req)
			if blocked != tt.shouldBlock {
				t.Errorf("%s: blocked = %v, want %v", tt.name, blocked, tt.shouldBlock)
			}
		})
	}
}

func TestBotDetector_Behavioral(t *testing.T) {
    e := NewEngine()
    req := &model.RequestContext{
        ID: "aggressive-bot",
        URL: "/",
        Headers: make(http.Header),
        RemoteAddr: "2.2.2.2",
    }

    // Simulate 101 requests to trigger behavioral block
    var blocked bool
    for i := 0; i < 101; i++ {
        _, blocked = e.InspectRequest(context.Background(), req)
    }

    if !blocked {
        t.Error("Bot should be blocked after 100 requests")
    }
}
