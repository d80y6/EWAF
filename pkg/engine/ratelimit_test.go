package engine

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_IsAllowed(t *testing.T) {
	// This test requires a running Redis instance or a mock.
	// For CI purposes, we might need a mock, but since the environment has Docker,
	// let's try to assume we can run it against a real one if available,
	// otherwise skip or use a mock logic.

	rl := NewRateLimiter("localhost:6379")
	ctx := context.Background()
	key := "test-ip-1"
	limit := 5
	window := time.Second

	// 1. Check basic limiting
	for i := 0; i < limit; i++ {
		allowed, err := rl.IsAllowed(ctx, key, limit, window)
		if err != nil {
			t.Logf("Redis probably not running: %v. Skipping real Redis test.", err)
			t.Skip()
			return
		}
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	allowed, _ := rl.IsAllowed(ctx, key, limit, window)
	if allowed {
		t.Error("Request exceeding limit should be blocked")
	}

	// 2. Check window reset
	time.Sleep(window + 100*time.Millisecond)
	allowed, _ = rl.IsAllowed(ctx, key, limit, window)
	if !allowed {
		t.Error("Request after window reset should be allowed")
	}
}

func TestRateLimiter_FailOpen(t *testing.T) {
	// Connect to non-existent Redis
	rl := NewRateLimiter("localhost:9999")
	ctx := context.Background()

	allowed, err := rl.IsAllowed(ctx, "any-key", 1, time.Minute)
	if err == nil {
		t.Error("Expected error from unreachable Redis")
	}
	if !allowed {
		t.Error("Should fail open (allowed=true) when Redis is unreachable")
	}
}
