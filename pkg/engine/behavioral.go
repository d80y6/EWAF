package engine

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
    "sync"
    "time"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type BotDetector struct {
	mu           sync.RWMutex
	profiles     map[string]*BehavioralProfile
	blockedJA3s  map[string]bool
}

func NewBotDetector() *BotDetector {
	return &BotDetector{
		profiles:    make(map[string]*BehavioralProfile),
		blockedJA3s: make(map[string]bool),
	}
}

func (e *Engine) GenerateFingerprint(req *model.RequestContext) string {
	// Simple fingerprint based on headers and IP
	var headers []string
	for k := range req.Headers {
		headers = append(headers, k)
	}
	sort.Strings(headers)

	raw := fmt.Sprintf("%s|%s|%s", req.RemoteAddr, req.Headers.Get("User-Agent"), strings.Join(headers, ","))
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}

func (b *BotDetector) IsBot(req *model.RequestContext) bool {
	b.mu.RLock()
	// 1. Check if JA3 (or our proxy fingerprint) is explicitly blocked
	if b.blockedJA3s[req.ID] { // Using req.ID as a placeholder for JA3 in this implementation
		b.mu.RUnlock()
		return true
	}
	b.mu.RUnlock()

	// 2. Behavioral analysis: check request frequency for this fingerprint
    // For M-09, we'll use a simple in-memory frequency check
    fingerprint := req.ID // Placeholder

    b.mu.Lock()
    defer b.mu.Unlock()

    profile, ok := b.profiles[fingerprint]
    if !ok {
        profile = &BehavioralProfile{
            Fingerprint: fingerprint,
            LastSeen:     time.Now().Unix(),
        }
        b.profiles[fingerprint] = profile
    }

    profile.RequestCount++
    profile.LastSeen = time.Now().Unix()

    // Simple heuristic: > 100 requests in a short burst (simulated)
    if profile.RequestCount > 100 {
        return true
    }

	return false
}

func (b *BotDetector) BlockJA3(ja3 string) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.blockedJA3s[ja3] = true
}

type BehavioralProfile struct {
	Fingerprint string
	RequestCount int
	LastSeen     int64
	Score        float64
}
