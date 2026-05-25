package engine

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

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

type BehavioralProfile struct {
	Fingerprint string
	RequestCount int
	LastSeen     int64
	Score        float64
}

func (e *Engine) AnalyzeBehavior(req *model.RequestContext) bool {
	// 1. Static Bot Detection (UA checks)
	ua := req.Headers.Get("User-Agent")
	if ua == "" || strings.Contains(strings.ToLower(ua), "headless") || strings.Contains(strings.ToLower(ua), "python-requests") {
		req.Score += 40
		req.MatchedRules = append(req.MatchedRules, "BOT_SUSPICIOUS_USER_AGENT")
		return true
	}

	// 2. Behavioral Bot Detection (Path pattern analysis)
	// Example: Rapid access to sensitive files
	if strings.Contains(req.URL, ".env") || strings.Contains(req.URL, ".git") {
		req.Score += 100
		req.MatchedRules = append(req.MatchedRules, "BOT_SENSITIVE_FILE_PROBING")
		return true
	}

	return false
}
