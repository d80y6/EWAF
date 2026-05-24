package engine

import (
	"math"
	"strings"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Optimized byte-level entropy calculation to bypass UTF-8 overhead
	var frequencies [256]float64
	for i := 0; i < len(data); i++ {
		frequencies[data[i]]++
	}

	var entropy float64
	length := float64(len(data))
	for _, freq := range frequencies {
		if freq > 0 {
			p := freq / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (e *Engine) DetectAnomaly(req *model.RequestContext) bool {
	// 1. Allow-list for common system and health check paths
	if strings.HasSuffix(req.URL, "/health") || strings.HasSuffix(req.URL, "/metrics") || strings.HasSuffix(req.URL, "/favicon.ico") {
		return false
	}

	// Ensure URL is normalized if not already
	if req.NormalizedURL == "" && req.URL != "" {
		e.NormalizeRequest(req)
	}

	// 2. Refined Entropy Check
	// Increase threshold for URL entropy to reduce false positives for UUIDs/Hashes
	urlEntropy := e.CalculateEntropy(req.NormalizedURL)
	if urlEntropy > 6.5 {
		req.Score += 5
		req.MatchedRules = append(req.MatchedRules, "ANOMALY_HIGH_ENTROPY_URL")
	}

	// 3. Detect suspicious sequences (e.g. excessive non-printable chars)
	nonPrintable := 0
	for _, b := range req.Body {
		if b < 32 || b > 126 {
			nonPrintable++
		}
	}
	binaryRatio := 0.0
	if len(req.Body) > 0 {
		binaryRatio = float64(nonPrintable) / float64(len(req.Body))
	}

	if binaryRatio > 0.3 {
		req.Score += 10
		req.MatchedRules = append(req.MatchedRules, "ANOMALY_HIGH_BINARY_RATIO")
	}

	// 4. Isolation Forest Scoring (Actual ML)
	// Features: [URL Entropy, Body Entropy, Binary Ratio, Request Length]
	bodyEntropy := e.CalculateEntropy(req.NormalizedBody)
	features := []float64{urlEntropy, bodyEntropy, binaryRatio, float64(len(req.Body))}

	if len(e.forest.Trees) > 0 {
		mlScore := e.forest.Score(features)
		if mlScore > 0.8 { // High anomaly score
			req.Score += 20
			req.MatchedRules = append(req.MatchedRules, "ANOMALY_ISOLATION_FOREST")
		}
	}

	return req.Score > 10
}
