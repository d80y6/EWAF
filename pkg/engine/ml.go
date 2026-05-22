package engine

import (
	"math"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	frequencies := make(map[rune]float64)
	for _, char := range data {
		frequencies[char]++
	}

	var entropy float64
	length := float64(len(data))
	for _, freq := range frequencies {
		p := freq / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func (e *Engine) DetectAnomaly(req *model.RequestContext) bool {
	// High entropy in URL or body often indicates encoded payloads or random probes
	urlEntropy := e.CalculateEntropy(req.URL)
	if urlEntropy > 5.0 {
		req.Score += 5
		req.MatchedRules = append(req.MatchedRules, "ANOMALY_HIGH_ENTROPY_URL")
	}

	// Detect suspicious sequences (e.g. excessive non-printable chars)
	nonPrintable := 0
	for _, b := range req.Body {
		if b < 32 || b > 126 {
			nonPrintable++
		}
	}
	if len(req.Body) > 0 && float64(nonPrintable)/float64(len(req.Body)) > 0.3 {
		req.Score += 10
		req.MatchedRules = append(req.MatchedRules, "ANOMALY_HIGH_BINARY_RATIO")
	}

	return req.Score > 10
}
