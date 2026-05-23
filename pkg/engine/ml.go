package engine

import (
	"math"
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
	// Ensure URL is normalized if not already
	if req.NormalizedURL == "" && req.URL != "" {
		e.NormalizeRequest(req)
	}

	// High entropy in URL or body often indicates encoded payloads or random probes
	urlEntropy := e.CalculateEntropy(req.NormalizedURL)
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
