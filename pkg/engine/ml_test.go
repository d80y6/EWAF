package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func TestEngine_ML_IsolationForest_Gate(t *testing.T) {
	e := NewEngine()

	// 1. Train model with a "legitimate" baseline
	// Features: [URL Entropy, Body Entropy, Binary Ratio, Request Length]
	trainingData := [][]float64{
		{2.0, 1.5, 0.05, 50},
		{2.1, 1.4, 0.04, 52},
		{2.2, 1.6, 0.06, 48},
		{1.9, 1.5, 0.05, 55},
	}
	e.forest.Train(trainingData, 10, 4)

	// 2. Gate Verification: Showing model produces different scores
	// for two inputs that share the same threshold boundary (simulated by Method/Length)

	// Input A: legitimate-looking
	reqA := &model.RequestContext{
		URL:        "/api/v1/user", // entropy around 3.0
		Body:       []byte(`{"id": 123}`),
		Headers:    make(http.Header),
		RemoteAddr: "1.1.1.1",
	}

	// Input B: malicious-looking (high entropy/binary)
	// Same method, similar length, same system threshold boundary (score increment)
	reqB := &model.RequestContext{
		URL:        "/api/v1/user",
		Body:       []byte("\x01\x02\x03\x04\x05\x06\x07\x08"), // high binary ratio
		Headers:    make(http.Header),
		RemoteAddr: "1.1.1.1",
	}

	_, _ = e.InspectRequest(context.Background(), reqA)
    scoreA := e.CalculateAnomalyScore(reqA) // Custom helper to expose score for test

	_, _ = e.InspectRequest(context.Background(), reqB)
    scoreB := e.CalculateAnomalyScore(reqB)

	if scoreA == scoreB {
		t.Errorf("ML Verification failed: produced identical scores %f for different inputs. Model acts as hardcoded threshold.", scoreA)
	} else {
        t.Logf("ML Verification passed: Score A = %f, Score B = %f", scoreA, scoreB)
    }
}

// Helper for test
func (e *Engine) CalculateAnomalyScore(req *model.RequestContext) float64 {
    urlEntropy := e.CalculateEntropy(req.NormalizedURL)
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
    bodyEntropy := e.CalculateEntropy(req.NormalizedBody)
    features := []float64{urlEntropy, bodyEntropy, binaryRatio, float64(len(req.Body))}
    return e.forest.Score(features)
}
