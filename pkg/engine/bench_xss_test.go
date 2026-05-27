package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func BenchmarkEngine_InspectRequest_XSS(b *testing.B) {
	e := NewEngine()
	e.LoadRules(rules.GetDefaultRules())

	req := &model.RequestContext{
		URL:     "/search?q=<script>alert('xss')</script>",
		Method:  "GET",
		Headers: make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.InspectRequest(context.Background(), req)
	}
}
