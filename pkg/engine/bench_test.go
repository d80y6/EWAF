package engine

import (
	"context"
	"net/http"
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"github.com/sentinel-waf/sentinel-waf/pkg/rules"
)

func BenchmarkEngine_InspectRequest_SQLi(b *testing.B) {
	e := NewEngine()
	e.LoadRules(rules.GetDefaultRules())

	req := &model.RequestContext{
		URL:     "/search?q=1' union select 1,2,3,4--",
		Method:  "GET",
		Headers: make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.InspectRequest(context.Background(), req)
	}
}

func BenchmarkEngine_InspectRequest_Safe(b *testing.B) {
	e := NewEngine()
	e.LoadRules(rules.GetDefaultRules())

	req := &model.RequestContext{
		URL:     "/api/v1/users/123/profile?expand=settings&lang=en-US",
		Method:  "GET",
		Headers: make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.InspectRequest(context.Background(), req)
	}
}
