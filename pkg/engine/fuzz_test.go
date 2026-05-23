package engine

import (
	"testing"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func FuzzParseBody(f *testing.F) {
	e := NewEngine()
	f.Add([]byte(`{"test": "data"}`))
	f.Add([]byte(`<xml><test>data</test></xml>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req := &model.RequestContext{
			Body:    data,
			Headers: make(map[string][]string),
		}
		req.Headers.Set("Content-Type", "application/json")
		e.ParseBody(req)

		req.Headers.Set("Content-Type", "application/xml")
		e.ParseBody(req)
	})
}
