package engine

import (
	"encoding/json"
	"encoding/xml"
	"strings"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) NormalizeRequest(req *model.RequestContext) {
	// Unicode normalization (simplified)
	req.NormalizedURL = strings.ToLower(req.URL)

	// Path normalization
	req.NormalizedURL = strings.ReplaceAll(req.NormalizedURL, "//", "/")
}

func (e *Engine) ParseBody(req *model.RequestContext) {
	contentType := req.Headers.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		var data interface{}
		if err := json.Unmarshal(req.Body, &data); err == nil {
			cleaned, _ := json.Marshal(data)
			req.NormalizedBody = string(cleaned)
		}
	} else if strings.Contains(contentType, "application/xml") {
		var data interface{}
		if err := xml.Unmarshal(req.Body, &data); err == nil {
			cleaned, _ := xml.Marshal(data)
			req.NormalizedBody = string(cleaned)
		}
	}
}
