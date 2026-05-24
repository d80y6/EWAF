package engine

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"strings"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) NormalizeRequest(req *model.RequestContext) {
	// 1. URL decoding to prevent %xx encoding bypasses
	decoded, err := url.QueryUnescape(req.URL)
	if err != nil {
		// Fallback to raw URL if it's malformed
		decoded = req.URL
	}

	// 2. Unicode normalization (simplified to lowercase)
	req.NormalizedURL = strings.ToLower(decoded)

	// 3. Path normalization: collapse multiple slashes recursively
	for strings.Contains(req.NormalizedURL, "//") {
		req.NormalizedURL = strings.ReplaceAll(req.NormalizedURL, "//", "/")
	}

	// 4. Handle directory traversal shorthand
	req.NormalizedURL = strings.ReplaceAll(req.NormalizedURL, "/./", "/")
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
