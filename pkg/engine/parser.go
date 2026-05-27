package engine

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"strings"
	"regexp"
    "io"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
	"golang.org/x/text/unicode/norm"
)

var (
	// regex for collapsing multiple slashes
	slashCollapseRegex = regexp.MustCompile(`//+`)
)

func (e *Engine) NormalizeRequest(req *model.RequestContext) {
	// 1. Multi-pass URL decoding to prevent double-encoding bypasses
	current := req.URL
	for i := 0; i < 3; i++ {
		decoded, err := url.QueryUnescape(current)
		if err != nil || decoded == current {
			break
		}
		current = decoded
	}

	// 2. Unicode normalization (NFKC) and simplified to lowercase
	normalized := norm.NFKC.String(current)
	normalized = strings.ToLower(normalized)

	// 3. Null byte removal
	normalized = strings.ReplaceAll(normalized, "\x00", "")

	// 4. Path normalization: collapse multiple slashes
	normalized = slashCollapseRegex.ReplaceAllString(normalized, "/")

	// 5. Handle directory traversal shorthand
	normalized = strings.ReplaceAll(normalized, "/./", "/")

	// 6. SQL specific normalization: collapse whitespace
	normalized = strings.Join(strings.Fields(normalized), " ")

	req.NormalizedURL = normalized
}

func (e *Engine) ParseBody(req *model.RequestContext) {
	contentType := req.Headers.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		var data interface{}
		if err := json.Unmarshal(req.Body, &data); err == nil {
			req.NormalizedBody = e.flattenJSON(data)
		}
	} else if strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml") {
		req.NormalizedBody = e.flattenXML(req.Body)
	} else {
		req.NormalizedBody = strings.ToLower(string(req.Body))
	}
}

func (e *Engine) flattenJSON(data interface{}) string {
	switch v := data.(type) {
	case string:
		return strings.ToLower(v)
	case map[string]interface{}:
		var sb strings.Builder
		for _, val := range v {
			sb.WriteString(e.flattenJSON(val))
			sb.WriteString(" ")
		}
		return sb.String()
	case []interface{}:
		var sb strings.Builder
		for _, val := range v {
			sb.WriteString(e.flattenJSON(val))
			sb.WriteString(" ")
		}
		return sb.String()
	default:
		return ""
	}
}

func (e *Engine) flattenXML(data []byte) string {
	var sb strings.Builder
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return strings.ToLower(string(data)) // Fallback to raw string
		}

		switch t := token.(type) {
		case xml.CharData:
			sb.WriteString(string(t))
			sb.WriteString(" ")
		case xml.StartElement:
			for _, attr := range t.Attr {
				sb.WriteString(attr.Value)
				sb.WriteString(" ")
			}
		}
	}
	return strings.ToLower(sb.String())
}
