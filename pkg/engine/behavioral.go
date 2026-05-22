package engine

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) GenerateFingerprint(req *model.RequestContext) string {
	// Simple fingerprint based on headers and IP
	var headers []string
	for k := range req.Headers {
		headers = append(headers, k)
	}
	sort.Strings(headers)

	raw := fmt.Sprintf("%s|%s|%s", req.RemoteAddr, req.Headers.Get("User-Agent"), strings.Join(headers, ","))
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}

type BehavioralProfile struct {
	Fingerprint string
	RequestCount int
	LastSeen     int64
	Score        float64
}
