package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel-waf/sentinel-waf/pkg/engine"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type Proxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
	engine *engine.Engine
}

func NewProxy(targetURL string, e *engine.Engine) (*Proxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		target: target,
		proxy:  httputil.NewSingleHostReverseProxy(target),
		engine: e,
	}

	return p, nil
}

const MaxBodySize = 10 * 1024 * 1024 // 10MB limit

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Capture request context
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	reqCtx := &model.RequestContext{
		ID:         uuid.New().String(),
		Method:     r.Method,
		URL:        r.URL.String(),
		Host:       r.Host,
		RemoteAddr: r.RemoteAddr,
		Headers:    r.Header.Clone(),
		Body:       body,
		StartTime:  time.Now(),
	}

	// 2. Inspect request
	_, blocked := p.engine.InspectRequest(context.Background(), reqCtx)

	// API Security Check (example policy)
	apiBlocked := p.engine.InspectAPI(context.Background(), reqCtx, []model.APISecurityPolicy{
		{
			PathPrefix:    "/api/secure",
			JWTVaildation: true,
			JWTSecret:     "super-secret",
		},
	})

	// API Security Violation detection for stats
	apiViolation := apiBlocked

	// 3. Report Stats
	cpURL := "http://localhost:8081" // Should be configurable
	go p.reportStats(cpURL, blocked || apiBlocked, reqCtx.Score > 10, apiViolation)

	if blocked || apiBlocked {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Request blocked by Sentinel WAF"))
		return
	}

	// 3. Forward to target
	p.proxy.ServeHTTP(w, r)
}
