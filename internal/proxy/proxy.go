package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
    "fmt"

	"github.com/google/uuid"
	"github.com/sentinel-waf/sentinel-waf/pkg/ebpf"
	"sync"

	"github.com/sentinel-waf/sentinel-waf/pkg/engine"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type Proxy struct {
	target       *url.URL
	proxy        *httputil.ReverseProxy
	engine       *engine.Engine
	controlPlane string
	xdp          *ebpf.XDPManager
	apiPolicies  []model.APISecurityPolicy
	mu           sync.RWMutex
    ratelimiter  *engine.RateLimiter
}

func NewProxy(targetURL string, e *engine.Engine, cpURL string, xdp *ebpf.XDPManager, rl *engine.RateLimiter) (*Proxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		target:       target,
		proxy:        httputil.NewSingleHostReverseProxy(target),
		engine:       e,
		controlPlane: cpURL,
		xdp:          xdp,
        ratelimiter:  rl,
	}

	return p, nil
}

const MaxBodySize = 10 * 1024 * 1024 // 10MB limit

var bodyPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Rate Limiting Check (M-07)
	if p.ratelimiter != nil {
		// Key by RemoteAddr for basic protection.
		// window/limit could be dynamic, hardcoded to 10/min for M-07 requirement.
		allowed, err := p.ratelimiter.IsAllowed(r.Context(), r.RemoteAddr, 10, time.Minute)
		if err != nil {
			// Log error but allow traffic (Fail Open logic from ADR-005/011)
			fmt.Printf("Rate limiter error: %v, failing open\n", err)
		} else if !allowed {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Rate limit exceeded"))
			return
		}
	}

	// 2. Capture request context with memory-efficient limit
	buf := bodyPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bodyPool.Put(buf)

	_, err := io.CopyN(buf, r.Body, int64(MaxBodySize))
	if err != nil && err != io.EOF {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body := make([]byte, buf.Len())
	copy(body, buf.Bytes())

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

	// 3. Inspect request
	_, blocked := p.engine.InspectRequest(context.Background(), reqCtx)

	// API Security Check - Using dynamic policies from control plane
	p.mu.RLock()
	policies := p.apiPolicies
	p.mu.RUnlock()
	apiBlocked := p.engine.InspectAPI(context.Background(), reqCtx, policies)

	// Real-time Anomaly Detection (Phase 2)
	isAnomaly := p.engine.DetectAnomaly(reqCtx)

	// 4. Report Stats
	go p.reportStats(p.controlPlane, blocked || apiBlocked, isAnomaly, apiBlocked, reqCtx)

	if blocked || apiBlocked {
		// Kernel-level mitigation: Block IP for subsequent requests if severity is high
		if reqCtx.Score > 50 && p.xdp != nil {
			p.xdp.BlockIP(reqCtx.RemoteAddr)
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Request blocked by Sentinel WAF"))
		return
	}

	// 5. Forward to target
	p.proxy.ServeHTTP(w, r)
}
