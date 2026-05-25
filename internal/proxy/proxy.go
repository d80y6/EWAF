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
}

func NewProxy(targetURL string, e *engine.Engine, cpURL string, xdp *ebpf.XDPManager) (*Proxy, error) {
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
	// 1. Capture request context with memory-efficient limit
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

	// 2. Inspect request
	_, blocked := p.engine.InspectRequest(context.Background(), reqCtx)

	// API Security Check - Using dynamic policies from control plane
	p.mu.RLock()
	policies := p.apiPolicies
	p.mu.RUnlock()
	apiBlocked := p.engine.InspectAPI(context.Background(), reqCtx, policies)

	// Real-time Anomaly Detection (Phase 2)
	isAnomaly := p.engine.DetectAnomaly(reqCtx)

	// 3. Report Stats
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

	// 4. Forward to target
	p.proxy.ServeHTTP(w, r)
}
