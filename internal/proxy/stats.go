package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

var (
	statsQueue []map[string]interface{}
	statsMu    sync.Mutex
	cpURL      string
	cpOnce     sync.Once
)

func startFlusher(url string) {
	cpOnce.Do(func() {
		cpURL = url
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			for range ticker.C {
				flushStats()
			}
		}()
	})
}

func flushStats() {
	statsMu.Lock()
	if len(statsQueue) == 0 {
		statsMu.Unlock()
		return
	}
	batch := statsQueue
	statsQueue = nil
	statsMu.Unlock()

	for _, s := range batch {
		body, _ := json.Marshal(s)
		http.Post(cpURL+"/api/stats/report", "application/json", bytes.NewBuffer(body))
	}
}

func (p *Proxy) reportStats(url string, blocked, anomaly, apiViolation bool, reqCtx *model.RequestContext) {
	startFlusher(url)
	data := map[string]interface{}{
		"blocked":       blocked,
		"anomaly":       anomaly,
		"apiViolation":  apiViolation,
		"requestID":     reqCtx.ID,
		"remoteAddr":    reqCtx.RemoteAddr,
		"method":        reqCtx.Method,
		"url":           reqCtx.URL,
		"score":         reqCtx.Score,
		"matchedRules":  reqCtx.MatchedRules,
	}

	// Use batching for high volume events
	if !blocked && !anomaly && !apiViolation {
		// Only batch "all-clear" stats to reduce load
		statsMu.Lock()
		statsQueue = append(statsQueue, data)
		statsMu.Unlock()
		return
	}

	// Important events are still reported immediately
	body, _ := json.Marshal(data)
	http.Post(url+"/api/stats/report", "application/json", bytes.NewBuffer(body))
}
