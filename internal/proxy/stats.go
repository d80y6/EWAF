package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)


func (p *Proxy) reportStats(url string, blocked, anomaly, apiViolation bool, reqCtx *model.RequestContext) {
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
	body, _ := json.Marshal(data)
	http.Post(url+"/api/stats/report", "application/json", bytes.NewBuffer(body))
}
