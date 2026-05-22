package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
)


func (p *Proxy) reportStats(url string, blocked, anomaly, apiViolation bool) {
	data := map[string]bool{
		"blocked":      blocked,
		"anomaly":      anomaly,
		"apiViolation": apiViolation,
	}
	body, _ := json.Marshal(data)
	http.Post(url+"/api/stats/report", "application/json", bytes.NewBuffer(body))
}
