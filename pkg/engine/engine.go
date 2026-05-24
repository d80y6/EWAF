package engine

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type Engine struct {
	rules       []model.Rule
	tenantRules map[uint][]model.Rule
	mu          sync.RWMutex
	regex       map[string]*regexp.Regexp
	threatIntel *ThreatIntel
	graphql     *GraphQLAnalyzer
	forest      *IsolationForest
}

func NewEngine() *Engine {
	return &Engine{
		rules:       make([]model.Rule, 0),
		tenantRules: make(map[uint][]model.Rule),
		regex:       make(map[string]*regexp.Regexp),
		threatIntel: NewThreatIntel(),
		graphql:     &GraphQLAnalyzer{MaxDepth: 10, MaxComplexity: 100},
		forest:      &IsolationForest{Trees: make([]*Tree, 0)},
	}
}

func (e *Engine) LoadRules(rules []model.Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	newRegex := make(map[string]*regexp.Regexp)
	for _, rule := range rules {
		for _, cond := range rule.Conditions {
			if cond.Operator == "regex" {
				re, err := regexp.Compile(cond.Value)
				if err != nil {
					return err
				}
				newRegex[cond.Value] = re
			}
		}
	}

	e.rules = rules
	e.regex = newRegex
	return nil
}

func (e *Engine) InspectRequest(ctx context.Context, req *model.RequestContext) (*model.RequestContext, bool) {
	// 1. Global Allow-list for system paths
	if strings.HasSuffix(req.URL, "/health") || strings.HasSuffix(req.URL, "/metrics") || strings.HasSuffix(req.URL, "/favicon.ico") {
		return req, false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	e.NormalizeRequest(req)
	e.ParseBody(req)

	shouldBlock := false

	// Threat Intelligence Check
	if e.threatIntel.IsMalicious(req.RemoteAddr) {
		req.Score += 100
		req.MatchedRules = append(req.MatchedRules, "THREAT_INTEL_MALICIOUS_IP")
		return req, true
	}

	// ML Anomaly Detection
	if e.DetectAnomaly(req) {
		// DetectAnomaly updates score and matched rules
		if req.Score > 20 {
			shouldBlock = true
		}
	}

	// GraphQL Analysis
	if strings.Contains(req.Headers.Get("Content-Type"), "application/json") &&
	   (strings.Contains(req.NormalizedBody, "query") || strings.Contains(req.NormalizedBody, "mutation")) {
		depth, complexity, err := e.graphql.Analyze(req.NormalizedBody)
		if err == nil {
			if depth > e.graphql.MaxDepth || complexity > e.graphql.MaxComplexity {
				req.Score += 30
				req.MatchedRules = append(req.MatchedRules, "GRAPHQL_LIMIT_EXCEEDED")
				shouldBlock = true
			}
		}
	}

	for _, rule := range e.rules {
		matched := true
		for _, cond := range rule.Conditions {
			if !e.evaluateCondition(cond, req) {
				matched = false
				break
			}
		}

		if matched {
			req.Score += rule.Score
			req.MatchedRules = append(req.MatchedRules, rule.RuleID)
			if rule.Action == "block" {
				shouldBlock = true
			}
		}
	}

	return req, shouldBlock
}

func (e *Engine) evaluateCondition(cond model.Condition, req *model.RequestContext) bool {
	var targetValue string
	switch cond.Target {
	case "url":
		targetValue = req.NormalizedURL
	case "method":
		targetValue = req.Method
	case "body":
		if req.NormalizedBody == "" && len(req.Body) > 0 {
			req.NormalizedBody = string(req.Body)
		}
		targetValue = req.NormalizedBody
	case "headers":
		targetValue = req.Headers.Get(cond.Key)
	case "ip":
		targetValue = req.RemoteAddr
	}

	result := false
	switch cond.Operator {
	case "regex":
		re := e.regex[cond.Value]
		if re != nil {
			result = re.MatchString(targetValue)
		}
	case "contains":
		result = strings.Contains(targetValue, cond.Value)
	case "eq":
		result = targetValue == cond.Value
	}

	if cond.Negate {
		return !result
	}
	return result
}
