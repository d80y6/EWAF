package engine

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type Engine struct {
	rules  []model.Rule
	mu     sync.RWMutex
	regex  map[string]*regexp.Regexp
}

func NewEngine() *Engine {
	return &Engine{
		rules: make([]model.Rule, 0),
		regex: make(map[string]*regexp.Regexp),
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
	e.mu.RLock()
	defer e.mu.RUnlock()

	shouldBlock := false

	// ML Anomaly Detection
	if e.DetectAnomaly(req) {
		// DetectAnomaly updates score and matched rules
		if req.Score > 20 {
			shouldBlock = true
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
			req.MatchedRules = append(req.MatchedRules, rule.ID)
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
		targetValue = req.URL
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
