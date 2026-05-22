package engine

import (
	"strings"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type RuleSuggester struct{}

func (s *RuleSuggester) SuggestRule(req *model.RequestContext) *model.Rule {
	// Simple AI-like heuristic to suggest rules based on blocked patterns
	if strings.Contains(req.URL, "UNION") && strings.Contains(req.URL, "SELECT") {
		return &model.Rule{
			Name: "Auto-suggested SQLI rule",
			Description: "Derived from anomalous pattern detected in traffic",
			Score: 10,
			Action: "block",
			Conditions: []model.Condition{
				{Target: "url", Operator: "contains", Value: "UNION SELECT"},
			},
		}
	}
	return nil
}
