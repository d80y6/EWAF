package engine

import (
	"strings"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type RuleSuggester struct{}

func (s *RuleSuggester) SuggestRule(req *model.RequestContext) *model.Rule {
	// AI-Heuristic: Analyze multiple signals to suggest a more specific rule
	// This simulates a more complex pattern matching logic
	urlLower := strings.ToLower(req.URL)
	if strings.Contains(urlLower, "union") && strings.Contains(urlLower, "select") {
		// Detect if it's attempting to bypass via comment or space encodings
		if strings.Contains(urlLower, "/**/") || strings.Contains(urlLower, "%20") {
			return &model.Rule{
				Name: "AI-Suggested SQLI Bypass Rule",
				Description: "Detected potential SQLI bypass attempt using comments or encoding",
				Score: 15,
				Action: "block",
				Conditions: []model.Condition{
					{Target: "url", Operator: "regex", Value: "(?i)union.*select"},
				},
			}
		}

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

	// Command Injection Heuristic
	if strings.Contains(urlLower, "cat") && strings.Contains(urlLower, "passwd") {
		return &model.Rule{
			Name: "AI-Suggested RCE Rule",
			Description: "Detected attempt to access sensitive system files",
			Score: 50,
			Action: "block",
			Conditions: []model.Condition{
				{Target: "url", Operator: "regex", Value: "(?i)cat.*/etc/passwd"},
			},
		}
	}

	return nil
}
