package rules

import "github.com/sentinel-waf/sentinel-waf/pkg/model"

func GetDefaultRules() []model.Rule {
	return []model.Rule{
		{
			RuleID:      "942100",
			Name:        "SQL Injection Attack: Common Keywords",
			Description: "Detects common SQL keywords used in injection attacks with word boundaries",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)\\b(?:UNION\\s+SELECT|INSERT\\s+INTO|UPDATE\\s+.*\\s+SET|DELETE\\s+FROM|DROP\\s+TABLE|TRUNCATE\\s+TABLE|ALTER\\s+TABLE|CREATE\\s+TABLE|RENAME\\s+TABLE|LOAD\\s+DATA|SELECT\\s+.*\\s+FROM)\\b",
				},
			},
		},
        {
			RuleID:      "942105",
			Name:        "SQL Injection Attack: Common Keywords (Body)",
			Description: "Detects common SQL keywords in request body",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "body",
					Operator: "regex",
					Value:    "(?i)\\b(?:UNION\\s+SELECT|INSERT\\s+INTO|UPDATE\\s+.*\\s+SET|DELETE\\s+FROM|DROP\\s+TABLE|TRUNCATE\\s+TABLE|ALTER\\s+TABLE|CREATE\\s+TABLE|RENAME\\s+TABLE|LOAD\\s+DATA|SELECT\\s+.*\\s+FROM)\\b",
				},
			},
		},
		{
			RuleID:      "942110",
			Name:        "SQL Injection Attack: Boolean/Logical Operators",
			Description: "Detects logical operators used for boolean-based SQLi",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(?:\\b(?:XOR|REGEXP|IS\\s+NULL|IS\\s+NOT\\s+NULL|TRUE|FALSE)\\b|'\\s*(?:OR|AND)\\s+['\"\\d]|\\d\\s*=\\s*\\d|'\\w+'\\s*=\\s*'\\w+')",
				},
			},
		},
		{
			RuleID:      "942120",
			Name:        "SQL Injection Attack: Blind SQLi / Time-based",
			Description: "Detects sleep and benchmark functions used for blind SQLi",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)\\b(?:SLEEP\\(|BENCHMARK\\(|WAITFOR\\s+DELAY|PG_SLEEP\\()",
				},
			},
		},
		{
			RuleID:      "942130",
			Name:        "SQL Injection Attack: Comment/Stacked Evasion",
			Description: "Detects SQL comments and stacked queries used for evasion",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(?:--\\s+|/\\*.*\\*/|;\\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|RENAME))",
				},
			},
		},
		{
			RuleID:      "942140",
			Name:        "SQL Injection Attack: Database Specific Functions",
			Description: "Detects DBMS specific functions (MySQL, Postgres, etc.)",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)\\b(?:DATABASE\\(\\)|VERSION\\(\\)|SESSION_USER\\(\\)|SYSTEM_USER\\(\\)|CURRENT_USER\\(\\)|LOAD_FILE\\()",
				},
			},
		},
		{
			RuleID:      "941100",
			Name:        "XSS Filter",
			Description: "Detects common XSS script tags",
			Severity:    "Critical",
			Category:    "XSS",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(<script|alert\\(|onerror=|onload=|javascript:)",
				},
			},
		},
		{
			RuleID:      "930100",
			Name:        "Path Traversal Attack",
			Description: "Detects path traversal attacks",
			Severity:    "High",
			Category:    "LFI",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(\\.\\./|\\.\\.\\\\|/etc/passwd|/windows/win.ini|/etc/shadow)",
				},
			},
		},
		{
			RuleID:      "932100",
			Name:        "Remote Command Execution",
			Description: "Detects common shell injection patterns",
			Severity:    "Critical",
			Category:    "RCE",
			Action:      "block",
			Score:       60,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(?:\\|\\x26|\\$\\(|\\x60|\\x3c|\\x3e|\\b(?:netcat|nc|bash|php|perl|python|ruby|socat|tftp|ftp|ssh)\\b)",
				},
			},
		},
	}
}
