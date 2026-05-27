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
			RuleID:      "942107",
			Name:        "SQL Injection Attack: Common Keywords (Headers/Cookies)",
			Description: "Detects common SQL keywords in headers or cookies",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "headers",
					Operator: "regex",
					Value:    "(?i)(?:UNION\\s+SELECT|INSERT\\s+INTO|UPDATE\\s+.*\\s+SET|DELETE\\s+FROM|DROP\\s+TABLE|SELECT\\s+.*\\s+FROM|'\\s*OR\\s+'|\\d\\s*=\\s*\\d)",
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
			Name:        "XSS Filter: Script Tags",
			Description: "Detects common XSS script tags",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(?:\\b(?:XOR|REGEXP|IS\\s+NULL|IS\\s+NOT\\s+NULL|TRUE|FALSE)\\b|'\\s*(?:OR|AND)\\s+['\"\\d]|\\d\\s*=\\s*\\d|'\\w+'\\s*=\\s*'\\w+')",
				},
			},
		},
        {
			RuleID:      "941110",
			Name:        "XSS Filter: HTML Attributes and Protocols",
			Description: "Detects XSS in HTML attributes and pseudo-protocols",
			Severity:    "Critical",
			Category:    "XSS",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(?:href|src|data|formaction|background|on(?:click|load|error|mouseover|submit))\\s*=\\s*['\"]?(?:javascript|data|vbscript):",
				},
			},
		},
        {
			RuleID:      "941120",
			Name:        "XSS Filter: SVG and Event Handlers",
			Description: "Detects XSS via SVG tags and DOM event handlers",
			Severity:    "Critical",
			Category:    "XSS",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)<(?:svg|details|iframe|object|embed|animate|set).*on(?:begin|end|repeat|load|click|error|focus)\\b",
				},
			},
		},
		{
			RuleID:      "930100",
			Name:        "Path Traversal Attack",
			Description: "Detects path traversal and LFI attempts",
			Severity:    "High",
			Category:    "LFI",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(?:\\.\\./|\\.\\.\\\\|/etc/passwd|/etc/shadow|/etc/group|/etc/hosts|/windows/win\\.ini|/boot/grub/grub\\.cfg|/\\.ssh/id_rsa|/\\.aws/credentials|win\\.ini)",
				},
			},
		},
		{
			RuleID:      "932100",
			Name:        "Remote Command Execution: OS Command",
			Description: "Detects common OS commands execution attempts",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       60,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)\\b(?:cat|ls|id|whoami|uname|netcat|nc|bash|sh|php|perl|python|ruby|socat|tftp|ftp|ssh|wget|curl|ping|telnet)\\b",
				},
			},
		},
        {
			RuleID:      "932110",
			Name:        "Remote Command Execution: Shell Metacharacters",
			Description: "Detects shell metacharacters used for command injection",
			Severity:    "Critical",
			Category:    "RCE",
			Action:      "block",
			Score:       60,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?:\\|\\x26|\\$\\(|\\x60|\\x3c|\\x3e|\\\\$|\\x7b|\\x7d)",
				},
			},
		},
        {
			RuleID:      "933100",
			Name:        "PHP Injection Attack",
			Description: "Detects common PHP injection patterns",
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
					Value:    "(?i)(?:<\\?php|eval\\s*\\(|base64_decode\\s*\\(|gzinflate\\s*\\(|str_rot13\\s*\\(|assert\\s*\\(|passthru\\s*\\(|system\\s*\\()",
				},
			},
		},
	}
}
