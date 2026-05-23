package rules

import "github.com/sentinel-waf/sentinel-waf/pkg/model"

func GetDefaultRules() []model.Rule {
	return []model.Rule{
		{
			RuleID:      "942100",
			Name:        "SQL Injection Attack Detected via libinjection",
			Description: "Detects classic SQL injection attacks",
			Severity:    "Critical",
			Category:    "SQLI",
			Action:      "block",
			Score:       5,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(['\"]|--|#|/\\*|\\*/|union|select|insert|update|delete|drop|truncate|alter|create|rename|desc|into|load|outfile|dumpfile|outfile|concat|group_concat|hex|unhex|base64|decode|encode|md5|sha1|sha2|crypt|password|aes_encrypt|aes_decrypt|des_encrypt|des_decrypt|encrypt|decrypt|make_set|export_set|char|ascii|ord|lower|upper|lpad|rpad|repeat|reverse|space|substring|substr|mid|left|right|elt|field|find_in_set|locate|instr|position|hex|bin|oct|conv|format|unhex|base64|decode|encode|md5|sha1|sha2|crypt|password|aes_encrypt|aes_decrypt|des_encrypt|des_decrypt|encrypt|decrypt|make_set|export_set|char|ascii|ord|lower|upper|lpad|rpad|repeat|reverse|space|substring|substr|mid|left|right|elt|field|find_in_set|locate|instr|position|hex|bin|oct|conv|format|unhex|base64|decode|encode|md5|sha1|sha2|crypt|password|aes_encrypt|aes_decrypt|des_encrypt|des_decrypt|encrypt|decrypt|make_set|export_set|char|ascii|ord|lower|upper|lpad|rpad|repeat|reverse|space|substring|substr|mid|left|right|elt|field|find_in_set|locate|instr|position|hex|bin|oct|conv|format|unhex|base64|decode|encode|md5|sha1|sha2|crypt|password|aes_encrypt|aes_decrypt|des_encrypt|des_decrypt|encrypt|decrypt|make_set|export_set|char|ascii|ord|lower|upper|lpad|rpad|repeat|reverse|space|substring|substr|mid|left|right|elt|field|find_in_set|locate|instr|position|hex|bin|oct|conv|format)",
				},
			},
		},
		{
			RuleID:      "941100",
			Name:        "XSS Filter - Category 1",
			Description: "Detects common XSS script tags",
			Severity:    "Critical",
			Category:    "XSS",
			Action:      "block",
			Score:       5,
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
			Score:       5,
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
			Name:        "Remote Command Execution: Unix Shell Code",
			Description: "Detects common shell injection patterns",
			Severity:    "Critical",
			Category:    "RCE",
			Action:      "block",
			Score:       60, // Auto-triggers eBPF block
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(;|\\||\\x26|\\$\\(|\\x60|\\x3c|\\x3e|cat\\s+/etc/passwd|nc\\s+-e|/bin/sh|/bin/bash)",
				},
			},
		},
		{
			RuleID:      "933100",
			Name:        "PHP Injection Attack",
			Description: "Detects common PHP injection patterns",
			Severity:    "Critical",
			Category:    "PHP",
			Action:      "block",
			Score:       10,
			Conditions: []model.Condition{
				{
					Target:   "url",
					Operator: "regex",
					Value:    "(?i)(<\\?php|eval\\(|base64_decode\\(|gzinflate\\(|str_rot13\\()",
				},
			},
		},
	}
}
