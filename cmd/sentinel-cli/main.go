package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	apiUrl := flag.String("api", "http://localhost:8081", "Control Plane API URL")
	action := flag.String("action", "list", "Action: list, add")
	flag.Parse()

	switch *action {
	case "list":
		listRules(*apiUrl)
	case "add":
		addRule(*apiUrl)
	default:
		fmt.Println("Unknown action")
		os.Exit(1)
	}
}

func listRules(url string) {
	resp, err := http.Get(url + "/api/rules")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}

func addRule(url string) {
	// Simple mock rule addition
	rule := map[string]interface{}{
		"RuleID": "CLI_RULE_1",
		"Name":   "CLI Generated Rule",
		"Action": "block",
		"Score":  50,
	}
	data, _ := json.Marshal(rule)
	resp, err := http.Post(url+"/api/rules", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Status: %s\n", resp.Status)
}
