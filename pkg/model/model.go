package model

import (
	"net/http"
	"time"
)

type RequestContext struct {
	ID             string
	Method         string
	URL            string
	Host           string
	RemoteAddr     string
	Headers        http.Header
	Body           []byte
	StartTime      time.Time
	NormalizedURL  string
	NormalizedBody string
	Score          int
	Tags           []string
	MatchedRules   []string
}

type Transaction struct {
	Request  *RequestContext
	Response *ResponseContext
}

type ResponseContext struct {
	Status  int
	Headers http.Header
	Body    []byte
}

type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Category    string
	Conditions  []Condition
	Action      string // block, allow, monitor
	Score       int
}

type Condition struct {
	Operator string // regex, contains, eq, gt, lt
	Target   string // url, body, headers, method, ip
	Key      string // if target is headers, this is the header name
	Value    string // the value to compare against
	Negate   bool
}

type APISecurityPolicy struct {
	ID                string
	PathPrefix        string
	JWTVaildation     bool
	JWTSecret         string
	OpenAPIEnforcement bool
	OpenAPISpec       string // URL or raw spec
}

type Tenant struct {
	ID        string
	Name      string
	APIKey    string
	Policies  []Rule
	IsActive  bool
}
