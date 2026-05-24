# Hotpath Profile Report - Sentinel WAF

## Identified Hotpaths

### 1. Regex Evaluation
The `regexp.MatchString` call in `evaluateCondition` is the most expensive operation.
```go
re := e.regex[cond.Value]
if re != nil {
    result = re.MatchString(targetValue)
}
```

### 2. Request Body Reading
`io.ReadAll` is a blocking and memory-intensive operation.
```go
body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
```

### 3. Stat Marshaling
Every request triggers a `json.Marshal` call in a background goroutine. While backgrounded, it still consumes CPU and creates GC pressure.
```go
body, _ := json.Marshal(data)
```
