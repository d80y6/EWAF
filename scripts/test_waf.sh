#!/bin/bash
TARGET="http://localhost:80"

echo "Running SQL Injection Test..."
curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/api/users?id=1' OR '1'='1"

echo "Running XSS Test..."
curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/search?q=<script>alert(1)</script>"

echo "Running RCE Test..."
curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/cmd?exec=cat+/etc/passwd"

echo "Running API Security Test (Unauthorized JWT)..."
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer invalid-token" "$TARGET/api/secure/data"
