---
name: wstg-errh-02
description: "Testing for Stack Traces"
category: error-handling
owasp_id: WSTG-ERRH-02
version: "1.0.0"
author: cyberstrike-official
tags: [error-handling, information-leak, stack-trace, wstg, errh]
tech_stack: []
cwe_ids: [CWE-209]
chains_with: [wstg-errh-01, wstg-info-01]
prerequisites: [wstg-info-01, wstg-info-02]
severity_boost:
  wstg-errh-01: "Stack trace/debug-mode exposure combined with verbose DB/SQL error disclosure gives an attacker the exact file paths, line numbers, and query structure needed to craft precise SQLi or deserialization exploits instead of blind guessing (High)"
---

# wstg-errh-02

## Test ID

WSTG-ERRH-02

## Test Name

Testing for Stack Traces

## High-Level Description

Stack traces provide detailed information about application internals including function call sequences, file paths, line numbers, and sometimes variable values. When exposed to users, stack traces can reveal sensitive implementation details that help attackers understand the application architecture and identify potential vulnerabilities.

---

## What to Check

- [ ] Stack traces in error responses
- [ ] Debug mode enabled
- [ ] Exception details exposed
- [ ] Framework-specific error pages
- [ ] API error responses
- [ ] JavaScript console errors

---

## How to Test

### Step 1: Trigger Application Errors

```bash
#!/bin/bash
TARGET="https://target.com"

# Force exceptions with various inputs
payloads=(
    # Division/null errors
    "0"
    "null"
    "undefined"
    "NaN"

    # Type errors
    "[]"
    "{}"
    "true"

    # SQL errors
    "'"
    "1'"
    "1 OR 1=1"

    # Path errors
    "../../etc/passwd"
    "/etc/passwd"

    # Format string
    "%s%s%s%s%s"
    "%n%n%n%n%n"

    # Buffer overflow attempt
    "$(python3 -c 'print(\"A\"*10000)')"
)

for payload in "${payloads[@]}"; do
    echo "=== Payload: $payload ==="
    response=$(curl -s "$TARGET/api/process?input=$payload")

    # Check for stack trace indicators
    if echo "$response" | grep -qiE "at\s+\w+\.|Traceback|Exception|Error at line|Stack trace"; then
        echo "[VULN] Stack trace detected!"
        echo "$response" | head -20
    fi
    echo ""
done
```

### Step 2: Check for Debug Mode

```bash
#!/bin/bash
TARGET="https://target.com"

# Look for debug indicators
response=$(curl -s "$TARGET/nonexistent")

# Django debug page
if echo "$response" | grep -q "Using the URLconf defined in"; then
    echo "[VULN] Django DEBUG=True detected"
fi

# Flask debug mode
if echo "$response" | grep -q "Werkzeug Debugger"; then
    echo "[VULN] Flask debug mode detected"
fi

# ASP.NET detailed errors
if echo "$response" | grep -q "Stack Trace:"; then
    echo "[VULN] ASP.NET detailed errors enabled"
fi

# PHP errors
if echo "$response" | grep -qiE "Fatal error:|Parse error:|Warning:.*on line"; then
    echo "[VULN] PHP errors displayed"
fi

# Express.js errors
if echo "$response" | grep -q "at Layer.handle"; then
    echo "[VULN] Express.js stack trace exposed"
fi
```

### Step 3: Stack Trace Analyzer

```python
#!/usr/bin/env python3
import requests
import re

class StackTraceTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    STACK_TRACE_PATTERNS = {
        'java': r'at\s+[\w.]+\([\w.]+:\d+\)',
        'python': r'File\s+"[^"]+",\s+line\s+\d+',
        'dotnet': r'at\s+[\w.]+\s+in\s+[^:]+:\d+',
        'php': r'in\s+/[\w/]+\.php\s+on\s+line\s+\d+',
        'nodejs': r'at\s+[\w.]+\s+\([^)]+:\d+:\d+\)',
        'ruby': r'from\s+[\w/]+\.rb:\d+',
    }

    FRAMEWORK_PATTERNS = {
        'django': r'Using the URLconf defined in|Django Version:',
        'flask': r'Werkzeug Debugger|werkzeug\.exceptions',
        'rails': r'ActionController::RoutingError|Rails\.root:',
        'spring': r'org\.springframework\.|Whitelabel Error Page',
        'express': r'at Layer\.handle|at Route\.dispatch',
        'laravel': r'Illuminate\\|app/Exceptions/Handler',
    }

    def test_endpoints(self, endpoints):
        """Test multiple endpoints for stack traces"""
        print("[*] Testing for stack trace exposure...")

        for endpoint in endpoints:
            self._test_endpoint(endpoint)

        return self.findings

    def _test_endpoint(self, endpoint):
        """Test single endpoint"""
        # Error-triggering payloads
        payloads = ["'", "null", "0", "{{7*7}}", "../"]

        for payload in payloads:
            try:
                url = f"{self.base_url}{endpoint}?id={payload}"
                response = requests.get(url, timeout=10)
                self._analyze_response(url, response.text)

            except requests.exceptions.RequestException:
                pass

    def _analyze_response(self, url, content):
        """Analyze response for stack traces"""
        # Check for stack traces
        for lang, pattern in self.STACK_TRACE_PATTERNS.items():
            if re.search(pattern, content):
                print(f"[VULN] {lang.upper()} stack trace at: {url}")
                self.findings.append({
                    "url": url,
                    "type": f"{lang}_stack_trace",
                    "severity": "Medium"
                })

        # Check for framework debug pages
        for framework, pattern in self.FRAMEWORK_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                print(f"[VULN] {framework.upper()} debug mode at: {url}")
                self.findings.append({
                    "url": url,
                    "type": f"{framework}_debug",
                    "severity": "High"
                })

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*50)
        print("STACK TRACE EXPOSURE REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo stack traces found.")
            return

        print(f"\nFindings: {len(self.findings)}")
        for f in self.findings:
            print(f"\n  [{f['severity']}] {f['type']}")
            print(f"  URL: {f['url']}")

# Usage
tester = StackTraceTester("https://target.com")
tester.test_endpoints(["/api/user", "/api/search", "/api/product"])
tester.generate_report()
```

---

## Tools

| Tool           | Description                              | Usage                                   |
| -------------- | ----------------------------------------- | ---------------------------------------- |
| **curl**       | Manual error-triggering requests          | `curl -s target.com/api?id='`            |
| **Burp Suite** | Intercept/repeat requests, view raw errors| Repeater on error-prone params           |
| **OWASP ZAP**  | Automated active scan for exceptions      | Active Scan -> Information Disclosure    |
| **grep/ripgrep**| Pattern-match stack traces in responses  | `grep -E "at .+\(.+:[0-9]+\)"`           |

---

## Example Commands/Payloads

```bash
TARGET="https://target.com"

# Fire error-triggering inputs and capture full response for inspection
for payload in "0" "null" "undefined" "[]" "{}" "'" "1 OR 1=1" "../../etc/passwd" "%s%s%s%s"; do
  echo "=== payload: $payload ==="
  curl -s "$TARGET/api/process?input=$payload" -o /tmp/errh2_resp.html -w "status=%{http_code}\n"
  grep -qiE "traceback|at\s+[a-z0-9_.]+\(.+:[0-9]+\)|stack trace" /tmp/errh2_resp.html && echo "[VULN] stack trace present"
done

# Detect framework debug pages directly
curl -s "$TARGET/nonexistent-path-xyz" | grep -q "Using the URLconf defined in" && echo "[VULN] Django DEBUG=True"
curl -s "$TARGET/nonexistent-path-xyz" | grep -q "Werkzeug Debugger" && echo "[VULN] Flask/Werkzeug debug mode"
curl -s "$TARGET/nonexistent-path-xyz" | grep -q "Stack Trace:" && echo "[VULN] ASP.NET detailed errors"
curl -s "$TARGET/nonexistent-path-xyz" | grep -qiE "Fatal error:|Parse error:" && echo "[VULN] PHP errors displayed"

# Language-specific stack trace regex sweep (run against saved response body)
grep -E 'at\s+[\w.]+\([\w.]+:[0-9]+\)' /tmp/errh2_resp.html          # Java/Node
grep -E 'File\s+"[^"]+",\s+line\s+[0-9]+' /tmp/errh2_resp.html       # Python
grep -E 'in\s+/[\w/]+\.php\s+on\s+line\s+[0-9]+' /tmp/errh2_resp.html # PHP
grep -E 'from\s+[\w/]+\.rb:[0-9]+' /tmp/errh2_resp.html               # Ruby
```

**Result patterns indicating a finding:**
- Response contains `Traceback (most recent call last)`, `File "...", line N` → Python stack trace
- Response contains `at <package.Class>.<method>(<File>:<line>)` → Java/Node stack trace
- Response contains `in /path/file.php on line N`, `Fatal error:`, `Parse error:` → PHP error disclosure
- Response contains `Werkzeug Debugger`, `Using the URLconf defined in`, `Whitelabel Error Page`, `at Layer.handle` → framework debug mode exposed (High severity — often includes an interactive console)
- Response contains `Stack Trace:` with `.aspx`/`.cs` file references → ASP.NET detailed errors enabled

---

## Remediation Guide

### Disable Debug Mode

```python
# Flask
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

# Django
DEBUG = False
ALLOWED_HOSTS = ['example.com']
```

```java
// Spring Boot - application.properties
server.error.include-stacktrace=never
server.error.include-message=never
```

```php
// PHP
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log
```

---

## Risk Assessment

| Finding                        | CVSS | Severity |
| ------------------------------ | ---- | -------- |
| Full stack trace in production | 5.3  | Medium   |
| Debug mode enabled             | 7.5  | High     |
| Framework debug page           | 7.5  | High     |

---

## CWE Categories

| CWE ID      | Title                                                        |
| ----------- | ------------------------------------------------------------ |
| **CWE-209** | Generation of Error Message Containing Sensitive Information |
| **CWE-215** | Insertion of Sensitive Information Into Debugging Code       |


---

## References

- [OWASP WSTG-ERRH-02: Testing for Stack Traces](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

---

## Checklist

```
[ ] Error-triggering inputs tested
[ ] Debug mode indicators checked
[ ] Framework-specific debug pages tested
[ ] Stack trace patterns analyzed
[ ] API error responses checked
[ ] Findings documented
```
