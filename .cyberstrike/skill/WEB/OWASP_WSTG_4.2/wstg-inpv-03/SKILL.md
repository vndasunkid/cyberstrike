---
name: wstg-inpv-03
description: "Testing for HTTP Verb Tampering"
category: input-validation
owasp_id: WSTG-INPV-03
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: [CWE-89]
chains_with: [wstg-inpv-05, wstg-inpv-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-05: "HTTP Verb Tampering bypasses method-restricted access control (WAF/ACL rules that only inspect POST) to reach an unauthenticated SQL Injection endpoint via GET/PUT = Critical (Full DB Compromise)"
---

# wstg-inpv-03

## Test ID

WSTG-INPV-03

## Test Name

Testing for HTTP Verb Tampering

## High-Level Description

HTTP Verb Tampering exploits web servers or applications that respond differently to various HTTP methods (GET, POST, PUT, DELETE, etc.). Attackers may bypass security controls by using alternative HTTP methods that aren't properly restricted, potentially gaining unauthorized access to protected resources.

---

## What to Check

- [ ] Supported HTTP methods per endpoint
- [ ] Authentication bypass via method change
- [ ] Authorization bypass via method change
- [ ] HEAD method information leakage
- [ ] TRACE method enabled (XST)
- [ ] Arbitrary methods acceptance

---

## How to Test

### Step 1: Enumerate HTTP Methods

```bash
#!/bin/bash
TARGET="https://target.com"
ENDPOINT="/admin"

# Test common HTTP methods
METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS" "TRACE" "CONNECT")

echo "[*] Testing HTTP methods on $TARGET$ENDPOINT"

for method in "${METHODS[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$TARGET$ENDPOINT")
    echo "  $method: $response"
done

# Check OPTIONS response for allowed methods
echo -e "\n[*] OPTIONS response:"
curl -s -I -X OPTIONS "$TARGET$ENDPOINT" | grep -i "allow"

# Test arbitrary method
echo -e "\n[*] Testing arbitrary method:"
curl -s -o /dev/null -w "JEFF: %{http_code}\n" -X "JEFF" "$TARGET$ENDPOINT"
```

### Step 2: HTTP Verb Tampering Tester

```python
#!/usr/bin/env python3
"""
HTTP Verb Tampering Vulnerability Tester
"""

import requests
from requests.auth import HTTPBasicAuth

class VerbTamperingTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []
        self.session = requests.Session()

    HTTP_METHODS = [
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
        'HEAD', 'OPTIONS', 'TRACE', 'CONNECT',
        'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE',
        'LOCK', 'UNLOCK', 'VERSION-CONTROL', 'REPORT',
        'CHECKOUT', 'CHECKIN', 'UNCHECKOUT',
        # Arbitrary methods (should be rejected)
        'JEFF', 'FAKE', 'TEST', 'DEBUG'
    ]

    def test_methods(self, endpoint):
        """Test all HTTP methods on endpoint"""
        print(f"\n[*] Testing methods on {endpoint}")

        results = {}
        url = f"{self.base_url}{endpoint}"

        for method in self.HTTP_METHODS:
            try:
                response = self.session.request(method, url, timeout=10)
                results[method] = {
                    'status': response.status_code,
                    'length': len(response.content)
                }
                print(f"  {method}: {response.status_code} ({len(response.content)} bytes)")
            except Exception as e:
                results[method] = {'status': 'Error', 'error': str(e)}

        return results

    def test_auth_bypass(self, protected_endpoint, valid_creds=None):
        """Test if authentication can be bypassed via method change"""
        print(f"\n[*] Testing authentication bypass...")

        url = f"{self.base_url}{protected_endpoint}"

        # Get baseline with authentication
        if valid_creds:
            auth = HTTPBasicAuth(valid_creds[0], valid_creds[1])
            auth_response = self.session.get(url, auth=auth)
            print(f"  Authenticated GET: {auth_response.status_code}")

        # Get baseline without authentication
        unauth_get = self.session.get(url)
        print(f"  Unauthenticated GET: {unauth_get.status_code}")

        # Test other methods without authentication
        bypass_methods = ['POST', 'PUT', 'HEAD', 'OPTIONS', 'TRACE', 'JEFF']

        for method in bypass_methods:
            try:
                response = self.session.request(method, url)

                # Check if we get different (successful) response
                if response.status_code == 200 and unauth_get.status_code in [401, 403]:
                    print(f"  [VULN] {method} bypasses authentication! ({response.status_code})")
                    self.findings.append({
                        'type': 'Authentication Bypass',
                        'method': method,
                        'endpoint': protected_endpoint,
                        'severity': 'Critical'
                    })
            except:
                pass

    def test_authorization_bypass(self, admin_endpoint, user_session):
        """Test if authorization can be bypassed via method change"""
        print(f"\n[*] Testing authorization bypass...")

        url = f"{self.base_url}{admin_endpoint}"
        self.session.cookies.update(user_session)

        # Test access with regular user credentials
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'JEFF']

        for method in methods:
            try:
                response = self.session.request(method, url)

                if response.status_code == 200:
                    # Check if response contains admin content
                    if 'admin' in response.text.lower() or len(response.content) > 100:
                        print(f"  [WARN] {method} returns content ({response.status_code})")
                        self.findings.append({
                            'type': 'Potential Authorization Bypass',
                            'method': method,
                            'endpoint': admin_endpoint,
                            'severity': 'High'
                        })
            except:
                pass

    def test_trace_xst(self):
        """Test for Cross-Site Tracing (XST) via TRACE method"""
        print(f"\n[*] Testing for XST (TRACE method)...")

        url = self.base_url
        headers = {'X-Custom-Header': 'XST-Test-Value'}

        try:
            response = self.session.request('TRACE', url, headers=headers)

            if response.status_code == 200:
                if 'XST-Test-Value' in response.text:
                    print(f"  [VULN] TRACE method enabled - XST possible!")
                    self.findings.append({
                        'type': 'Cross-Site Tracing (XST)',
                        'method': 'TRACE',
                        'severity': 'Medium',
                        'detail': 'TRACE reflects headers including cookies'
                    })
                else:
                    print(f"  [INFO] TRACE enabled but not reflecting headers")
            else:
                print(f"  [OK] TRACE method disabled ({response.status_code})")
        except:
            pass

    def test_webdav_methods(self):
        """Test for WebDAV methods"""
        print(f"\n[*] Testing WebDAV methods...")

        webdav_methods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']

        for method in webdav_methods:
            try:
                response = self.session.request(method, self.base_url)

                if response.status_code not in [405, 501]:
                    print(f"  [WARN] {method} enabled ({response.status_code})")
                    self.findings.append({
                        'type': 'WebDAV Method Enabled',
                        'method': method,
                        'severity': 'Low',
                        'detail': 'WebDAV methods should be disabled if not needed'
                    })
            except:
                pass

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("HTTP VERB TAMPERING REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo significant vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                print(f"  Method: {f['method']}")
                if 'endpoint' in f:
                    print(f"  Endpoint: {f['endpoint']}")
                if 'detail' in f:
                    print(f"  Detail: {f['detail']}")

    def run_tests(self, endpoints=None):
        """Run all verb tampering tests"""
        if endpoints is None:
            endpoints = ['/admin', '/api/admin', '/dashboard', '/settings']

        for endpoint in endpoints:
            self.test_methods(endpoint)

        self.test_auth_bypass('/admin')
        self.test_trace_xst()
        self.test_webdav_methods()
        self.generate_report()

# Usage
tester = VerbTamperingTester("https://target.com")
tester.run_tests()
```

### Step 3: Method Override Headers

```bash
#!/bin/bash
TARGET="https://target.com/admin"

# Test method override headers
echo "[*] Testing method override headers..."

# X-HTTP-Method-Override
curl -s -X POST -H "X-HTTP-Method-Override: DELETE" "$TARGET" -o /dev/null -w "X-HTTP-Method-Override: DELETE -> %{http_code}\n"

# X-HTTP-Method
curl -s -X POST -H "X-HTTP-Method: PUT" "$TARGET" -o /dev/null -w "X-HTTP-Method: PUT -> %{http_code}\n"

# X-Method-Override
curl -s -X POST -H "X-Method-Override: PATCH" "$TARGET" -o /dev/null -w "X-Method-Override: PATCH -> %{http_code}\n"

# Query parameter method override
curl -s -X POST "$TARGET?_method=DELETE" -o /dev/null -w "_method=DELETE parameter -> %{http_code}\n"

# Body parameter override
curl -s -X POST -d "_method=DELETE" "$TARGET" -o /dev/null -w "_method=DELETE body -> %{http_code}\n"
```

### Step 4: Burp Intruder Technique

```
# Burp Suite Intruder configuration

# Position: HTTP method
# Payload list:
GET
POST
PUT
DELETE
PATCH
HEAD
OPTIONS
TRACE
CONNECT
PROPFIND
COPY
MOVE
LOCK
UNLOCK
MKCOL
FAKE

# Also test with authentication removed
# Compare response codes and lengths
```

---

## Tools

| Tool              | Purpose                       |
| ----------------- | ----------------------------- |
| curl              | Manual method testing         |
| Burp Suite        | Intercept and modify methods  |
| Nmap http-methods | Script for method enumeration |
| OWASP ZAP         | Web scanner                   |

---

## Example Commands/Payloads

### Method Enumeration (curl / nmap)

```bash
TARGET="https://target.com/admin"

# Enumerate allowed methods via OPTIONS
curl -s -i -X OPTIONS "$TARGET" | grep -i "^allow:"

# Sweep individual verbs and compare status codes/lengths
for m in GET POST PUT DELETE PATCH HEAD TRACE CONNECT PROPFIND COPY MOVE LOCK UNLOCK MKCOL FAKEVERB; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" "$TARGET")
    echo "$m -> $code"
done

# Nmap http-methods NSE script
nmap -p 443 --script http-methods --script-args http-methods.url-path='/admin' target.com
```

### Authentication/Authorization Bypass via Verb Tampering

```bash
# Baseline: GET is blocked (401/403)
curl -s -o /dev/null -w "GET -> %{http_code}\n" "$TARGET"

# Try alternate verbs against the same protected resource
curl -s -o /dev/null -w "POST -> %{http_code}\n" -X POST "$TARGET"
curl -s -o /dev/null -w "HEAD -> %{http_code}\n" -X HEAD "$TARGET"
curl -s -o /dev/null -w "TRACE -> %{http_code}\n" -X TRACE "$TARGET"
curl -s -o /dev/null -w "FAKEVERB -> %{http_code}\n" -X FAKEVERB "$TARGET"

# 200 on a verb that GET/POST denies indicates a verb-based ACL bypass (e.g. Apache <LimitExcept GET POST>)
```

### Cross-Site Tracing (XST) Check

```bash
curl -s -i -X TRACE "$TARGET" -H "X-Header: xst-test" | grep -q "xst-test" && \
    echo "[VULN] TRACE enabled and reflects headers - XST possible (can bypass HttpOnly cookies via XSS)"
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `Allow:` header lists verbs beyond `GET, POST, HEAD, OPTIONS` | Extra methods enabled, needs review |
| A restricted resource returns `200`/`3xx` for a non-standard verb while `GET` returns `401`/`403` | ACL implemented only for specific verbs — bypass |
| `TRACE` response echoes back request headers | XST vulnerable, can be combined with XSS to steal `HttpOnly` cookies |
| WebDAV verbs (`PROPFIND`, `MKCOL`, `PUT`) return `2xx`/`207` | WebDAV enabled and potentially writable |

---

## Remediation

```python
# Python/Flask - Explicitly define allowed methods
from flask import Flask, request, abort

app = Flask(__name__)

# Only allow specific methods per endpoint
@app.route('/api/resource', methods=['GET', 'POST'])
def resource():
    if request.method == 'GET':
        return get_resource()
    elif request.method == 'POST':
        return create_resource()

# Deny all other methods globally
@app.before_request
def check_method():
    allowed = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    if request.method not in allowed:
        abort(405)

# Disable TRACE
@app.after_request
def disable_trace(response):
    if request.method == 'TRACE':
        return '', 405
    return response
```

```nginx
# Nginx - Restrict HTTP methods
location /admin {
    limit_except GET POST {
        deny all;
    }

    # Disable TRACE
    if ($request_method = TRACE) {
        return 405;
    }
}
```

```apache
# Apache - Restrict methods
<Location "/admin">
    <LimitExcept GET POST>
        Require all denied
    </LimitExcept>

    # Disable TRACE
    TraceEnable off
</Location>
```

---

## Risk Assessment

| Finding                          | CVSS | Severity |
| -------------------------------- | ---- | -------- |
| Authentication bypass via method | 9.8  | Critical |
| Authorization bypass via method  | 8.1  | High     |
| TRACE method enabled (XST)       | 5.3  | Medium   |
| WebDAV methods enabled           | 4.3  | Medium   |
| Arbitrary methods accepted       | 3.1  | Low      |

---

## CWE Categories

| CWE ID      | Title                                               |
| ----------- | --------------------------------------------------- |
| **CWE-650** | Trusting HTTP Permission Methods on the Server Side |

---

## References

- [OWASP Testing Guide - HTTP Methods](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 7231 - HTTP Methods](https://tools.ietf.org/html/rfc7231)


---

## Checklist

```
[ ] All HTTP methods tested
[ ] Authentication bypass tested
[ ] Authorization bypass tested
[ ] TRACE method tested (XST)
[ ] WebDAV methods tested
[ ] Method override headers tested
[ ] Arbitrary methods tested
[ ] Findings documented
```
