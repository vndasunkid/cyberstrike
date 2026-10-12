---
name: wstg-apit-00
description: "API Testing Overview"
category: api-testing
owasp_id: WSTG-APIT-00
version: "1.0.0"
author: cyberstrike-official
tags: [api, rest, graphql, soap, wstg, apit]
tech_stack: []
cwe_ids: []
chains_with: [wstg-apit-01, wstg-apit-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-apit-00

## Test ID

WSTG-APIT-00

## Test Name

API Testing Overview

## High-Level Description

APIs (Application Programming Interfaces) are the backbone of modern applications, enabling communication between different services, mobile apps, and frontend interfaces. API security testing focuses on identifying vulnerabilities specific to API implementations including authentication, authorization, input validation, and business logic flaws.

---

## API Types

### REST APIs

- HTTP-based, stateless
- Uses standard methods (GET, POST, PUT, DELETE)
- JSON/XML responses
- Resource-based URLs

### GraphQL APIs

- Single endpoint
- Query language for APIs
- Client-specified data retrieval
- Introspection capabilities

### SOAP APIs

- XML-based protocol
- WSDL service descriptions
- Enterprise/legacy systems
- Strict contracts

---

## What to Check

### Authentication & Authorization

- [ ] API key security
- [ ] OAuth implementation
- [ ] JWT validation
- [ ] BOLA (IDOR) vulnerabilities
- [ ] BFLA (Function-level auth)
- [ ] Rate limiting

### Input Validation

- [ ] Injection attacks
- [ ] Mass assignment
- [ ] Parameter tampering
- [ ] Content-type validation

### Data Protection

- [ ] Sensitive data exposure
- [ ] Excessive data exposure
- [ ] Encryption in transit

---

## How to Test

### Step 1: API Discovery

```bash
#!/bin/bash
TARGET="target.com"

# Find API endpoints
# Check common paths
endpoints=(
    "/api"
    "/api/v1"
    "/api/v2"
    "/v1"
    "/graphql"
    "/rest"
    "/swagger.json"
    "/openapi.json"
    "/api-docs"
)

for endpoint in "${endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$endpoint")
    echo "$endpoint: $status"
done

# Check for API documentation
curl -s "https://$TARGET/swagger.json" | jq '.' 2>/dev/null
curl -s "https://$TARGET/.well-known/openapi.json" | jq '.' 2>/dev/null
```

### Step 2: API Enumeration

```bash
# Use API documentation or fuzzing
# Extract endpoints from:
# - Swagger/OpenAPI specs
# - Mobile app analysis
# - JavaScript source code
# - Proxy traffic

# Fuzz API endpoints
ffuf -u "https://target.com/api/FUZZ" -w api-wordlist.txt -mc 200,201,401,403
```

### Step 3: Authentication Testing

```bash
#!/bin/bash
API="https://target.com/api"

# Test without authentication
curl -s "$API/users" -H "Content-Type: application/json"

# Test with invalid token
curl -s "$API/users" -H "Authorization: Bearer invalid_token"

# Test with expired token
curl -s "$API/users" -H "Authorization: Bearer expired_token"

# Test API key in different locations
curl -s "$API/users?api_key=test"
curl -s "$API/users" -H "X-API-Key: test"
curl -s "$API/users" -H "Authorization: ApiKey test"
```

### Step 4: Basic API Security Checker

```python
#!/usr/bin/env python3
import requests
import json

class APISecurityChecker:
    def __init__(self, base_url, auth_header=None):
        self.base_url = base_url
        self.session = requests.Session()
        if auth_header:
            self.session.headers.update(auth_header)
        self.findings = []

    def check_authentication(self, endpoints):
        """Check authentication requirements"""
        print("[*] Checking authentication...")

        no_auth = requests.Session()

        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"

            # Test without auth
            response = no_auth.get(url)
            if response.status_code == 200:
                print(f"[VULN] No auth required: {endpoint}")
                self.findings.append({
                    "issue": f"Missing authentication on {endpoint}",
                    "severity": "High"
                })

    def check_rate_limiting(self, endpoint, requests_count=100):
        """Check for rate limiting"""
        print(f"\n[*] Checking rate limiting on {endpoint}...")

        for i in range(requests_count):
            response = self.session.get(f"{self.base_url}{endpoint}")
            if response.status_code == 429:
                print(f"[OK] Rate limited after {i+1} requests")
                return

        print(f"[WARN] No rate limiting after {requests_count} requests")
        self.findings.append({
            "issue": f"No rate limiting on {endpoint}",
            "severity": "Medium"
        })

    def check_http_methods(self, endpoint):
        """Check allowed HTTP methods"""
        print(f"\n[*] Checking HTTP methods on {endpoint}...")

        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
        url = f"{self.base_url}{endpoint}"

        for method in methods:
            response = self.session.request(method, url)
            if response.status_code not in [404, 405]:
                print(f"  {method}: {response.status_code}")

    def check_cors(self, endpoint):
        """Check CORS configuration"""
        print(f"\n[*] Checking CORS on {endpoint}...")

        headers = {"Origin": "https://evil.com"}
        response = self.session.options(
            f"{self.base_url}{endpoint}",
            headers=headers
        )

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'https://evil.com':
            print(f"[VULN] Permissive CORS: {acao}")
            self.findings.append({
                "issue": "Permissive CORS configuration",
                "severity": "Medium"
            })

    def generate_report(self):
        """Generate API security report"""
        print("\n" + "="*50)
        print("API SECURITY REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo issues found.")
            return

        print(f"\nFindings: {len(self.findings)}")
        for f in self.findings:
            print(f"\n  [{f['severity']}] {f['issue']}")

# Usage
checker = APISecurityChecker(
    "https://target.com/api",
    {"Authorization": "Bearer token"}
)
checker.check_authentication(["/users", "/orders", "/admin"])
checker.check_rate_limiting("/users")
checker.check_http_methods("/users")
checker.check_cors("/users")
checker.generate_report()
```

---

## Tools

| Tool                | Description                   |
| ------------------- | ----------------------------- |
| **Postman**         | API testing and documentation |
| **Burp Suite**      | API traffic interception      |
| **OWASP ZAP**       | Automated API scanning        |
| **Insomnia**        | API client                    |
| **GraphQL Voyager** | GraphQL visualization         |

---

## Example Commands/Payloads

### Initial API Discovery Cheat Sheet

```bash
TARGET="{target}"

# Swagger / OpenAPI / API doc discovery
for path in swagger.json swagger/v1/swagger.json openapi.json v2/api-docs v3/api-docs \
            api-docs api/swagger.json .well-known/openapi.json redoc api/docs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$path")
  [ "$code" != "404" ] && echo "[FOUND] /$path -> $code"
done

# Pull and pretty-print the spec once found
curl -s "https://$TARGET/swagger.json" | jq '.paths | keys'
curl -s "https://$TARGET/openapi.json" | jq '.paths | keys'

# GraphQL endpoint probe (single request, no auth needed)
curl -s -X POST "https://$TARGET/graphql" -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}'

# SOAP/WSDL discovery
curl -s "https://$TARGET/service?wsdl"
curl -s "https://$TARGET/api/service.asmx?wsdl"

# API version sweep
for v in v1 v2 v3 v4; do
  curl -s -o /dev/null -w "/api/$v -> %{http_code}\n" "https://$TARGET/api/$v"
done

# Endpoint fuzzing once a base path is known
ffuf -u "https://$TARGET/api/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200,201,204,301,302,401,403 -o api-discovery.json
```

### Detection Patterns

| Signal                                    | Meaning                              |
| -------------------------------------------- | ----------------------------------------- |
| `200` on `swagger.json`/`openapi.json`         | Full API surface disclosed — enumerate `paths` |
| `__typename` responds without error            | GraphQL endpoint confirmed, try introspection |
| `?wsdl` returns XML service description        | SOAP endpoint — extract operations/params |
| Non-`404` on `/api/v1` but `404` on `/api/v4`   | Active API version range identified   |

---

## Remediation Guide

- **Inventory & documentation**: maintain an up-to-date API inventory (all versions, all environments); never expose Swagger/OpenAPI/GraphQL introspection in production without authentication.
- **AuthN/AuthZ**: enforce object-level and function-level authorization checks on every endpoint server-side — never trust client-supplied IDs or roles (see `wstg-apit-02` for BOLA specifics).
- **Rate limiting & resource limits**: apply per-user/per-IP rate limiting, request size caps, and query complexity/depth limits (GraphQL) to prevent abuse and DoS (see `wstg-apit-99`).
- **Input validation**: validate content-type, schema, and payload structure server-side regardless of what client SDKs enforce; reject unexpected fields (mass assignment).
- **Versioning hygiene**: deprecate and fully decommission old API versions rather than leaving them reachable alongside current ones.

---

## Risk Assessment

This is an overview/entry-point skill — actual severity depends on which specific API weakness is confirmed via the chained skills (`wstg-apit-01` Recon, `wstg-apit-02` BOLA, `wstg-apit-99` GraphQL). As a general guide:

| Finding Category | Typical CVSS Range | Severity |
| --- | --- | --- |
| Broken Object/Function Level Authorization (BOLA/BFLA) | 7.5 - 9.8 | High-Critical |
| Missing/weak authentication on endpoint | 8.0 - 9.8 | High-Critical |
| Excessive data exposure / verbose errors | 5.3 - 6.5 | Medium |
| Missing rate limiting | 5.3 | Medium |
| Undocumented/deprecated endpoint reachable | 5.3 - 7.5 | Medium-High |

---

## CWE Categories

| CWE ID | Title | Description |
| --- | --- | --- |
| **CWE-284** | Improper Access Control | Umbrella category for BOLA/BFLA findings across API endpoints |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | Excessive data exposure, verbose API errors |
| **CWE-799** | Improper Control of Interaction Frequency | Missing/insufficient API rate limiting |

---

## OWASP API Security Top 10 (2023)

| ID    | Vulnerability                                   |
| ----- | ----------------------------------------------- |
| API1  | Broken Object Level Authorization (BOLA)        |
| API2  | Broken Authentication                           |
| API3  | Broken Object Property Level Authorization      |
| API4  | Unrestricted Resource Consumption               |
| API5  | Broken Function Level Authorization (BFLA)      |
| API6  | Unrestricted Access to Sensitive Business Flows |
| API7  | Server Side Request Forgery (SSRF)              |
| API8  | Security Misconfiguration                       |
| API9  | Improper Inventory Management                   |
| API10 | Unsafe Consumption of APIs                      |

---

## References

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)


---

## Checklist

```
[ ] API endpoints discovered
[ ] Authentication tested
[ ] Authorization tested
[ ] Input validation tested
[ ] Rate limiting checked
[ ] CORS configuration reviewed
[ ] Error handling analyzed
[ ] Findings documented
```
