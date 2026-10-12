---
name: wstg-sess-06
description: "Testing for Logout Functionality"
category: session-management
owasp_id: WSTG-SESS-06
version: "1.0.0"
author: cyberstrike-official
tags: [session, cookies, csrf, token, wstg, sess]
tech_stack: []
cwe_ids: [CWE-613]
chains_with: [wstg-sess-03, wstg-sess-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-sess-03: "Broken logout invalidation + confirmed session fixation = attacker's pre-set session stays valid even after the victim logs out, giving persistent unauthorized access (Critical)"
  wstg-sess-01: "No server-side invalidation on logout + no absolute session expiration in the schema = a leaked or hijacked token remains exploitable indefinitely (High)"
---

# wstg-sess-06

## Test ID

WSTG-SESS-06

## Test Name

Testing for Logout Functionality

## High-Level Description

Logout functionality must properly terminate user sessions by invalidating session tokens on the server side. Improper logout implementation can allow continued access using old session tokens, session replay attacks, or leave users vulnerable if using shared computers.

---

## What to Check

- [ ] Server-side session invalidation
- [ ] Client-side token clearing
- [ ] "Remember me" token revocation
- [ ] All sessions logout (multi-device)
- [ ] Browser cache clearing
- [ ] Redirect after logout

---

## How to Test

### Step 1: Test Session Invalidation

```bash
#!/bin/bash
TARGET="https://target.com"

# Get authenticated session
session=$(curl -s -c - -X POST "$TARGET/login" \
    -d "username=test&password=test" | grep -oP "SESSIONID=\K[^;]+")
echo "Session: $session"

# Verify authenticated
curl -s -b "SESSIONID=$session" "$TARGET/dashboard" | grep -q "Welcome" && \
    echo "[OK] Session authenticated"

# Logout
curl -s -b "SESSIONID=$session" "$TARGET/logout"

# Try to use old session
response=$(curl -s -b "SESSIONID=$session" "$TARGET/dashboard")

if echo "$response" | grep -q "Welcome"; then
    echo "[VULN] Session still valid after logout!"
else
    echo "[OK] Session properly invalidated"
fi
```

### Step 2: Test Back Button After Logout

```bash
# After logout, cached pages should not be accessible
# Check Cache-Control headers on authenticated pages

curl -sI -b "session=valid" "https://target.com/dashboard" | \
    grep -iE "cache-control|pragma"

# Should include: no-store, no-cache, must-revalidate
```

### Step 3: Session Invalidation Tester

```python
#!/usr/bin/env python3
import requests
import time

class LogoutTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    def test_logout(self, login_creds, protected_page, logout_endpoint):
        """Test complete logout functionality"""
        print("[*] Testing logout functionality...")

        # Login
        session = requests.Session()
        session.post(f"{self.base_url}/login", data=login_creds)

        # Get session cookie
        original_cookies = dict(session.cookies)
        print(f"Session established: {list(original_cookies.keys())}")

        # Verify authenticated
        response = session.get(f"{self.base_url}{protected_page}")
        if response.status_code != 200:
            print("[!] Could not authenticate")
            return

        # Logout
        session.get(f"{self.base_url}{logout_endpoint}")
        print("Logout request sent")

        # Test 1: Same session access
        print("\n[1] Testing session after logout...")
        new_session = requests.Session()
        for name, value in original_cookies.items():
            new_session.cookies.set(name, value)

        response = new_session.get(f"{self.base_url}{protected_page}")

        if response.status_code == 200 and 'login' not in response.url.lower():
            print("[VULN] Session still valid after logout!")
            self.findings.append({
                "issue": "Session not invalidated",
                "severity": "High"
            })
        else:
            print("[OK] Session properly invalidated")

        # Test 2: Check cache headers
        print("\n[2] Checking cache headers...")
        self._check_cache_headers(protected_page)

        return self.findings

    def _check_cache_headers(self, protected_page):
        """Check if cache headers prevent storing"""
        session = requests.Session()
        response = session.get(f"{self.base_url}{protected_page}")

        cache_control = response.headers.get('Cache-Control', '')

        if 'no-store' in cache_control.lower():
            print("[OK] no-store header present")
        else:
            print("[WARN] Missing no-store - pages may be cached")
            self.findings.append({
                "issue": "Missing no-store cache header",
                "severity": "Medium"
            })

# Usage
tester = LogoutTester("https://target.com")
tester.test_logout(
    {"username": "test", "password": "test"},
    "/dashboard",
    "/logout"
)
```

---

## Tools

| Tool                 | Description             | Usage                                    |
| --------------------- | ------------------------- | ------------------------------------------ |
| **Burp Suite**        | Repeater/Proxy            | Replay pre-logout request with old cookie |
| **OWASP ZAP**         | Automated scanner         | Session management add-on                |
| **jwt_tool**          | JWT-specific testing      | Check if JWT is blacklisted after logout |
| **curl**              | Command-line replay       | Scripted invalidation checks             |

---

## Example Commands/Payloads

```bash
# Full logout invalidation check
SESSION=$(curl -s -c - -X POST "https://{target}/login" -d "username=test&password=test" | grep -oP "SESSIONID=\K[^;]+")
curl -s -b "SESSIONID=$SESSION" "https://{target}/logout" -o /dev/null
curl -s -o /dev/null -w "%{http_code}\n" -b "SESSIONID=$SESSION" "https://{target}/dashboard"
# 200/"Welcome" => [VULN] session still valid after logout

# Check JWT-based session for revocation/blacklist after logout
TOKEN="{jwt_token}"
curl -s -X POST "https://{target}/logout" -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" "https://{target}/api/protected" \
    -H "Authorization: Bearer $TOKEN"
# 200 => [VULN] JWT not revoked/blacklisted after logout

# Check "remember me" persistent cookie is also cleared
curl -s -c - -b "remember_token={remember_token}" "https://{target}/logout" | grep -i "remember"
curl -s -b "remember_token={remember_token}" "https://{target}/dashboard" | grep -qi "welcome" \
    && echo "[VULN] remember-me token still valid after logout"

# Confirm logout response clears the cookie (Set-Cookie with Max-Age=0 / expired)
curl -sI -b "SESSIONID=$SESSION" "https://{target}/logout" | grep -i "set-cookie"
```

---

## Remediation Guide

### Proper Logout Implementation

```python
from flask import session, redirect

@app.route('/logout')
def logout():
    # Clear server-side session
    session_id = session.get('id')
    if session_id:
        SessionStore.delete(session_id)

    # Clear all session data
    session.clear()

    # Create response with cache headers
    response = redirect('/login')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'

    # Clear session cookie
    response.delete_cookie('session')

    return response
```

---

## Risk Assessment

| Finding                     | CVSS | Severity |
| --------------------------- | ---- | -------- |
| Session valid after logout  | 6.5  | Medium   |
| Missing cache headers       | 4.3  | Medium   |
| No server-side invalidation | 7.5  | High     |

---

## CWE Categories

| CWE ID      | Title                           |
| ----------- | ------------------------------- |
| **CWE-613** | Insufficient Session Expiration |

---

## References

- [OWASP WSTG - Testing for Logout Functionality](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)


---

## Checklist

```
[ ] Server-side invalidation tested
[ ] Old session token tested post-logout
[ ] Cache headers checked
[ ] All sessions logout tested
[ ] Cookie clearing verified
[ ] Findings documented
```
