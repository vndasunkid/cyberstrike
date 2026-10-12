---
name: wstg-cryp-03
description: "Testing for Sensitive Information Sent via Unencrypted Channels"
category: cryptography
owasp_id: WSTG-CRYP-03
version: "1.0.0"
author: cyberstrike-official
tags: [cryptography, tls, ssl, encryption, wstg, cryp]
tech_stack: []
cwe_ids: [CWE-311]
chains_with: [wstg-cryp-01, wstg-cryp-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-cryp-01: "Sensitive data reachable over plain HTTP combined with weak/missing HSTS lets an active attacker perform SSL-stripping to force victims onto the unencrypted channel and capture credentials/tokens in cleartext at scale (Critical)"
---

# wstg-cryp-03

## Test ID

WSTG-CRYP-03

## Test Name

Testing for Sensitive Information Sent via Unencrypted Channels

## High-Level Description

Sensitive data transmitted over unencrypted channels (HTTP) can be intercepted by attackers through man-in-the-middle attacks. This includes credentials, session tokens, personal information, and financial data. All sensitive communications must use encrypted channels (HTTPS) with proper configuration.

---

## What to Check

- [ ] Login forms over HTTP
- [ ] Session tokens over HTTP
- [ ] Sensitive data in HTTP requests
- [ ] Mixed content issues
- [ ] HTTP to HTTPS redirects
- [ ] API calls over HTTP
- [ ] Form actions over HTTP

---

## How to Test

### Step 1: Check for HTTP Access

```bash
#!/bin/bash
TARGET="target.com"

# Check if HTTP is accessible
echo "=== HTTP Access ==="
curl -sI "http://$TARGET" | head -10

# Check if redirect to HTTPS
redirect=$(curl -sI "http://$TARGET" | grep -i "location")
if echo "$redirect" | grep -qi "https"; then
    echo "[OK] Redirects to HTTPS"
else
    echo "[VULN] HTTP accessible without redirect"
fi

# Check login page over HTTP
curl -sI "http://$TARGET/login" | head -10
```

### Step 2: Check Form Actions

```bash
#!/bin/bash
TARGET="https://target.com"

# Get login page and check form action
page=$(curl -s "$TARGET/login")

# Check for HTTP form actions
if echo "$page" | grep -qi 'action="http://'; then
    echo "[VULN] Form submits to HTTP"
fi

# Check for protocol-relative or relative URLs
echo "$page" | grep -oP 'action="[^"]*"' | head -5
```

### Step 3: Check for Mixed Content

```bash
#!/bin/bash
TARGET="https://target.com"

# Get page and check for HTTP resources
page=$(curl -s "$TARGET")

# Find HTTP resources
echo "=== HTTP Resources on HTTPS Page ==="
echo "$page" | grep -oP 'src="http://[^"]*"' | head -10
echo "$page" | grep -oP 'href="http://[^"]*"' | head -10
```

### Step 4: Comprehensive Channel Security Tester

```python
#!/usr/bin/env python3
import requests
from urllib.parse import urlparse
import re

class ChannelSecurityTester:
    def __init__(self, domain):
        self.domain = domain
        self.findings = []

    def test_http_redirect(self):
        """Test if HTTP redirects to HTTPS"""
        print("[*] Testing HTTP redirect...")

        try:
            response = requests.get(
                f"http://{self.domain}",
                allow_redirects=False,
                timeout=10
            )

            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    print(f"[OK] Redirects to HTTPS: {location}")
                    return
                else:
                    print(f"[WARN] Redirects but not to HTTPS: {location}")

            print("[VULN] HTTP accessible without redirect to HTTPS")
            self.findings.append({
                "issue": "HTTP accessible without HTTPS redirect",
                "severity": "High"
            })

        except requests.exceptions.ConnectionError:
            print("[OK] HTTP not accessible (port closed)")

    def test_hsts(self):
        """Test HSTS implementation"""
        print("\n[*] Testing HSTS...")

        try:
            response = requests.get(f"https://{self.domain}", timeout=10)
            hsts = response.headers.get('Strict-Transport-Security', '')

            if hsts:
                print(f"[OK] HSTS: {hsts}")

                # Check max-age
                if 'max-age=' in hsts:
                    max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                    if max_age < 31536000:
                        print("[WARN] HSTS max-age less than 1 year")
                        self.findings.append({
                            "issue": "HSTS max-age too short",
                            "severity": "Low"
                        })
            else:
                print("[VULN] HSTS header missing")
                self.findings.append({
                    "issue": "Missing HSTS header",
                    "severity": "Medium"
                })

        except Exception as e:
            print(f"[ERROR] {e}")

    def test_mixed_content(self, pages):
        """Test for mixed content on HTTPS pages"""
        print("\n[*] Testing for mixed content...")

        http_resources = []

        for page in pages:
            try:
                response = requests.get(f"https://{self.domain}{page}", timeout=10)

                # Find HTTP resources
                http_refs = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']',
                                      response.text, re.IGNORECASE)

                for ref in http_refs:
                    print(f"[VULN] Mixed content on {page}: {ref[:60]}")
                    http_resources.append({'page': page, 'resource': ref})

            except Exception as e:
                pass

        if http_resources:
            self.findings.append({
                "issue": f"Mixed content found ({len(http_resources)} resources)",
                "severity": "Medium"
            })

    def test_sensitive_forms(self, form_pages):
        """Test if sensitive forms submit securely"""
        print("\n[*] Testing form security...")

        for page in form_pages:
            try:
                response = requests.get(f"https://{self.domain}{page}", timeout=10)

                # Find form actions
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']',
                                  response.text, re.IGNORECASE)

                for action in forms:
                    if action.startswith('http://'):
                        print(f"[VULN] Form on {page} submits to HTTP: {action}")
                        self.findings.append({
                            "issue": f"Form submits to HTTP on {page}",
                            "severity": "High"
                        })

            except Exception as e:
                pass

    def generate_report(self):
        """Generate security report"""
        print("\n" + "="*50)
        print("CHANNEL SECURITY REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo issues found.")
            return

        print(f"\nFindings: {len(self.findings)}")
        for f in self.findings:
            print(f"\n  [{f['severity']}] {f['issue']}")

# Usage
tester = ChannelSecurityTester("target.com")
tester.test_http_redirect()
tester.test_hsts()
tester.test_mixed_content(["/", "/login", "/dashboard"])
tester.test_sensitive_forms(["/login", "/register", "/payment"])
tester.generate_report()
```

---

## Tools

| Tool               | Description                          | Usage                                        |
| ------------------ | ------------------------------------- | --------------------------------------------- |
| **curl**           | Manual HTTP/HTTPS probing            | `curl -sI http://target.com`                  |
| **testssl.sh**     | Checks HSTS/security headers         | `./testssl.sh --headers target.com`           |
| **OWASP ZAP**      | Passive scan for mixed content       | Spider + passive scan                         |
| **Burp Suite**     | Proxy history review for HTTP traffic| Manual review / passive scan                  |
| **MixedContentScan**| Automated mixed-content crawler      | `mixed-content-scan https://target.com`       |

---

## Example Commands/Payloads

```bash
TARGET="target.com"

# Is plaintext HTTP reachable at all, and does it redirect?
curl -sI "http://$TARGET" -o /tmp/http_headers.txt -w "%{http_code} -> %{redirect_url}\n"
grep -i '^location:' /tmp/http_headers.txt

# Confirm HSTS header and max-age on the HTTPS origin
curl -sI "https://$TARGET" | grep -i 'strict-transport-security'

# Sensitive endpoints reachable over plain HTTP (credentials/session risk)
for path in /login /account /api/user /checkout; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET$path")
  echo "http://$TARGET$path -> $code"
done

# Mixed content grep on a rendered HTTPS page
curl -s "https://$TARGET/" | grep -oE '(src|href|action)="http://[^"]+"'

# Capture a login POST over HTTP with Wireshark/tcpdump to prove cleartext credentials (authorized testing only)
sudo tcpdump -i any -A 'tcp port 80 and host '"$TARGET" -w http_capture.pcap
```

**Result patterns indicating a finding:**
- `curl -sI http://target.com` returns `200` (not a `301/302/307/308` to `https://`) → HTTP accessible without HTTPS redirect
- `Location:` header on the 30x response points to `http://` instead of `https://` → insecure redirect
- `strict-transport-security` header absent, or `max-age` below `31536000` → missing/weak HSTS
- Grep on rendered HTTPS page returns `src="http://...`, `href="http://...`, or `action="http://...` → mixed content / insecure form submission
- Captured pcap shows readable `POST /login` body with `username=`/`password=` in cleartext → confirmed cleartext credential transmission

---

## Remediation Guide

### Force HTTPS Redirect

```nginx
# Nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

### HSTS Header

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

### Content Security Policy

```nginx
add_header Content-Security-Policy "upgrade-insecure-requests";
```

---

## Risk Assessment

| Finding                 | CVSS | Severity |
| ----------------------- | ---- | -------- |
| Credentials over HTTP   | 7.5  | High     |
| Session token over HTTP | 7.5  | High     |
| Missing HSTS            | 4.3  | Medium   |
| Mixed content           | 4.3  | Medium   |

---

## CWE Categories

| CWE ID      | Title                                           |
| ----------- | ----------------------------------------------- |
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **CWE-311** | Missing Encryption of Sensitive Data            |


---

## References

- [OWASP WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels)
- [OWASP HTTP Strict Transport Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [MDN: Mixed Content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)

---

## Checklist

```
[ ] HTTP redirect tested
[ ] HSTS header checked
[ ] Form actions verified
[ ] Mixed content tested
[ ] API endpoints checked
[ ] Findings documented
```
