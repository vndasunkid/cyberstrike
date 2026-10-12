---
name: wstg-clnt-08
description: "Testing for Cross-Site Flashing"
category: client-side
owasp_id: WSTG-CLNT-08
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: [html, javascript]
cwe_ids: [CWE-1021]
chains_with: [wstg-clnt-01, wstg-clnt-01.1]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-clnt-01: "Wildcard crossdomain.xml + a SWF that calls getURL('asfunction:...')/ExternalInterface on unsanitized FlashVars = any external domain can load the SWF to execute arbitrary JavaScript in the embedding page's origin, turning a legacy policy misconfig into full DOM XSS/session theft (Medium -> High)"
---

# wstg-clnt-08

## Test ID

WSTG-CLNT-08

## Test Name

Testing for Cross-Site Flashing

## High-Level Description

Cross-Site Flashing (XSF) vulnerabilities occur in Flash/SWF applications when user input is improperly handled. Although Flash is deprecated, legacy applications may still use it. Similar vulnerabilities can exist in other rich media technologies.

---

## What to Check

- [ ] Flash files on target site
- [ ] crossdomain.xml configuration
- [ ] External data loading in SWF
- [ ] User input in Flash parameters
- [ ] Legacy rich media content

---

## How to Test

### Step 1: Find Flash Content

```bash
#!/bin/bash
TARGET="target.com"

# Find SWF files
curl -s "https://$TARGET" | grep -oP '[^"]+\.swf'

# Check crossdomain.xml
curl -s "https://$TARGET/crossdomain.xml"

# Common paths
paths=("/crossdomain.xml" "/clientaccesspolicy.xml" "/flash/crossdomain.xml")
for path in "${paths[@]}"; do
    curl -s "https://$TARGET$path"
done
```

### Step 2: Analyze crossdomain.xml

```xml
<!-- Vulnerable configuration -->
<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="*"/>  <!-- VULNERABLE -->
</cross-domain-policy>

<!-- Secure configuration -->
<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="trusted.com"/>
    <allow-access-from domain="*.trusted.com"/>
</cross-domain-policy>
```

---

## Tools

| Tool               | Purpose                                              |
| ------------------- | ------------------------------------------------------ |
| **curl**             | Fetch and inspect `crossdomain.xml` / SWF files          |
| **swfdump / RABCDAsm** | Decompile SWF to inspect ActionScript for unsafe loads  |
| **Burp Suite**       | Intercept SWF loading and cross-domain policy requests    |

---

## Example Commands/Payloads

### Locate Flash content and policy files

```bash
TARGET="{target}"
curl -s "https://$TARGET" | grep -oP '[^"]+\.swf'
curl -s "https://$TARGET/crossdomain.xml"
curl -s "https://$TARGET/clientaccesspolicy.xml"
for path in /crossdomain.xml /clientaccesspolicy.xml /flash/crossdomain.xml; do
    curl -s "https://$TARGET$path"
done
```

### Vulnerable policy pattern to flag

```xml
<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="*"/>
</cross-domain-policy>
```

### Silverlight equivalent (clientaccesspolicy.xml) wildcard check

```xml
<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from http-request-headers="*">
        <domain uri="*"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
```

---

## Remediation

```xml
<!-- Restrict cross-domain access -->
<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
    <site-control permitted-cross-domain-policies="master-only"/>
    <allow-access-from domain="www.trusted.com" secure="true"/>
</cross-domain-policy>
```

---

## Risk Assessment

| Finding                  | CVSS | Severity |
| ------------------------ | ---- | -------- |
| Wildcard crossdomain.xml | 5.3  | Medium   |
| XSF vulnerability        | 6.1  | Medium   |


---

## CWE Categories

| CWE ID | Title | Description |
| --- | --- | --- |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | Flash movie makes state-changing cross-domain requests without origin verification |
| **CWE-346** | Origin Validation Error | Missing/misconfigured crossdomain.xml allows untrusted domains to interact with the SWF |

---

## References

- [OWASP WSTG - Testing for Cross Site Flashing (WSTG-CLNT-08)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Site_Flashing)
- [Adobe - Cross-domain policy file specification](https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html)
- [OWASP Testing for Flash Guide (legacy)](https://owasp.org/www-project-web-security-testing-guide/)

---

## Checklist

```
[ ] Flash files identified
[ ] crossdomain.xml analyzed
[ ] SWF parameters tested
[ ] clientaccesspolicy.xml checked
[ ] Findings documented
```
