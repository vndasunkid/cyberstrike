---
name: wstg-info-09
description: "Fingerprint Web Application"
category: information-gathering
owasp_id: WSTG-INFO-09
version: "1.0.0"
author: cyberstrike-official
tags: [recon, fingerprint, enumeration, wstg, info]
tech_stack: []
cwe_ids: [CWE-200]
chains_with: [wstg-info-01, wstg-info-02]
prerequisites: []
severity_boost: {}
---

# wstg-info-09

## Test ID

WSTG-INFO-09

## Test Name

Fingerprint Web Application

## Status

> **Note**: This test case has been merged into **WSTG-INFO-08: Fingerprint Web Application Framework** in the latest OWASP WSTG version.

## Consolidated Reference

For comprehensive guidance on web application fingerprinting, including:

- Application identification techniques
- Version detection methods
- Technology stack analysis
- Custom application identification

Please refer to: **[WSTG-INFO-08: Fingerprint Web Application Framework](./WSTG-INFO-08.md)**

---

## Additional Application-Specific Fingerprinting

While WSTG-INFO-08 covers framework fingerprinting, consider these additional checks for custom/bespoke applications:

### Custom Application Indicators

- [ ] Unique URL patterns
- [ ] Custom HTTP headers
- [ ] Application-specific cookies
- [ ] Proprietary JavaScript libraries
- [ ] Custom error messages
- [ ] Unique HTML structures
- [ ] Versioning in source code comments

### Version Detection Techniques

```bash
# Check for version in common locations
curl -s https://target.com/version
curl -s https://target.com/api/version
curl -s https://target.com/health
curl -s https://target.com/info
curl -s https://target.com/about

# Check for build info in HTML comments
curl -s https://target.com | grep -iE 'version|build|release'

# Check JavaScript for version strings
curl -s https://target.com/app.js | grep -iE 'version|v[0-9]+\.[0-9]+'
```

### Documentation

When fingerprinting custom applications, document:

1. **Application Name**: Official name and any aliases
2. **Version Information**: If discoverable
3. **Vendor/Developer**: Who built the application
4. **Deployment Date**: If identifiable
5. **Technology Stack**: Underlying frameworks and libraries
6. **Known CVEs**: Research based on identified versions


---

## Tools

| Tool             | Description                                   | Usage                                             |
| ---------------- | ---------------------------------------------- | -------------------------------------------------- |
| **Wappalyzer**   | Technology/CMS/JS-library fingerprinting (CLI/browser ext) | `wappalyzer https://target.com`        |
| **whatweb**      | Web technology fingerprinter                  | `whatweb -a 3 target.com`                          |
| **curl**         | Manual header/banner grabbing                 | `curl -sI https://target.com`                      |
| **BuiltWith**    | Online technology profiler                    | Web-based                                          |
| **Nikto**        | Server banner + fingerprint checks            | `nikto -h https://target.com`                      |
| **httpx**        | Fast HTTP probing with tech detection         | `httpx -u target.com -title -server -tech-detect`  |

---

## Example Commands/Payloads

```bash
TARGET="target.com"

# Wappalyzer CLI - technology stack, CMS, JS libraries, analytics
wappalyzer "https://$TARGET" --pretty

# whatweb - aggressive fingerprinting (level 3) with version detection
whatweb -a 3 -v "$TARGET"

# httpx - quick tech-detect + title + server banner across a list of hosts
echo "$TARGET" | httpx -title -server -tech-detect -status-code

# curl - manual banner grabbing from response headers
curl -sI "https://$TARGET" | grep -iE 'server|x-powered-by|x-aspnet-version|x-generator'

# Grab custom/app-specific version strings from common endpoints
for path in /version /api/version /health /info /about /humans.txt; do
  echo "=== $path ==="
  curl -s "https://$TARGET$path"
done

# Search rendered HTML/JS for build/version comments and custom cookies
curl -s "https://$TARGET" | grep -iE '<!--.*(version|build|release).*-->'
curl -sI "https://$TARGET" | grep -i 'set-cookie'
curl -s "https://$TARGET/app.js" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+'
```

**Result patterns indicating a finding:**
- Wappalyzer/whatweb/httpx return a named CMS, framework, or library with a specific version number → confirms application fingerprint, cross-reference against known CVEs
- `Server:`/`X-Powered-By:`/`X-Generator:` headers leak stack + version → direct fingerprint without active scanning
- `/version`, `/api/version`, `/health`, `/info` endpoints return JSON/plaintext with a build number or commit hash → precise version disclosure
- HTML comments or `app.js` contain `vX.Y.Z` strings or internal build identifiers → source-level version leakage
- Application-specific `Set-Cookie` names (e.g. `JSESSIONID`, `PHPSESSID`, custom `APPNAME_session`) → framework/app identification via cookie naming convention

---

## References

- [OWASP WSTG-INFO-08: Fingerprint Web Application Framework](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
- [Wappalyzer](https://www.wappalyzer.com/)
- [whatweb (GitHub)](https://github.com/urbanadventurer/WhatWeb)
- [httpx (ProjectDiscovery)](https://github.com/projectdiscovery/httpx)
- [BuiltWith](https://builtwith.com/)

---

## Checklist

```
[ ] See WSTG-INFO-08 checklist for comprehensive fingerprinting steps
[ ] Custom application identifiers documented
[ ] Version information gathered
[ ] Vendor/developer identified
[ ] Known vulnerabilities researched
```
