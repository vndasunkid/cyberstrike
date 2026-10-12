---
name: wstg-info-01
description: "Conduct Search Engine Discovery Reconnaissance for Information Leakage"
category: information-gathering
owasp_id: WSTG-INFO-01
version: "1.0.0"
author: cyberstrike-official
tags: [recon, fingerprint, enumeration, wstg, info]
tech_stack: []
cwe_ids: [CWE-200]
chains_with: [wstg-info-06, wstg-conf-01]
prerequisites: []
severity_boost: {}
---

# wstg-info-01

## Test ID

WSTG-INFO-01

## Test Name

Conduct Search Engine Discovery Reconnaissance for Information Leakage

## High-Level Description

This test aims to identify sensitive information about the target organization that has been unintentionally exposed on the internet through search engines and cache services. When search engines index web pages, they may also index sensitive configuration files, internal documentation, user information, and other confidential data. This test gathers OSINT (Open Source Intelligence) from an attacker's perspective to uncover potential security risks.

---

## What to Check

### Information Types to Investigate

- [ ] Network diagrams and configuration information
- [ ] Archived posts by administrators/personnel
- [ ] Login procedure information
- [ ] Username formats and email addresses
- [ ] Error message content (stack traces, debug info)
- [ ] Development, test, or staging environment URLs
- [ ] Third-party/cloud service configurations
- [ ] Credentials (passwords, API keys, secret keys)
- [ ] Private keys and certificates
- [ ] Backup files
- [ ] Source code snippets
- [ ] Database dumps
- [ ] Internal IP addresses and hostnames
- [ ] VPN and remote access configuration details

---

## How to Test

### Step 4: Historical Data Analysis (Wayback Machine)

1. Navigate to https://web.archive.org
2. Enter the target URL
3. Review past snapshots
4. Search for sensitive pages that no longer exist but were previously available
5. Check robots.txt changes (previously restricted paths)

### Step 5: Shodan and IoT Device Search

```
# Shodan Queries
hostname:target.com
org:"Target Organization"
ssl.cert.subject.cn:target.com
http.title:"Target Application"
```

### Step 7: Pastebin and Leak Sites

- Pastebin.com
- Ghostbin
- Hastebin
- Have I Been Pwned (HIBP)

---

## Tools

### Automated Tools

| Tool                     | Description                      | Installation/Usage                        |
| ------------------------ | -------------------------------- | ----------------------------------------- |
| **Recon-ng**             | Web reconnaissance framework     | `recon-ng`                                |
| **Maltego**              | OSINT and link analysis          | GUI tool                                  |
| **SpiderFoot**           | Automated OSINT                  | `spiderfoot -s target.com`                |
| **Photon**               | Web crawler                      | `python3 photon.py -u https://target.com` |
| **Amass**                | Subdomain enumeration            | `amass enum -d target.com`                |
| **Subfinder**            | Subdomain discovery              | `subfinder -d target.com`                 |

### Online Services

| Service         | URL                | Purpose                  |
| --------------- | ------------------ | ------------------------ |
| Wayback Machine | web.archive.org    | Historical data          |
| Shodan          | shodan.io          | IoT/device search        |
| Censys          | censys.io          | Internet-wide scanning   |
| VirusTotal      | virustotal.com     | Domain intelligence      |
| SecurityTrails  | securitytrails.com | DNS history              |
| DNSDumpster     | dnsdumpster.com    | DNS recon                |
| crt.sh          | crt.sh             | Certificate transparency |

---

## Example Commands/Payloads

### theHarvester Commands

```bash
# Passive sources only (no search engines)
theHarvester -d target.com -b crtsh,hackertarget,dnsdumpster
```

### Amass Commands

```bash
# Passive enumeration
amass enum -passive -d target.com

# Active enumeration
amass enum -active -d target.com

# With brute force
amass enum -brute -d target.com -w wordlist.txt

# Save results
amass enum -d target.com -o results.txt
```

### Subfinder Commands

```bash
# Basic usage
subfinder -d target.com

# Verbose output
subfinder -d target.com -v

# Output to file
subfinder -d target.com -o subdomains.txt

# Recursive search
subfinder -d target.com -recursive
```

### Shodan CLI

```bash
# Authenticate with API key
shodan init YOUR_API_KEY

# Host search
shodan host target_ip

# Search
shodan search hostname:target.com

# Specific port
shodan search hostname:target.com port:22
```

### crt.sh (Certificate Transparency)

```bash
# Fetch subdomains with curl
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

---

## Remediation Guide

### Preventive Measures

1. **Sensitive Information Publication Policy**
   - Evaluate the sensitivity level of all information before publishing online
   - Never share production environment details on public resources

2. **robots.txt Configuration**

   ```
   User-agent: *
   Disallow: /admin/
   Disallow: /config/
   Disallow: /backup/
   Disallow: /private/
   Disallow: /*.sql$
   Disallow: /*.bak$
   ```

   > **Note**: robots.txt does not provide security, it only guides well-behaved bots

3. **Meta Tag Usage**

   ```html
   <meta name="robots" content="noindex, nofollow" />
   ```

4. **Authentication Controls**
   - Require authentication for sensitive pages
   - Implement IP-based access restrictions

5. **Search Engine Removal Tools**
   - Google: Search Console > Removals
   - Bing: Webmaster Tools > Content Removal
   - Use respective webmaster tools for other engines

6. **Regular Audits**
   - Periodically perform OSINT scans on your own organization
   - Detect new leaks early

7. **Employee Training**
   - Awareness about social media and forum usage
   - Sensitive information sharing policies

### Remediating Detected Leaks

1. Remove sensitive content from the source system
2. Request removal from search engines
3. Request removal from Wayback Machine (info@archive.org)
4. If credentials are leaked, immediately rotate passwords/keys
5. Initiate incident response procedures

---

## Risk Assessment

### CVSS Score

**Base Score**: 5.3 (Medium)

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

| Metric              | Value     | Description                    |
| ------------------- | --------- | ------------------------------ |
| Attack Vector       | Network   | Accessible via internet        |
| Attack Complexity   | Low       | No special skills required     |
| Privileges Required | None      | No authentication needed       |
| User Interaction    | None      | No user interaction required   |
| Scope               | Unchanged | Impact scope unchanged         |
| Confidentiality     | Low       | Limited information disclosure |
| Integrity           | None      | No integrity impact            |
| Availability        | None      | No availability impact         |

> **Note**: CVSS score may vary based on the sensitivity of discovered information. Credential leaks can significantly increase the score (High/Critical).

### Severity Levels

| Discovered Information    | Severity | Example                           |
| ------------------------- | -------- | --------------------------------- |
| General info, public data | Info     | Company address, general contact  |
| Internal configuration    | Low      | Subdomain list                    |
| Potential attack vector   | Medium   | Admin panel URL, technology stack |
| Credential information    | High     | API key, password                 |
| Critical system access    | Critical | Private key, admin credentials    |

---

## CWE Categories

| CWE ID      | Title                                                                           | Description                                                 |
| ----------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor                      | Disclosure of sensitive information to unauthorized parties |
| **CWE-538** | Insertion of Sensitive Information into Externally-Accessible File or Directory | Adding sensitive info to externally accessible files        |
| **CWE-359** | Exposure of Private Personal Information to an Unauthorized Actor               | Disclosure of personal information to unauthorized parties  |
| **CWE-312** | Cleartext Storage of Sensitive Information                                      | Storing sensitive information without encryption            |
| **CWE-615** | Inclusion of Sensitive Information in Source Code Comments                      | Sensitive information in source code comments               |

---

## References

### OWASP References

- [OWASP WSTG - Search Engine Discovery](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Tools

- [theHarvester](https://github.com/laramies/theHarvester)
- [Amass](https://github.com/OWASP/Amass)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
- [SpiderFoot](https://github.com/smicallef/spiderfoot)

### Other Resources

- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- [Shodan](https://www.shodan.io/)
- [Wayback Machine](https://web.archive.org/)
- [Certificate Transparency - crt.sh](https://crt.sh/)


---

## Checklist

```
[ ] DuckDuckGo search queries executed
[ ] Shodan scan performed
[ ] Wayback Machine historical analysis completed
[ ] theHarvester OSINT gathered
[ ] Subdomain enumeration performed (Amass/Subfinder)
[ ] Certificate transparency check completed (crt.sh)
[ ] Pastebin/leak site check completed
[ ] Discovered sensitive information documented
[ ] Risk assessment completed
[ ] Remediation recommendations prepared
```
