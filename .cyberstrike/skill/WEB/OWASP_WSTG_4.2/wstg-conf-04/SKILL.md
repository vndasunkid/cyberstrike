---
name: wstg-conf-04
description: "Review Old Backup and Unreferenced Files for Sensitive Information"
category: configuration
owasp_id: WSTG-CONF-04
version: "1.0.0"
author: cyberstrike-official
tags: [misconfiguration, hardening, server, wstg, conf]
tech_stack: []
cwe_ids: [CWE-16]
chains_with: [wstg-conf-01, wstg-conf-02]
prerequisites: []
severity_boost:
  wstg-conf-01: "Backup File Credential Leak + Exposed Admin Interface = Full System Takeover (Critical)"
---

# wstg-conf-04

## Test ID

WSTG-CONF-04

## Test Name

Review Old Backup and Unreferenced Files for Sensitive Information

## High-Level Description

Old backup files, unreferenced pages, and forgotten content can expose sensitive information including source code, credentials, and outdated vulnerable functionality. These files often contain debugging information, database credentials, or reveal application logic that aids attackers. This test focuses on discovering such files through inference, brute-forcing, and examining publicly available information.

---

## What to Check

### File Types to Discover

- [ ] Backup files (.bak, .old, .backup, ~)
- [ ] Temporary files (.tmp, .swp, .temp)
- [ ] Archive files (.zip, .tar, .gz, .rar)
- [ ] Editor files (.bak, ~, .orig)
- [ ] Unreferenced pages
- [ ] Old versions of files
- [ ] Development/test files
- [ ] Snapshot directories
- [ ] Log files
- [ ] Database dumps

### Naming Conventions

| Pattern       | Description       |
| ------------- | ----------------- |
| file~         | Emacs backup      |
| file.bak      | Generic backup    |
| file.old      | Old version       |
| file.orig     | Original version  |
| file.save     | Saved version     |
| file.swp      | Vim swap file     |
| file.tmp      | Temporary file    |
| Copy of file  | Manual copy       |
| file (1).ext  | Duplicate         |
| file_backup   | Backup naming     |
| file_YYYYMMDD | Date-based backup |

---

## How to Test

### Step 1: Inference from Naming Schemes

```bash
# If you find viewuser.asp, try:
files=("edituser.asp" "adduser.asp" "deleteuser.asp"
       "listuser.asp" "createuser.asp" "updateuser.asp"
       "modifyuser.asp" "removeuser.asp")

for file in "${files[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$file")
    echo "$file: $status"
done
```

### Step 2: Test Backup Extensions

```bash
#!/bin/bash
TARGET=$1
FILE=$2  # e.g., config.php

# Backup extensions
extensions=(
    ".bak" ".backup" ".old" ".orig" ".save" ".swp" ".tmp"
    ".copy" ".1" ".2" "~" "_backup" "_old" "_bak"
    ".txt" ".src" ".inc" ".dev" ".test"
    "-backup" "-old" "-copy" ".BACKUP" ".BAK"
)

for ext in "${extensions[@]}"; do
    test_file="${FILE}${ext}"
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$test_file")
    if [ "$status" == "200" ]; then
        echo "[FOUND] $test_file"
    fi
done

# Also test prefix patterns
prefixes=("backup_" "old_" "copy_" "bak_" "." "_")
for prefix in "${prefixes[@]}"; do
    test_file="${prefix}${FILE}"
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$test_file")
    if [ "$status" == "200" ]; then
        echo "[FOUND] $test_file"
    fi
done
```

### Step 3: Archive File Discovery

```bash
# Common archive files
archives=(
    "backup.zip" "backup.tar.gz" "backup.tar" "backup.rar"
    "site.zip" "www.zip" "html.zip" "web.zip"
    "database.sql" "db.sql" "dump.sql" "backup.sql"
    "files.zip" "archive.zip" "old.zip"
)

for file in "${archives[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$file")
    if [ "$status" == "200" ]; then
        echo "[CRITICAL] Archive found: $file"
    fi
done

# Date-based backups
for year in 2023 2024 2025; do
    for month in 01 02 03 04 05 06 07 08 09 10 11 12; do
        file="backup_${year}${month}.zip"
        status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$file")
        if [ "$status" == "200" ]; then
            echo "[FOUND] $file"
        fi
    done
done
```

### Step 4: Source Code Review

```bash
# Look in HTML source for hidden links
curl -s https://target.com | grep -oP 'href="[^"]*"' | sort -u

# Look for commented code
curl -s https://target.com | grep -oP '<!--.*?-->'

# Look in JavaScript
curl -s https://target.com | grep -oP 'src="[^"]*\.js[^"]*"' | while read js; do
    curl -s "https://target.com$js" | grep -iE 'admin|backup|test|dev|hidden'
done
```

### Step 5: Robots.txt Analysis

```bash
# Check robots.txt for hidden paths
curl -s https://target.com/robots.txt

# Test disallowed paths
curl -s https://target.com/robots.txt | grep "Disallow" | awk '{print $2}' | while read path; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    echo "$path: $status"
done
```

### Step 6: Search Engine Discovery

```
# Google dorks for backups
site:target.com filetype:bak
site:target.com filetype:sql
site:target.com filetype:zip
site:target.com filetype:tar
site:target.com filetype:old
site:target.com "index of" backup
site:target.com inurl:backup
site:target.com intitle:"index of" "backup"
```

### Step 7: Directory Brute-forcing

```bash
# Gobuster
gobuster dir -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -x bak,old,backup,zip,tar,gz,sql,tmp \
    -o backup_scan.txt

# ffuf
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/backup-filenames.txt \
    -mc 200
```

### Step 8: Snapshot Directory Check

```bash
# Common snapshot paths
snapshots=(
    "/.snapshot/"
    "/.snap/"
    "/~snapshot/"
    "/backup/"
    "/backups/"
    "/old/"
    "/archive/"
    "/archived/"
)

for path in "${snapshots[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    if [ "$status" != "404" ]; then
        echo "Potential snapshot: $path - Status: $status"
    fi
done
```

---

## Tools

### Directory/File Scanners

| Tool          | Description           | Usage                                        |
| ------------- | --------------------- | -------------------------------------------- |
| **Gobuster**  | Directory brute-force | `gobuster dir -u url -w wordlist -x bak,old` |
| **ffuf**      | Fast fuzzer           | `ffuf -u url/FUZZ -w wordlist`               |
| **Dirb**      | Directory scanner     | `dirb https://target.com`                    |
| **Dirsearch** | Web path scanner      | `dirsearch -u target.com`                    |

### Web Spiders

| Tool            | Description        |
| --------------- | ------------------ |
| **wget**        | Recursive download |
| **HTTrack**     | Website copier     |
| **Burp Spider** | Web crawler        |

### Vulnerability Scanners

| Tool       | Description            |
| ---------- | ---------------------- |
| **Nikto**  | Web server scanner     |
| **Nessus** | Vulnerability scanner  |
| **Nuclei** | Template-based scanner |

---

## Example Commands/Payloads

### Comprehensive Backup Scanner

```bash
#!/bin/bash
TARGET=$1

echo "=== BACKUP FILE SCANNER ==="
echo "Target: $TARGET"

# Wordlist of common backup files
backup_files=(
    "backup.zip" "backup.tar.gz" "backup.sql" "database.sql"
    "site.zip" "www.zip" "html.zip" "web.zip"
    "db_backup.sql" "dump.sql" "data.sql"
    "config.php.bak" "wp-config.php.bak" ".htaccess.bak"
    "web.config.bak" "config.yml.bak"
)

# Test each file
for file in "${backup_files[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$file")
    if [ "$status" == "200" ]; then
        size=$(curl -sI "https://$TARGET/$file" | grep -i content-length | awk '{print $2}' | tr -d '\r')
        echo "[CRITICAL] Found: $file (Size: $size bytes)"
    fi
done

# Test common directories with date patterns
echo ""
echo "[+] Testing date-based backups..."
current_year=$(date +%Y)
for year in $((current_year-1)) $current_year; do
    for month in {01..12}; do
        for ext in zip tar.gz sql; do
            file="backup-${year}-${month}.$ext"
            status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$file")
            if [ "$status" == "200" ]; then
                echo "[FOUND] $file"
            fi
        done
    done
done

echo "[+] Scan complete"
```

### Exposed Version Control Folders - Git/SVN/Mercurial/Bazaar Dumping (from PayloadsAllTheThings)

Leftover `.git`, `.svn`, `.hg`, or `.bzr` directories in the web root let an attacker reconstruct the entire source history, even without directory listing enabled:

```bash
# Check for the tell-tale files first
for f in .git/config .git/HEAD .git/logs/HEAD .svn/entries .svn/wc.db .hg/dirstate .hg/requires .bzr/README .bzr/branch/format; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://{target}/$f")
    echo "$f: $status"
done

# Automated full dump with git-dumper (works even when only single objects are fetchable, no listing needed)
pip install -r requirements.txt
python3 git-dumper.py https://{target}/.git ./dumped_repo

# Manual recovery from .git/logs/HEAD when git-dumper is blocked
curl -s https://{target}/.git/logs/HEAD
# Take a commit hash from the log, fetch the object (first 2 chars = subdir, rest = filename)
curl -s https://{target}/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c -o obj
mkdir -p .git/objects/26 && mv obj .git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c   # reveals tree/parent/commit message
```

Recover file names/hashes from `.git/index` (works even without the reflog) using the `gin` index parser, then repeat the object-fetch process above per file:

```bash
pip3 install gin
gin .git/index | egrep -e "name|sha1"
# name = config/database.yml
# sha1 = 862a3e58d138d6809405aa062249487bee074b98
```

#### Additional Git Dumping Tools

| Tool | Usage |
| ---- | ----- |
| **git-dumper** (arthaud/git-dumper) | `python3 git-dumper.py http://{target}/.git ~/website` |
| **GitTools** (internetwache/GitTools) | `./gitdumper.sh http://{target}/.git/ /tmp/destdir && git checkout -- .` |
| **GitHack** (lijiejie/GitHack) | `python2 GitHack.py http://{target}/.git/` |
| **diggit.py** (bl4de/security-tools) | `./diggit.py -u http://{target} -t /tmp/dest -o <object_hash>` |
| **GoGitDumper** (c-sto/gogitdumper) | `gogitdumper -u http://{target}/.git/ -o dest/.git/ && git log && git checkout` |
| **dvcs-ripper rip-git.pl** (kost/dvcs-ripper) | `perl rip-git.pl -v -u "http://{target}/.git/"` — also rips SVN/HG |

After dumping, run a secret scanner against the recovered working tree/history — commits removed from HEAD but still present in objects often contain credentials that were later "fixed":

```bash
trufflehog filesystem ./dumped_repo
gitleaks detect --source=./dumped_repo --no-git=false
```

#### Additional Secret-Harvesting Tools

| Tool | Purpose | Usage |
| ---- | ------- | ----- |
| **noseyparker** (praetorian-inc/noseyparker) | Regex/entropy secret scanner over any datastore/git history | `noseyparker scan --datastore np.datastore --git-url <repo_or_local_path>` then `noseyparker report --color always` |
| **Yar** (nielsing/yar) | Scans all repos of a user/org for secrets (regex + entropy) | `yar -o orgname --both` |
| **Gitrob** | Clones org/user repos and flags filenames matching sensitive-file signatures | `GITROB_ACCESS_TOKEN=<token> gitrob target1 target2` |

A reverse-proxy rule returning `403` instead of `404` for `/.git`/`/.svn` (e.g. Nginx `location /.git { deny all; }`) still confirms the folder exists — worth noting even when direct dumping is blocked.

### Bazaar (.bzr) Dumping

Bazaar (bzr) repositories exposed under the web root can be reconstructed the same way as Git/SVN:

```bash
# Confirm exposure
curl -s https://{target}/.bzr/README
curl -s https://{target}/.bzr/branch/branch.conf
curl -s https://{target}/.bzr/branch/last-revision

# rip-bzr.pl (kost/dvcs-ripper) - dockerized
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-bzr.pl -v -u https://{target}/.bzr/

# bzr_dumper (SeahunOh/bzr_dumper) - pulls pack-names, checkout/dirstate, branch metadata, then object packs
python3 dumper.py -u "https://{target}/" -o source
# [+] GET repository/pack-names / checkout/dirstate / branch/branch.conf / branch/last-revision ...

# Restore the working tree from the dumped repo
cd source && bzr revert
#  N  application.py
#  N  database.py
#  N  static/
```

### Mercurial (.hg) Dumping

```bash
# Confirm exposure
curl -s https://{target}/.hg/requires
curl -s https://{target}/.hg/dirstate
curl -s https://{target}/.hg/store/00manifest.i

# rip-hg.pl (kost/dvcs-ripper) - rips SVN/GIT/HG alike, dockerized
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-hg.pl -v -u https://{target}/.hg/
```

After the rip completes, `hg log` / `hg update` against the recovered `.hg` store reveals commit history and working files — treat it the same as a recovered `.git` tree for secret scanning (trufflehog/gitleaks work on any VCS working directory, not just Git).

### Subversion (.svn) Dumping

```bash
# Confirm exposure and grab a single file directly (older SVN <1.7 layout)
curl -s https://{target}/.svn/text-base/wp-config.php.svn-base
curl -s https://{target}/.svn/entries

# Automated full dump - svn-extractor (anantshri/svn-extractor), works for the newer wc.db-based layout (SVN >=1.7)
python svn-extractor.py --url "https://{target}/.svn/"
```

Manual recovery from `.svn/wc.db` (SQLite database, SVN >= 1.7 working-copy format) when the extractor is blocked or you need a specific file:

```bash
# 1. Download the SQLite working-copy database
curl -s https://{target}/.svn/wc.db -o wc.db

# 2. Query the NODES table to find file paths + content SHA1
sqlite3 wc.db "SELECT local_relpath, checksum FROM NODES;"
# Example row: local_relpath='trunk/test.txt', checksum='$sha1$945a60e68acc693fcb74abadb588aac1a9135f62'

# 3. Rebuild the download path from the checksum:
#    - strip the "$sha1$" prefix
#    - append ".svn-base"
#    - use the first 2 hex chars of the hash as the pristine/ subdirectory
curl -s https://{target}/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base -o test.txt
```

This recovers file content even for files removed from the current working copy but still present in the local pristine cache — useful for finding old credentials/config that were later deleted.

### Nuclei Backup Templates

```bash
# Run backup-related templates
nuclei -u https://target.com -t http/exposures/backups/
nuclei -u https://target.com -t http/exposures/files/
```

---

## Remediation Guide

### 1. Remove All Backup Files

```bash
# Find and remove backup files
find /var/www/html -name "*.bak" -delete
find /var/www/html -name "*.backup" -delete
find /var/www/html -name "*.old" -delete
find /var/www/html -name "*~" -delete
find /var/www/html -name "*.swp" -delete
find /var/www/html -name "*.tmp" -delete

# Find archives
find /var/www/html -name "*.zip" -o -name "*.tar*" -o -name "*.sql"
```

### 2. Block Backup Extensions

```apache
# Apache
<FilesMatch "\.(bak|backup|old|orig|save|swp|tmp|sql|tar|gz|zip|rar)$">
    Require all denied
</FilesMatch>
```

```nginx
# Nginx
location ~* \.(bak|backup|old|orig|save|swp|tmp|sql|tar|gz|zip|rar)$ {
    deny all;
    return 404;
}
```

### 3. Configuration Management

- Never create backups in web-accessible directories
- Use version control (Git) instead of manual backups
- Implement automated deployment without manual file copying
- Store backups in secure, non-web-accessible locations

### 4. Monitoring

- Implement file integrity monitoring
- Alert on new backup file creation
- Regular audits for backup files

---

## Risk Assessment

### CVSS Score

| Finding                      | CVSS     | Severity |
| ---------------------------- | -------- | -------- |
| Source code backup exposed   | 7.5      | High     |
| Database dump accessible     | 9.8      | Critical |
| Config file with credentials | 9.8      | Critical |
| Old vulnerable page          | Variable | Variable |

**Typical Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

---

## CWE Categories

| CWE ID      | Title                          | Description                    |
| ----------- | ------------------------------ | ------------------------------ |
| **CWE-530** | Exposure of Backup File        | Backup accessible to attackers |
| **CWE-538** | Sensitive Information in Files | Sensitive data in public files |
| **CWE-200** | Information Exposure           | Information disclosure         |

---

## References

- [OWASP WSTG - Review Old Backup and Unreferenced Files](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)
- [SecLists Backup Filenames](https://github.com/danielmiessler/SecLists)
- [PayloadsAllTheThings - Insecure Source Code Management](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Source%20Code%20Management)
- [PayloadsAllTheThings - Git](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Source%20Code%20Management/Git.md)
- [PayloadsAllTheThings - Bazaar](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Source%20Code%20Management/Bazaar.md)
- [PayloadsAllTheThings - Mercurial](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Source%20Code%20Management/Mercurial.md)
- [PayloadsAllTheThings - Subversion](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Source%20Code%20Management/Subversion.md)


---

## Checklist

```
[ ] Backup extension scanning completed
[ ] Archive files checked (.zip, .tar, .sql)
[ ] Date-based backup patterns tested
[ ] Robots.txt paths tested
[ ] Search engine dorking performed
[ ] Source code reviewed for hidden links
[ ] Snapshot directories checked
[ ] Directory brute-forcing completed
[ ] Unreferenced pages identified
[ ] Sensitive files documented
[ ] Risk assessment completed
```
