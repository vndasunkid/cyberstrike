# CyberStrike Architecture & Behavior Guide

> Documentation audit — code is the source of truth. Every claim below cites a file (and line where useful). Where a statement is inferred rather than confirmed from code, it is marked **(inferred)**. Paths are relative to the repo root unless noted; most source lives under `packages/cyberstrike/src/`.

---

## 1. Overview

CyberStrike is an autonomous **offensive-security (penetration-testing) agent**, built as a hard fork/rename of SST's **OpenCode** AI coding agent. The OpenCode coding core (session loop, tool framework, provider abstraction, Hono server, SolidJS web UI, plugin system) is retained largely intact; on top of it CyberStrike adds a pentest domain layer: security-specialist agents, a per-vulnerability-class subagent fleet, a **methodology engine** (phase/coverage state machine), a **web-proxy testing pipeline** fed by an autonomous browser crawler, cloud/network/container post-exploitation tools, and a findings/reporting store. The rename is near-total — only two literal `opencode` strings remain in `packages/cyberstrike/src/` (a GitLab auth plugin import and a models.dev data blob). Its self-description: *"The first open-source AI agent built for offensive security"* ([README.md:35](README.md#L35)).

The system runs as a long-lived local server (`cyberstrike web` / `cyberstrike serve`) driving one or more LLM providers; a human interacts through a web UI or the CLI, and the agent plans and executes security testing against targets the operator points it at.

---

## 2. System Architecture

### Components

| Layer | Location | Role |
|---|---|---|
| CLI entry | [index.ts](packages/cyberstrike/src/index.ts) | yargs bootstrap; 23 subcommands (`web`, `serve`, `run`, `hackbrowser`, …) |
| HTTP server | [server/server.ts](packages/cyberstrike/src/server/server.ts) | Hono app on Bun.serve; auth gate; mounts session/project/… routes |
| Session engine | [session/prompt.ts](packages/cyberstrike/src/session/prompt.ts), [session/processor.ts](packages/cyberstrike/src/session/processor.ts), [session/llm.ts](packages/cyberstrike/src/session/llm.ts) | The agentic loop, tool dispatch, streaming model calls |
| Agent registry | [agent/agent.ts](packages/cyberstrike/src/agent/agent.ts) + `agent/prompt/*.txt` | Primary + subagent definitions and system prompts |
| Tool registry | [tool/registry.ts](packages/cyberstrike/src/tool/registry.ts), [tool/lazy-registry.ts](packages/cyberstrike/src/tool/lazy-registry.ts) | ~65 built-in tools + MCP + plugin tools |
| Methodology engine | [methodology/](packages/cyberstrike/src/methodology/) | Phase state machine, intel/VRT coverage, chains, agent scoring |
| Web-proxy pipeline | [session/web/](packages/cyberstrike/src/session/web/), `agent/prompt/orchestrator` + `vuln/*` | HTTP capture → analyze → per-class tester subagents → findings |
| Crawler | [packages/hackbrowser/](packages/hackbrowser/) | Playwright browser that crawls a target and streams captured requests |
| Providers | [provider/provider.ts](packages/cyberstrike/src/provider/provider.ts) | Anthropic subscription, OpenAI-compatible, vLLM/Ollama, models.dev |
| Config | [config/config.ts](packages/cyberstrike/src/config/config.ts) | Layered zod config (`cyberstrike.jsonc`) |
| Persistence | [storage/db.ts](packages/cyberstrike/src/storage/db.ts) + `*.sql.ts` | Bun SQLite via Drizzle at `~/.local/share/cyberstrike/cyberstrike.db` |
| Event bus | [bus/index.ts](packages/cyberstrike/src/bus/index.ts) | Pub/sub for state changes (the closest thing to an audit trail) |

### Data flow

```
 Operator (web UI / CLI run)
        │  POST /session/:id/message
        ▼
 ┌────────────────────────────────────────────────────────────────┐
 │  Hono server (server.ts) ── auth gate (CYBERSTRIKE_SERVER_PASSWORD)│
 └───────────────┬────────────────────────────────────────────────┘
                 ▼
      SessionPrompt.prompt → SessionPrompt.loop   (prompt.ts:170 / :299)
                 │   while(true) state machine (prompt.ts:333)
                 ▼
      SessionProcessor.process → LLM.stream → streamText  (processor.ts:46 / llm.ts:176)
                 │            ▲
      tool-call │            │ tool-result feeds back into message stream
                 ▼            │
      Tool registry ─────────┘   (bash, web_*, hackbrowser, task, report_vulnerability, …)
                 │
                 ├─► task tool ──► subagents (web-application, proxy-agent, proxy-tester-*, …)
                 │
                 ├─► hackbrowser tool ──► Playwright crawler ──► POST /session ingest ──► RequestTable
                 │
                 ├─► methodology engine (intel/VRT/phase/coverage) injected into system prompt
                 │
                 └─► report_vulnerability ──► VulnerabilityTable ──► generate_report (Markdown)
                 ▼
             SQLite (cyberstrike.db) + Event bus (permission.*, vulnerability.updated, web_*.updated)
```

### The web-proxy sub-pipeline (pentest core)

```
 hackbrowser crawl OR Firefox extension
        │  captured HTTP request (+ credential, + UI context)
        ▼
   RequestTable (normalized, dedup by key_hash)
        │  ingest → web-proxy-agent (orchestrator subagent)
        ▼
   proxy-analyzer subagent ── extracts objects / functions / roles / values
        │
        ▼   intelligent tester selection
   proxy-tester-{idor,authz,injection,authn,ssrf,file-attacks,mass-assignment,business-logic,llm}
        │  each locked to its own vuln class (vuln-scope.ts)
        ▼
   report_vulnerability → VulnerabilityTable
        │
   new role / object-value / credential  ──► WebRetest.checkTriggers ──► web_retest_queue
        └─► enqueueRetests() auto-drains queue (session.ts, uncommitted change)
```

---

## 3. Execution Flow (one task lifecycle)

References are to real functions; the control-flow spine is:
`index.ts → web/serve → Server.listen → POST /session/:id/message → SessionPrompt.prompt → SessionPrompt.loop → SessionProcessor.process → LLM.stream/streamText`.

1. **Startup.** [index.ts:49](packages/cyberstrike/src/index.ts#L49) builds the yargs parser; a `.middleware` initializes logging and runs a one-time JSON→SQLite migration ([index.ts:96](packages/cyberstrike/src/index.ts#L96)). `cyberstrike web` ([cli/cmd/web.ts:31](packages/cyberstrike/src/cli/cmd/web.ts#L31)) requires `CYBERSTRIKE_SERVER_PASSWORD`, calls `Server.listen(opts)`, and blocks forever ([web.ts:83](packages/cyberstrike/src/cli/cmd/web.ts#L83)). `serve` is the same, headless (`webUI:false`). The CLI `run` command is a thin client that spins up/attaches to the server and drives it over the SDK (`sdk.session.prompt`, [run.ts:599](packages/cyberstrike/src/cli/cmd/run.ts#L599)) — it does **not** run the loop in-process.

2. **Task reception (API).** `Server.listen` ([server.ts:675](packages/cyberstrike/src/server/server.ts#L675)) builds a Hono app on `Bun.serve` (default port 4096). A basic-auth middleware ([server.ts:115](packages/cyberstrike/src/server/server.ts#L115)) trusts local requests and requires the password for remote ones. Objectives enter through session routes ([server/routes/session.ts](packages/cyberstrike/src/server/routes/session.ts)):
   - `POST /:sessionID/message` (`session.prompt`) → `SessionPrompt.prompt` ([session.ts:2006](packages/cyberstrike/src/server/routes/session.ts#L2006)) — the normal chat/objective path.
   - `POST /:sessionID` ingest ("send a message as if from user input", [session.ts:1133](packages/cyberstrike/src/server/routes/session.ts#L1133)) — the cross-service/crawler injection path.
   - `POST /:sessionID/abort` → `SessionPrompt.cancel` ([session.ts:1595](packages/cyberstrike/src/server/routes/session.ts#L1595)).

3. **Planning / the agentic loop.** `SessionPrompt.prompt` ([prompt.ts:170](packages/cyberstrike/src/session/prompt.ts#L170)) records the user message and calls `loop`. The loop is a **stream-derived `while(true)` state machine** ([prompt.ts:333](packages/cyberstrike/src/session/prompt.ts#L333)) — not a fixed-iteration ReAct counter; each pass re-derives state (`lastUser`/`lastAssistant`/`lastFinished`, pending compaction/subtask) by scanning the message stream. Concurrency is serialized: a second caller for the same session parks on a callback queue rather than starting a second loop ([prompt.ts:250-308](packages/cyberstrike/src/session/prompt.ts#L250-L308)). This is a plan-as-you-go ReAct-style agent — planning is emergent from the model, steered by the injected methodology context, not a separate planner module **(inferred from loop structure + prompt injection at [prompt.ts:768](packages/cyberstrike/src/session/prompt.ts#L768))**.

4. **Tool selection & invocation.** Each turn resolves the agent's tool set (`resolveTools`, [prompt.ts:1028](packages/cyberstrike/src/session/prompt.ts#L1028)), assembles the system prompt (environment + instructions + methodology context + MCP/skill awareness, [prompt.ts:759-838](packages/cyberstrike/src/session/prompt.ts#L759-L838)), then calls `SessionProcessor.process` ([processor.ts:46](packages/cyberstrike/src/session/processor.ts#L46)), which streams `LLM.stream` → Vercel AI SDK `streamText` ([llm.ts:176](packages/cyberstrike/src/session/llm.ts#L176)). Streamed events (`tool-call`, `tool-result`, `tool-error`, `finish-step`) are handled in the processor's inner `while(true)` ([processor.ts:50](packages/cyberstrike/src/session/processor.ts#L50)). Subagents are launched via the `task` tool.

5. **Observation feedback.** Tool results are persisted as message parts ([processor.ts:181](packages/cyberstrike/src/session/processor.ts#L181)) and become part of the message stream the loop re-reads next pass — that stream *is* the working memory. Longer-lived state lives in SQLite (intel, coverage, objects/roles, findings) and is re-summarized into the system prompt via the methodology engine each turn.

6. **Termination.** Multiple layers, by design:
   - **Natural finish** — last assistant message stopped with a non-`tool-calls` reason → break ([prompt.ts:357-368](packages/cyberstrike/src/session/prompt.ts#L357-L368)).
   - **Hard step backstop (Layer 1)** — `if (step > maxSteps) break` ([prompt.ts:643](packages/cyberstrike/src/session/prompt.ts#L643)); the wrap-up turn strips all tools so the model must emit text.
   - **Stuck/repeat detectors (Layer 2/2b)** — for native subagents only, a `StuckDetector` (monologue rule, disabled by default) and a `RepeatDetector(3)` catch identical repeated tool calls ([prompt.ts:947-989](packages/cyberstrike/src/session/prompt.ts#L947-L989)); an in-turn `DOOM_LOOP_THRESHOLD = 3` guard raises a `doom_loop` permission ask ([processor.ts:21](packages/cyberstrike/src/session/processor.ts#L21), [:155](packages/cyberstrike/src/session/processor.ts#L155)).
   - **Processor stop** — `blocked` (permission denial) or model error → `return "stop"` ([processor.ts:430-431](packages/cyberstrike/src/session/processor.ts#L430-L431)).
   - **Context overflow** is *not* a terminator — it routes to compaction (`return "compact"`, [processor.ts:429](packages/cyberstrike/src/session/processor.ts#L429)), handled at three points: processor `finish-step`/`ContextOverflowError` ([processor.ts:297](packages/cyberstrike/src/session/processor.ts#L297)/[:371](packages/cyberstrike/src/session/processor.ts#L371)), the loop's post-finish overflow check ([prompt.ts:620](packages/cyberstrike/src/session/prompt.ts#L620)), and a pre-flight 95%-of-limit guard ([prompt.ts:847-871](packages/cyberstrike/src/session/prompt.ts#L847-L871)). Compaction summarizes history via a dedicated `compaction` agent ([compaction.ts:103](packages/cyberstrike/src/session/compaction.ts#L103)). *(Known failure mode: a model whose config omits `limit.context` reports context `0`, disabling the pre-flight guard and causing an infinite compact-retry loop — see §8.)*
   - The pentest agents additionally have a **"forced continuation" protocol** in their prompt (`agent/prompt/methodology/forced-continuation.txt`) instructing them not to stop until methodology completion >50% and VRT coverage >30% — a *soft*, prompt-level completion criterion layered on top of the hard loop backstops.

7. **Output.** Findings are written to `VulnerabilityTable` via the `report_vulnerability` tool; a human-readable **Markdown** report is produced on demand by `generate_report` (§4/§6). Every state change also emits a bus event.

---

## 4. Tools & Capabilities

Tools are `Tool.define(id, {...})` modules in [tool/](packages/cyberstrike/src/tool/), auto-discovered by [registry.ts:74-92](packages/cyberstrike/src/tool/registry.ts#L74-L92) (glob `{tool,tools}/*.{js,ts}`), extended by MCP servers and plugins. ~65 built-in tool ids exist. Selected/representative tools:

| Tool | Purpose | Inputs (key params) | Output | File |
|---|---|---|---|---|
| `bash` | Run shell commands (nmap, curl, sqlmap, etc.) | `command`, `timeout` | stdout/stderr | [tool/bash.ts](packages/cyberstrike/src/tool/bash.ts) |
| `webfetch` | Fetch a URL (5 MB cap, 30s/120s timeout) | `url`, `format` | page content | [tool/webfetch.ts](packages/cyberstrike/src/tool/webfetch.ts) |
| `websearch` / `codesearch` | Web / code search | `query` | results | [tool/websearch.ts](packages/cyberstrike/src/tool/websearch.ts) |
| `task` | Launch a subagent | `subagent_type`, `prompt` | subagent result | [tool/task.ts](packages/cyberstrike/src/tool/task.ts) |
| `read`/`write`/`edit`/`multiedit`/`apply_patch`/`glob`/`grep`/`ls` | Filesystem + code editing (inherited from OpenCode) | paths/patterns | file content/diffs | [tool/](packages/cyberstrike/src/tool/) |
| `hackbrowser` | Autonomously crawl a target, capture HTTP + UI context (async) | `target` (URL), `credentials[]`, `scope[]`, `exclude[]` | starts background crawl | [tool/hackbrowser.ts](packages/cyberstrike/src/tool/hackbrowser.ts) |
| `attack_script` | Curated exploit helpers (16 scripts) | `script` name + script args | script output/JSON | [tool/attack-script.ts](packages/cyberstrike/src/tool/attack-script.ts) |
| `inject_probe` | Injection probing (large; ~89 KB) | payload/target params | probe results | [tool/inject-probe.ts](packages/cyberstrike/src/tool/inject-probe.ts) |
| `scope_check` | **Advisory** in-scope check (domain/wildcard/CIDR) | `target`, `scope_items[]` | in/out-of-scope + WARNING string | [tool/scope-check.ts](packages/cyberstrike/src/tool/scope-check.ts) |
| `add_intel` | Log a discovery; auto-creates a VRT checklist | `type`, `title`, `asset`, `severity`, `detail` | intel entry | [tool/intel.ts](packages/cyberstrike/src/tool/intel.ts) |
| `update_vrt_check` / `methodology_status` | Track VRT coverage / phase progress | check id / — | coverage state | [tool/vrt-check.ts](packages/cyberstrike/src/tool/vrt-check.ts), [tool/methodology-status.ts](packages/cyberstrike/src/tool/methodology-status.ts) |
| `record_coverage_note`/`get_coverage_notes` | Free-form coverage notes | note text | stored/listed notes | [tool/coverage-note.ts](packages/cyberstrike/src/tool/coverage-note.ts) |
| `report_vulnerability` | Record a finding (severity-capped w/o evidence) | `severity`, `title`, `description`, `cwe_id`, `poc`, `execution_evidence`, `vrt_category` | stored finding | [tool/vulnerability.ts](packages/cyberstrike/src/tool/vulnerability.ts) |
| `triage_vulnerability` | Approve or mark a finding duplicate | id, `approved`/`duplicate`+`duplicate_of` | updated status | [tool/triage-vulnerability.ts](packages/cyberstrike/src/tool/triage-vulnerability.ts) |
| `generate_report` | Build final Markdown report | (session) | Markdown report string | [tool/generate-report.ts](packages/cyberstrike/src/tool/generate-report.ts) |
| `web_write_object`/`web_write_object_value`/`web_write_function`/`web_write_role`/`web_update_credential_claims` | Populate the web app model (objects/values/functions/roles/creds) | entity fields | writes + retest triggers | [tool/web-write-*.ts](packages/cyberstrike/src/tool/) |
| `web_get_session_context`/`web_get_vulnerabilities`/`web_get_detail`/`web_get_request_detail`/`web_get_vuln_detail` | Read-side of the web model | filters | JSON context | [tool/web-get-*.ts](packages/cyberstrike/src/tool/) |
| `cloud_audit`/`k8s_audit`/`ci_audit` | Read-only cloud/K8s/CI/CD security audits | program name | findings | [tool/cloud-audit.ts](packages/cyberstrike/src/tool/cloud-audit.ts), [tool/k8s-audit.ts](packages/cyberstrike/src/tool/k8s-audit.ts), [tool/ci-audit.ts](packages/cyberstrike/src/tool/ci-audit.ts) |
| `linuxhook`/`winhook`/`machook`/`awshook`/`azurehook`/`gcphook`/`kubehook`/`containerhook`/`iachook`/`llmhook` | Post-exploitation / hook suites (e.g. linuxhook = 120 programs across recon, cred-harvest, privesc, persistence, lateral, evasion, exfil) | `program` + args | program output | [tool/](packages/cyberstrike/src/tool/), [CHANGELOG.md](CHANGELOG.md) |
| `ensure_tools` | Install missing CLI tools (nmap, nuclei, …) | tool names | install result | [tool/ensure-tools.ts](packages/cyberstrike/src/tool/ensure-tools.ts) |
| `tool_search`/`load_tools`/`unload_tools`/`list_loaded_tools` | Lazy MCP-tool management | query/names | tool list | [tool/tool-search.ts](packages/cyberstrike/src/tool/tool-search.ts) |
| `memory_search`/`memory_write`/`memory_read`/`memory_context` | Persistent cross-session memory | query/content | memory | [tool/memory.ts](packages/cyberstrike/src/tool/memory.ts) |

**`attack_script` catalogue** (16, [attack-script.ts:7](packages/cyberstrike/src/tool/attack-script.ts#L7)): `jwt_tamper`, `race_tester`, `ssti_tester`, `ssrf_listener`, `idor_tester`, `cors_checker`, `graphql_tester`, `file_upload_tester`, `oauth_tester`, `rate_limit_bypass`, `waf_bypass`, `cloud_storage_enum`, `subdomain_takeover`, `github_dorker`, `wayback_endpoints`, `response_diff`.

**Agents / subagents** ([agent/agent.ts](packages/cyberstrike/src/agent/agent.ts), names at lines 189-775). Agents have `mode: "primary" | "subagent" | "all"`; primaries are user-facing, subagents are launched via the `task` tool.

| Agent | Codename | Type | Purpose |
|---|---|---|---|
| `cyberstrike` | — | primary | Default orchestrator; routes phases to specialists |
| `web-application` | STRIKER | primary | Web app exploitation, chain building, OWASP |
| `cloud-security` | AURORA | primary | Cloud/IAM/CIS assessment |
| `internal-network` | PHANTOM | primary | AD, lateral movement, Kerberos, post-exploitation |
| `mobile-application` | CIPHER | primary | Mobile/APK/API hooking |
| `proxy-agent` (`web-proxy-agent` prompt) | INTERCEPTOR | primary/orchestrator | Traffic orchestration; drives the web-proxy pipeline |
| `explore` | GHOST | subagent | Recon, codebase/pattern discovery |
| `general` | — | subagent | Catch-all sub-tasks |
| `proxy-analyzer` | — | subagent | Extracts objects/functions/roles from a captured request |
| `proxy-tester-{idor,authz,injection,authn,ssrf,file-attacks,mass-assignment,business-logic,llm}` | — | subagent (native, hidden) | One specialist per vuln class; class-locked by `vuln-scope.ts` |
| `title` / `summary` / `compaction` / `normalize-request` | — | utility | House-keeping LLM tasks |

The primary `cyberstrike` prompt ([agent/prompt/cyberstrike.txt:25-51](packages/cyberstrike/src/agent/prompt/cyberstrike.txt#L25-L51)) contains the codename roster and a **phase → primary/backup agent routing table** the orchestrator follows.

**MCP servers** (built-in defaults, [config.ts:82-141](packages/cyberstrike/src/config/config.ts#L82-L141)): `github-security`, `cve`, `osint`, `cloud-audit`, `hackbrowser`, `darknet`, `dns-security`, `supply-chain`, `mcp-scanner`, `steganography`, `satellite`, plus **Bolt** Docker-Kali container servers ([mcp/bolt-auth.ts](packages/cyberstrike/src/mcp/bolt-auth.ts), `createBolt()` in [mcp/index.ts](packages/cyberstrike/src/mcp/index.ts)). In this working tree `cve`, `osint`, and `dns-security` are flipped to `enabled:true` (uncommitted; see §5/§8).

### Example tool contract (real code)

`report_vulnerability` from [tool/vulnerability.ts:17-52](packages/cyberstrike/src/tool/vulnerability.ts#L17-L52):

```ts
export const ReportVulnerabilityTool = Tool.define("report_vulnerability", {
  parameters: z.object({
    severity: z.enum(["critical","high","medium","low","info"]),
    title: z.string(), description: z.string(),
    cwe_id: z.string().optional(),
    steps_to_reproduce: z.string().optional(),
    poc: z.string().optional(),   // baseline req/resp, exploit req/resp, one-line diff
    // ...execution_evidence, vrt_category, endpoint, attack_vector
  }),
  // execute → Vulnerability.add(...) → VulnerabilityTable
})
```

Behavior: an injection-class, execution-dependent finding (XSS/SSTI/cmd-injection/deser-RCE per `isExecutionDependentFinding`, [vuln-scope.ts:132](packages/cyberstrike/src/tool/vuln-scope.ts#L132)) filed as critical/high **without** `execution_evidence` is overridden to `medium` and labelled `[UNCONFIRMED CANDIDATE]` ([vulnerability.ts:118-128](packages/cyberstrike/src/tool/vulnerability.ts#L118-L128)) — an anti-false-positive rail.

---

## 5. Divergence from OpenCode

CyberStrike keeps OpenCode's engine and adds a pentest domain layer. What was **added** (none of these exist upstream):

- **Security agents & prompts** — `agent/prompt/{cyberstrike,web-application,cloud-security,internal-network,mobile-application}.txt`, the `vuln/*` per-class tester prompts, and the `orchestrator`/`analyzer`/`methodology` prompt sets. The agent registry ([agent/agent.ts](packages/cyberstrike/src/agent/agent.ts)) hardcodes the specialist and `proxy-tester-*` fleet.
- **Methodology engine** — [methodology/](packages/cyberstrike/src/methodology/) (`methodology.ts`, `phase.ts`, `intel.ts`, `chain.ts`, `validation.ts`, `performance.ts` + `methodology.sql.ts`). Tracks WSTG-style phases, VRT coverage, attack chains, and per-agent "performance" scores, injected into the system prompt as an "Agent Delegation Briefing." Backs the *forced-continuation* completion criterion.
- **Web-proxy testing pipeline** — [session/web/](packages/cyberstrike/src/session/web/) entity model (objects/values/functions/roles/credentials/retest-queue), request normalization ([session/normalize/](packages/cyberstrike/src/session/normalize/)), ingest queue, coverage notes, and the `web_*` tools.
- **HackBrowser crawler** — [packages/hackbrowser/](packages/hackbrowser/), a Playwright browser that captures HTTP + UI context and streams into a session; run out-of-process ([hackbrowser-subprocess/](packages/cyberstrike/src/hackbrowser-subprocess/)) so Playwright never loads in the main binary.
- **Findings/reporting** — `session/vulnerability.ts` + `VulnerabilityTable`, `report_vulnerability`/`triage_vulnerability`/`generate_report`.
- **Offensive tooling** — `attack-script`, `inject-probe`, the `*hook` post-exploitation suites, cloud/K8s/CI audits, `ensure-tools`, and the security MCP servers (incl. Bolt Docker-Kali containers, [packages/containers/](packages/containers/)).
- **TLS-bypass provider option** — `tlsRejectUnauthorized` ([config.ts:1083](packages/cyberstrike/src/config/config.ts#L1083), wired at [provider.ts:1146](packages/cyberstrike/src/provider/provider.ts#L1146)) for self-signed lab / vLLM endpoints.
- **Full rebrand** — `CYBERSTRIKE_*` env vars, `@cyberstrike-io/*` packages, `cyberstrike.jsonc` config, `/etc/cyberstrike` managed dir.

Packages inherited from OpenCode (renamed, largely unchanged) **(inferred from monorepo layout + package.json)**: `app` (web UI), `console`, `enterprise`, `function`, `identity`, `sdk`, `plugin`, `ui`, `util`, `slack`, `script`. Pentest-specific packages: `hackbrowser`, `containers`. The `cyberstrike` package is the renamed `opencode` core. Note the [CHANGELOG.md](CHANGELOG.md) still carries upstream OpenCode history beneath the CyberStrike entries.

### Local uncommitted modifications (this working tree)

`git diff` shows 13 changed/added files (documented in [HANDOFF-2026-08-11.md](HANDOFF-2026-08-11.md) and the operator's memory). Functionally material ones:

- `server/routes/session.ts` + `web-proxy-agent/prompt.txt` — new `enqueueRetests()` that **auto-drains** `web_retest_queue` after every ingest and recurses on each retest's completion (no depth cap).
- `session/web/web-retest.ts` — adds `relevantRequestIDs()` so `checkTriggers` scopes retests to endpoints actually touching the discovered objects (the fix for the retest cascade below).
- `permission/next.ts` — the 10-minute auto-reject timeout.
- `config.ts` + `provider.ts` — the `tlsRejectUnauthorized` option.
- `config.ts` — enable `cve`/`osint`/`dns-security` MCP; point `hackbrowser` MCP at a local dev checkout.
- `cli/cmd/web.ts` — skip auto-open-browser when headless (no `DISPLAY`).
- `agent/prompt/vuln/common-prompt.txt` — force `curl --max-time 10`.

> **Known regression from these changes:** the auto-dispatch (`enqueueRetests`) combined with a pre-existing over-fan-out in `checkTriggers` produced a **380-item / ~30-hour retest cascade** that looked like a hung session ([web-retest.ts:271](packages/cyberstrike/src/session/web/web-retest.ts#L271); root cause and diagnosis in [HANDOFF-2026-08-11.md](HANDOFF-2026-08-11.md)). The `relevantRequestIDs` scoping fix is applied; the `enqueueRetests` recursion cap was deferred.

---

## 6. Security & Scoping Controls

Stated plainly, with gaps called out.

### Target scoping / authorization — **weak; no enforced allowlist**

Scoping exists in three disjoint places, only one of which blocks any network traffic:

1. **`scope_check` — advisory only.** [tool/scope-check.ts](packages/cyberstrike/src/tool/scope-check.ts) validates a target against a `scope_items` list the **model itself supplies as a parameter** (not read from config, not persisted). Out-of-scope just appends a `WARNING` string and returns ([scope-check.ts:33-36](packages/cyberstrike/src/tool/scope-check.ts#L33-L36)); it never throws or blocks.
2. **HackBrowser crawl scope — the only real host filter.** The crawler derives a default `*.{eTLD+1}` scope from the target and drops out-of-scope requests at capture time (`deriveScope`/`makeMatcher` in `packages/hackbrowser/src/scope.ts`; enforced `if (!inScope(hostname)) return` in `packages/hackbrowser/src/agent.ts:394` **(reported by subsystem audit; the hackbrowser package is external to `packages/cyberstrike/src`)**). This bounds only what the **crawler captures** — not what tester agents or `bash`/`curl`/`webfetch` may hit. The scope is still self-declared and defaults to the whole eTLD+1 of whatever target is passed in.
3. **`vuln-scope.ts` — lane discipline, not host scoping.** [tool/vuln-scope.ts](packages/cyberstrike/src/tool/vuln-scope.ts) structurally restricts which *vulnerability class* a `proxy-tester-<class>` subagent may record (`TESTER_VRT_SCOPE`, `vrtScopeViolation`). Anti-drift between specialists; unrelated to authorization.

> **Gap:** there is **no consent/ownership check and no enforced target allowlist** governing which hosts the agent may attack. Nothing gates `bash`, `webfetch`, or the `*hook`/audit tools by target. The operator is trusted to point it only at authorized targets.

### Network-touching code paths

- **Reconnaissance/exploitation via shell** — `bash` ([tool/bash.ts](packages/cyberstrike/src/tool/bash.ts)) runs arbitrary commands (nmap, sqlmap, nuclei, curl). Permission-gated (default `ask`).
- **HTTP fetch** — `webfetch` ([tool/webfetch.ts](packages/cyberstrike/src/tool/webfetch.ts)), 5 MB / 30s-120s / scheme-validated, permission-gated.
- **Autonomous crawl** — `hackbrowser` ([tool/hackbrowser.ts](packages/cyberstrike/src/tool/hackbrowser.ts)) → Playwright browser sending live traffic; permission-gated (`ctx.ask`, [hackbrowser.ts:64](packages/cyberstrike/src/tool/hackbrowser.ts#L64)).
- **Exploit helpers** — `attack_script`, `inject_probe`, `*hook` post-exploitation suites (credential harvest, privesc, persistence, lateral movement, exfil — see [CHANGELOG.md](CHANGELOG.md) `linuxhook`), cloud/K8s/CI audits (documented read-only).
- **Credential handling** — captured credentials are stored per-session in `WebCredentialTable` ([session.sql.ts:193](packages/cyberstrike/src/session/session.sql.ts#L193)) and tagged onto captured requests; the crawler collects them via interactive manual login (auto-login is intentionally unsupported, [tool/hackbrowser.ts](packages/cyberstrike/src/tool/hackbrowser.ts) description).

### Permission model & safety rails

- **Permission gate** — [permission/next.ts](packages/cyberstrike/src/permission/next.ts): `deny`→throw ([:143](packages/cyberstrike/src/permission/next.ts#L143)); `ask`→publish `permission.asked` + await ([:146-164](packages/cyberstrike/src/permission/next.ts#L146-L164)); default-when-unmatched is `ask` (fail-closed). A **10-minute auto-reject** timeout ([:158](packages/cyberstrike/src/permission/next.ts#L158)) prevents a disconnected UI from hanging the agent. A `reject` cancels all other pending permissions for the session ([:190-201](packages/cyberstrike/src/permission/next.ts#L190-L201)).
  - *Loop integration:* a hard denial sets `blocked` and stops the turn (`return "stop"`) unless `experimental.continue_loop_on_deny` is set ([processor.ts:49](packages/cyberstrike/src/session/processor.ts#L49), [:224-228](packages/cyberstrike/src/session/processor.ts#L224-L228), [:430](packages/cyberstrike/src/session/processor.ts#L430)).
  - *Known bug:* the auto-reject path bypasses `reply()` and never publishes `Event.Replied`, leaving a stale clickable prompt in the UI ([HANDOFF-2026-08-11.md](HANDOFF-2026-08-11.md), Issue 3). Also, approvals are **in-memory only** — `PermissionTable` exists ([session.sql.ts:119](packages/cyberstrike/src/session/session.sql.ts#L119)) but the write is a commented TODO ([permission/next.ts:235-238](packages/cyberstrike/src/permission/next.ts#L235-L238)).
- **Evidence-gated severity capping** — prevents fabricated high-severity findings (§4).
- **Timeouts** — `webfetch` caps; `cipipe` process kills; the uncommitted `curl --max-time 10` prompt rule.
- **Retest cap** — `maxRetests ?? 20` per trigger ([web-retest.ts:278](packages/cyberstrike/src/session/web/web-retest.ts#L278)).
- **Crawler exclude list** — semantic labels ("Delete Account", "Cancel Subscription") tell the crawler to skip destructive UI actions ([tool/hackbrowser.ts:46-51](packages/cyberstrike/src/tool/hackbrowser.ts#L46-L51)).
- **No global rate-limiter/throttle and no dedicated immutable audit-log table.** The closest audit trail is the **event bus** ([bus/index.ts](packages/cyberstrike/src/bus/index.ts)): every state change emits `permission.asked`/`replied`, `vulnerability.updated`, `web_object.updated`, `web_role.updated`, `web_retest.updated`, etc. — a live event stream, not a persisted log.

### Findings storage & reporting

- **Storage:** SQLite `VulnerabilityTable` ([session.sql.ts:82](packages/cyberstrike/src/session/session.sql.ts#L82)) — severity, title, description, cwe_id, file/line, steps, PoC, business impact, recommendation, status (`new`/`approved`/`duplicate`/`open`/`fixed`/`ignored`), candidate flag, `duplicate_of`. `Vulnerability.add` **never drops** a finding ([vulnerability.ts:76](packages/cyberstrike/src/session/vulnerability.ts#L76)); unique→`approved`, has-similar→`new` (for orchestrator triage).
- **Reporting:** `generate_report` ([tool/generate-report.ts](packages/cyberstrike/src/tool/generate-report.ts)) emits a **Markdown** report (returned as tool output, not auto-written to disk) combining confirmed findings (`SEV-NNN` refs + per-finding PoC), intel/coverage/methodology/chains/validation, an attack-surface summary, timeline, and an agent-performance scoreboard.

---

## 7. Configuration & Extensibility

### Configuration ([config/config.ts](packages/cyberstrike/src/config/config.ts))

Layered load order, low→high precedence ([config.ts:68-272](packages/cyberstrike/src/config/config.ts#L68-L272)): built-in MCP defaults → remote org defaults (`.well-known/cyberstrike`) → global `~/.config/cyberstrike/cyberstrike.json{,c}` → `CYBERSTRIKE_CONFIG` file → project `cyberstrike.json{,c}` → `.cyberstrike/` dir → `CYBERSTRIKE_CONFIG_CONTENT` → `CYBERSTRIKE_PERMISSION` → managed enterprise dir (`/etc/cyberstrike`, always overrides). Config is loaded once per process and cached.

Notable schema keys ([config.ts:1097+](packages/cyberstrike/src/config/config.ts#L1097)): `provider`, `mcp` (full config or `{enabled}` toggle), `bolt` (Docker-Kali container servers), `permission`, `agent` (+ `default_agent`, defaults to `cyberstrike`), `model`/`small_model` (`provider/model`), `enabled_providers`/`disabled_providers`, `server`, `skills`, `plugin`, `instructions`, `compaction`, `experimental` (incl. `continue_loop_on_deny`). Per-provider `options` include `apiKey`, `baseURL`, `timeout`, and `tlsRejectUnauthorized` ([config.ts:1083](packages/cyberstrike/src/config/config.ts#L1083)).

Env vars (`CYBERSTRIKE_*`, [flag/flag.ts](packages/cyberstrike/src/flag/flag.ts)): `CYBERSTRIKE_CONFIG`, `CYBERSTRIKE_CONFIG_DIR`, `CYBERSTRIKE_CONFIG_CONTENT`, `CYBERSTRIKE_PERMISSION`, `CYBERSTRIKE_SERVER_PASSWORD`/`_USERNAME`, `CYBERSTRIKE_DISABLE_PROJECT_CONFIG`, `CYBERSTRIKE_DISABLE_DEFAULT_PLUGINS`, and many `CYBERSTRIKE_EXPERIMENTAL_*`.

Providers ([provider/provider.ts](packages/cyberstrike/src/provider/provider.ts)): Anthropic subscription (custom `@anthropic-ai/sdk` wrapper for OAuth refresh, [:88-157](packages/cyberstrike/src/provider/provider.ts#L88-L157)), OpenAI-compatible / vLLM / Ollama (`@ai-sdk/openai-compatible`; custom-API-URL providers loaded as local, [:942](packages/cyberstrike/src/provider/provider.ts#L942)), and models.dev metadata. Models are `provider/model`; each carries `limit: {context, input, output}` (local default context 131072, [local.ts:53](packages/cyberstrike/src/provider/local.ts#L53)). **`limit.context` must be set for custom models** or compaction breaks (§8).

### Persistence

Bun SQLite opened at `~/.local/share/cyberstrike/cyberstrike.db` ([storage/db.ts:146-148](packages/cyberstrike/src/storage/db.ts#L146-L148), path from [global/index.ts:8](packages/cyberstrike/src/global/index.ts#L8)). Schema is Drizzle `sqliteTable` definitions (not raw `.sql` migrations): session/messages/parts/todos/**vulnerabilities**/permissions/requests + the web model (roles, objects, object-values, functions, endpoint-templates, observations, coverage-notes, **retest-queue**) in [session/session.sql.ts](packages/cyberstrike/src/session/session.sql.ts); methodology tables (intel, VRT checks, phases, chain candidates, agent performance, validation violations) in [methodology/methodology.sql.ts](packages/cyberstrike/src/methodology/methodology.sql.ts).

### Extensibility

- **New tool:** drop a `Tool.define(...)` module into [tool/](packages/cyberstrike/src/tool/) (or a `.cyberstrike/tool(s)/` dir) — auto-discovered by [registry.ts](packages/cyberstrike/src/tool/registry.ts). Co-locate prompt text as `<tool>.txt`.
- **New agent:** add a `.txt` prompt + registry entry in [agent/agent.ts](packages/cyberstrike/src/agent/agent.ts) for built-ins, or define one in the `agent` config key / `.cyberstrike/agent(s)/` (`model`, `prompt`, `tools`, `permission`, `steps`, `mode`, …).
- **New MCP server:** add to the `mcp` config key (local `command[]` or remote `url`), or `{enabled:true}` to flip a built-in; Bolt servers via the `bolt` key.
- **Plugins:** `@cyberstrike-io/plugin` ([packages/plugin/](packages/plugin/)); loaded from the `plugin: string[]` config, `.cyberstrike/plugins/`, or an npm dep ([plugin/index.ts](packages/cyberstrike/src/plugin/index.ts)).

### Build / deploy (repo root)

- [build.sh](build.sh) — clears `dist` and builds a standalone Linux x64 binary at `packages/cyberstrike/dist/cyberstrike-linux-x64/bin/cyberstrike`.
- [run.sh](run.sh) — kills any running instance, exports `DISPLAY=:10`/`XAUTHORITY` (for Playwright) and `CYBERSTRIKE_SERVER_PASSWORD=admin`, runs `cyberstrike web --hostname 0.0.0.0 --port 4444`.
- [cyberstrike.service](cyberstrike.service) — systemd unit, same env, `--port 8676`, `Restart=on-failure`.

> **Deployment security note:** both `run.sh` and the systemd unit hardcode `CYBERSTRIKE_SERVER_PASSWORD=admin` and bind `0.0.0.0` — the server is exposed on all interfaces with a weak default credential. The built-in `hackbrowser` MCP command also hardcodes a machine-specific path (`/home/master/code/hackbrowser-mcp/src/index.ts`, [config.ts:106](packages/cyberstrike/src/config/config.ts#L106)) that will fail on other hosts.

---

## 8. Known Limitations / Open Questions

1. **No enforced target authorization.** Nothing prevents the agent from attacking any host; `scope_check` is advisory and the only real host filter is the crawler's self-declared capture scope (§6). A human should verify scope discipline is acceptable for the intended use.
2. **Custom models must declare `limit.context`.** A vLLM/OpenAI-compatible model configured without `limit.context` reports context `0`, disabling the pre-flight overflow guard and causing an infinite compact-retry loop that presents as a "hang" ([vllm-model-needs-context-limit] memory; [prompt.ts:847](packages/cyberstrike/src/session/prompt.ts#L847)). The compact-retry loop has no progress check to bail when compaction fails to shrink the prompt.
3. **Retest cascade risk.** The uncommitted auto-dispatch `enqueueRetests()` has no recursion/count cap; combined with `checkTriggers` fan-out it caused a 380-item/30h cascade. The scoping fix is applied but the recursion cap was deferred (§5). Verify behaviorally before relying on it.
4. **Permission edge cases.** Approvals are not persisted (in-memory only, commented-out `PermissionTable` write); the auto-reject timeout doesn't emit `Event.Replied`, leaving stale UI prompts. The design question "should a single denial hard-stop the whole turn?" is unresolved ([HANDOFF-2026-08-11.md](HANDOFF-2026-08-11.md)).
5. **Audit trail is ephemeral.** State changes emit bus events but there is no persisted immutable audit log of actions taken against a target — a gap for engagements needing an auditable record.
6. **Planning pattern is emergent, not explicit.** No standalone planner module was found; planning appears to be model-driven ReAct steered by the methodology-engine context and forced-continuation prompt. This is inferred from loop structure, not stated in code comments.
7. **Hackbrowser package not audited line-by-line here.** Scope-enforcement claims for `packages/hackbrowser/` come from a subsystem sweep (that package sits outside `packages/cyberstrike/src`); a human should confirm `agent.ts:394` behavior against the shipped hackbrowser version, which may be the npm package rather than the local dev checkout the config points at.
8. **Docs vs. code drift.** Repo docs are thin (`docs/` holds only `skill-signing.md`; `specs/project.md` is a short API sketch) and the CHANGELOG still carries upstream OpenCode history. The README's marketing counts ("7,600+ security skills", "56+ tools") are not directly verifiable from a single source file and should be treated as approximate.

---

*Generated from a source audit of the CyberStrike working tree (branch `main`) on 2026-08-14. Line numbers reflect the tree at audit time and may shift.*
