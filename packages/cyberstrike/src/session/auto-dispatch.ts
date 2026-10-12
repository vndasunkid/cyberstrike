import { Session } from "."
import { Agent } from "../agent/agent"
import { SessionPrompt } from "./prompt"
import { Identifier } from "../id/id"
import { WebCredential } from "./web/web-credential"
import { Config } from "../config/config"
import { PermissionNext } from "../permission/next"
import { Log } from "../util/log"
import { Skill } from "../skill"
import { Vulnerability } from "./vulnerability"

const TESTER_CLASSES = [
  "proxy-tester-injection",
  "proxy-tester-idor",
  "proxy-tester-authz",
  "proxy-tester-authn",
  "proxy-tester-business-logic",
  "proxy-tester-mass-assignment",
  "proxy-tester-ssrf",
  "proxy-tester-file-attacks",
] as const

const MAX_CONCURRENT = 4
const DISPATCH_TIMEOUT_MS = 25 * 60 * 1000

const CLASS_SKILLS: Record<string, string[]> = {
  "proxy-tester-injection": [
    // SQLi (all DB variants)
    "wstg-inpv-05", "wstg-inpv-05.1", "wstg-inpv-05.2", "wstg-inpv-05.3",
    "wstg-inpv-05.4", "wstg-inpv-05.5", "wstg-inpv-05.6", "wstg-inpv-05.7",
    "wstg-inpv-05.8", "wstg-inpv-05.9", "wstg-inpv-05.10", "wstg-inpv-05.11",
    // XSS (reflected, stored, DOM)
    "wstg-inpv-01", "wstg-inpv-02", "wstg-clnt-01", "wstg-clnt-01.1",
    // SSTI, Code Injection, Command Injection
    "wstg-inpv-18", "wstg-inpv-11", "wstg-inpv-12",
    // LDAP, XML/XXE, SSI, XPath, IMAP/SMTP, Format String
    "wstg-inpv-06", "wstg-inpv-07", "wstg-inpv-08", "wstg-inpv-09",
    "wstg-inpv-10", "wstg-inpv-13",
    // HTTP verb/param/header/smuggling
    "wstg-inpv-03", "wstg-inpv-04", "wstg-inpv-15", "wstg-inpv-16", "wstg-inpv-17",
    // Incubated vulns
    "wstg-inpv-14",
    // Client-side: JS exec, HTML injection, CSS injection, XSSI
    "wstg-clnt-02", "wstg-clnt-03", "wstg-clnt-05", "wstg-clnt-13",
    // Meta: injection overview
    "wstg-injection",
  ],
  "proxy-tester-idor": [
    "wstg-authz-04",   // IDOR
    "wstg-apit-00",    // API Testing Overview
    "wstg-apit-01",    // API Reconnaissance
    "wstg-apit-02",    // BOLA
    "wstg-apit-99",    // GraphQL
  ],
  "proxy-tester-authz": [
    "wstg-authz-01",   // Directory Traversal / File Include
    "wstg-authz-02",   // Bypassing Authorization Schema
    "wstg-authz-03",   // Privilege Escalation
    "wstg-authz-05",   // OAuth Weaknesses
    "wstg-authz-05.1", // OAuth Authorization Server
    "wstg-authz-05.2", // OAuth Client
    "wstg-bac",        // Broken Access Control pack
    "wstg-conf-05",    // Admin Interfaces
    "wstg-idnt-01",    // Role Definitions
    "wstg-conf-06",    // HTTP Methods
    "wstg-conf-12",    // Content Security Policy
    "wstg-conf-13",    // Path Confusion
  ],
  "proxy-tester-authn": [
    // Authentication tests
    "wstg-athn-01",    // Credentials over encrypted channel
    "wstg-athn-02",    // Default Credentials
    "wstg-athn-03",    // Weak Lock Out
    "wstg-athn-04",    // Bypassing Authentication Schema
    "wstg-athn-05",    // Vulnerable Remember Password
    "wstg-athn-06",    // Browser Cache Weaknesses
    "wstg-athn-07",    // Weak Password Policy
    "wstg-athn-08",    // Weak Security Question Answer
    "wstg-athn-09",    // Weak Password Change/Reset
    "wstg-athn-10",    // Weaker Auth in Alternative Channel
    "wstg-athn-11",    // Multi-Factor Authentication
    "wstg-auth-session", // Auth/session meta
    // Identity tests
    "wstg-idnt-02",    // User Registration
    "wstg-idnt-03",    // Account Provisioning
    "wstg-idnt-04",    // Account Enumeration
    "wstg-idnt-05",    // Username Policy
    "wstg-idnt-06",    // SAML/SSO
    // Session management
    "wstg-sess-01",    // Session Management Schema
    "wstg-sess-02",    // Cookies Attributes
    "wstg-sess-03",    // Session Fixation
    "wstg-sess-04",    // Exposed Session Variables
    "wstg-sess-05",    // CSRF
    "wstg-sess-06",    // Logout Functionality
    "wstg-sess-07",    // Session Timeout
    "wstg-sess-08",    // Session Puzzling
    "wstg-sess-09",    // Session Hijacking
    "wstg-sess-10",    // JWT
    "wstg-sess-11",    // Concurrent Sessions
    // Crypto (password hashing, weak encryption)
    "wstg-cryp-01",    // Weak Transport Layer Security
    "wstg-cryp-02",    // Padding Oracle
    "wstg-cryp-03",    // Sensitive Info Unencrypted
    "wstg-cryp-04",    // Weak Encryption
  ],
  "proxy-tester-business-logic": [
    "wstg-busl-01",    // Business Logic Data Validation
    "wstg-busl-02",    // Forge Requests
    "wstg-busl-03",    // Integrity Checks
    "wstg-busl-04",    // Process Timing (race conditions)
    "wstg-busl-05",    // Function Use Limits
    "wstg-busl-06",    // Circumvention of Work Flows
    "wstg-busl-07",    // Defenses Against App Misuse
    "wstg-busl-10",    // Payment Functionality
    // Error handling (info leakage via errors)
    "wstg-errh-01",    // Improper Error Handling
    "wstg-errh-02",    // Stack Traces
  ],
  "proxy-tester-mass-assignment": [
    "wstg-inpv-20",    // Mass Assignment
    "wstg-authz-03",   // Privilege Escalation (via mass assignment)
    "wstg-inpv-04",    // HTTP Parameter Pollution
  ],
  "proxy-tester-ssrf": [
    "wstg-inpv-19",    // SSRF
    "wstg-clnt-04",    // Client-Side URL Redirect
    "wstg-clnt-07",    // CORS
    "wstg-clnt-08",    // Cross-Site Flashing
    "wstg-clnt-09",    // Clickjacking
    "wstg-clnt-10",    // WebSockets
    "wstg-clnt-11",    // Web Messaging
    "wstg-clnt-14",    // Reverse Tabnabbing
    "wstg-conf-08",    // RIA Cross Domain Policy
    "wstg-conf-10",    // Subdomain Takeover
  ],
  "proxy-tester-file-attacks": [
    "wstg-inpv-11.1",  // LFI/RFI
    "wstg-inpv-07",    // XML Injection (XXE)
    "wstg-inpv-12",    // Command Injection (via file upload)
    "wstg-busl-08",    // Upload Unexpected File Types
    "wstg-busl-09",    // Upload Malicious Files
    "wstg-conf-03",    // File Extensions
    "wstg-conf-04",    // Backup/Unreferenced Files
    "wstg-conf-09",    // File Permission
    "wstg-conf-11",    // Cloud Storage
    "wstg-clnt-06",    // Client-Side Resource Manipulation
    "wstg-clnt-12",    // Browser Storage
    // Recon/config (info leakage via files)
    "wstg-info-01",    // Search Engine Discovery
    "wstg-info-02",    // Fingerprint Web Server
    "wstg-info-03",    // Webserver Metafiles
    "wstg-info-04",    // Enumerate Applications
    "wstg-info-05",    // Web Page Content Info Leakage
    "wstg-info-06",    // Identify Entry Points
    "wstg-info-07",    // Map Execution Paths
    "wstg-info-08",    // Fingerprint Framework
    "wstg-info-09",    // Fingerprint Web App
    "wstg-info-10",    // Map Architecture
    "wstg-conf-01",    // Network Infrastructure Config
    "wstg-conf-02",    // Application Platform Config
    "wstg-conf-07",    // HSTS
    "wstg-recon-config", // Recon/config meta
  ],
}

const MAX_SKILL_CHARS = 8000

async function loadSkillSnippets(cls: string): Promise<string> {
  const names = CLASS_SKILLS[cls]
  if (!names?.length) return ""
  const perSkillLimit = Math.max(20, Math.floor(200 / names.length))
  const parts: string[] = []
  let totalChars = 0
  for (const name of names) {
    if (totalChars >= MAX_SKILL_CHARS) break
    const skill = await Skill.get(name)
    if (!skill) continue
    const lines = skill.content.split("\n")
    const payloadStart = lines.findIndex((l) => /payload|example|step|technique|test.*objective|how.*test|curl|fetch|http/i.test(l))
    const start = payloadStart >= 0 ? payloadStart : 0
    const snippet = lines.slice(start, start + perSkillLimit).join("\n")
    if (!snippet.trim()) continue
    const block = `<skill name="${name}">\n${snippet}\n</skill>`
    totalChars += block.length
    parts.push(block)
  }
  return parts.length > 0 ? `\n## WSTG Reference Techniques (use these payloads)\n${parts.join("\n\n")}` : ""
}

function collectLeakedIntel(rootID: string): string {
  const parts: string[] = []
  try {
    const vulns = Vulnerability.get(rootID)
    const userDumps = vulns.filter(
      (v) => v.title?.includes("User Credentials") || v.title?.includes("UNION") || v.description?.includes("MD5 hash"),
    )
    if (userDumps.length > 0) {
      parts.push("## Leaked User Data (from SQLi UNION dump)")
      parts.push("The following users/hashes were already extracted. USE them for per-user targeting:")
      for (const v of userDumps) {
        const poc = v.poc ?? v.steps_to_reproduce ?? ""
        if (poc) parts.push(poc.slice(0, 500))
      }
    }
    const secAnswers = vulns.filter((v) => v.title?.includes("SecurityAnswer") || v.description?.includes("security question"))
    if (secAnswers.length > 0) {
      parts.push("\n## Leaked Security Answers")
      for (const v of secAnswers) parts.push((v.poc ?? v.description ?? "").slice(0, 300))
    }
  } catch {}
  return parts.join("\n")
}

export namespace AutoDispatch {
  const log = Log.create({ service: "auto-dispatch" })
  const dispatched = new Set<string>()

  export async function run(input: {
    sessionID: string
    target: string
    endpoints: Array<{ method: string; path: string; note?: string }>
  }): Promise<void> {
    const rootID = Session.root(input.sessionID)
    if (dispatched.has(rootID)) return
    dispatched.add(rootID)

    const creds = WebCredential.get(rootID)
    const tokenLines: string[] = []
    for (const c of creds) {
      const auth = c.headers["Authorization"] ?? c.headers["authorization"]
      if (auth) tokenLines.push(`- ${c.label ?? "credential"}: ${auth}`)
    }
    const tokenBlock =
      tokenLines.length > 0
        ? `## Credentials\n${tokenLines.join("\n")}`
        : "No credentials available — test unauthenticated only."

    const writes = input.endpoints.filter((e) => e.method !== "GET")
    const gets = input.endpoints.filter((e) => e.method === "GET")
    const endpointBlock = input.endpoints.map((e) => `- ${e.method} ${e.path}`).join("\n")

    const intelBlock = collectLeakedIntel(rootID)

    const classPrompts: Record<string, string> = {
      "proxy-tester-injection": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for injection (SQLi, XSS, SSTI, command injection, NoSQLi)`,
        endpointBlock,
        `Test EVERY endpoint above for injection vulnerabilities. For each:`,
        `1. Identify all input parameters (query, body, path, headers)`,
        `2. Test SQLi: UNION, blind boolean, blind time, error-based on each param`,
        `3. Test XSS: reflected, stored. Try <script>, img onerror, svg onload`,
        `4. Test SSTI: {{7*7}}, ${"`${7*7}`"} in template-rendered fields. If arithmetic works, ESCALATE to RCE: #{global.process.mainModule.require('child_process').execSync('id')}`,
        `5. Test NoSQLi on JSON endpoints: {"$ne":""}, {"$gt":""}, {"$where":"sleep(2000)"}, {"$regex":".*"}`,
        `6. Drive each finding to FULL impact (extract data, execute code, read files)`,
        `7. report_vulnerability for each confirmed finding`,
        `8. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-idor": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for BOLA/IDOR`,
        endpointBlock,
        `Test EVERY endpoint above for Insecure Direct Object References:`,
        `1. Identify object IDs in path, query, body (numeric IDs, UUIDs)`,
        `2. With two different credentials: access user A's objects as user B`,
        `3. Try sequential IDs, ID+1, ID-1, 0, negative, other users' known IDs`,
        `4. Prove cross-user data access with the response`,
        `5. Test data theft WITHOUT injection: GET /rest/track-order/{id} with other users' order IDs`,
        `6. Delete operations: DELETE /api/Feedbacks/{id} to delete 5-star reviews`,
        `7. Basket swap: PUT /api/BasketItems/{id} with BasketId of another user`,
        `8. report_vulnerability for each confirmed finding`,
        `9. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-authz": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for authorization bypass / privilege escalation`,
        endpointBlock,
        `Test EVERY endpoint above for broken access control:`,
        `1. Access admin-only endpoints with a regular user token`,
        `2. Access authenticated endpoints with no token (remove Authorization header)`,
        `3. Try horizontal privilege escalation (user A accessing user B's resources)`,
        `4. Try vertical privilege escalation (normal user → admin functions)`,
        `5. Admin section access: GET /administration — test with normal user JWT`,
        `6. PUT /api/Users/{id} — change role to "admin" from normal user session`,
        `7. View other users' baskets: GET /rest/basket/{otherId} with your token`,
        `8. report_vulnerability for each confirmed finding`,
        `9. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-authn": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for authentication bypass`,
        endpointBlock,
        `Test authentication mechanisms:`,
        `1. JWT attacks: alg=none, alg=HS256 with public key (key confusion), weak secret`,
        `2. Forge tokens with modified claims (role, isAdmin, userId)`,
        `3. Test token expiration, reuse after logout`,
        `4. Default credentials, credential stuffing on login endpoint`,
        `5. Password reset flow abuse — for EACH user found in leaked data above:`,
        `   a. Try forgot-password with their security question answers`,
        `   b. Try login with cracked MD5 hashes (use CrackStation/rainbow tables)`,
        `   c. Try password change without current password: GET /rest/user/change-password?new=X&repeat=X`,
        `6. Per-user login: if hashes were dumped, crack common ones (admin123, ncc-1701, etc.) and LOGIN each user`,
        `7. report_vulnerability for each confirmed finding`,
        `8. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-business-logic": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for business logic flaws`,
        writes.length > 0
          ? `### Write endpoints (high priority)\n${writes.map((e) => `- ${e.method} ${e.path}`).join("\n")}`
          : "",
        `### All endpoints\n${endpointBlock}`,
        `Test for business logic vulnerabilities:`,
        `1. Negative quantities/amounts in orders, payments, transfers`,
        `2. Price tampering: modify price/total in request body`,
        `3. Workflow bypass: skip required steps (e.g. payment before checkout)`,
        `4. Race conditions: send 10+ CONCURRENT identical requests to state-changing endpoints:`,
        `   - POST /rest/products/{id}/reviews (like endpoint — Multiple Likes)`,
        `   - POST /rest/basket/{id}/checkout (duplicate orders)`,
        `   - POST /api/Feedbacks (multiple feedbacks)`,
        `5. Integer overflow/underflow on numeric fields`,
        `6. Coupon/discount abuse: try expired coupons (WMNSDY2019), z85 forging, reuse`,
        `7. Zero-star feedback: POST rating:0 (intercept and modify)`,
        `8. Empty email registration: POST /api/Users with email:""`,
        `9. report_vulnerability for each confirmed finding`,
        `10. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-mass-assignment": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for mass assignment`,
        writes.length > 0
          ? writes.map((e) => `- ${e.method} ${e.path}`).join("\n")
          : endpointBlock,
        `Test EVERY write endpoint for mass assignment / parameter pollution:`,
        `1. Add extra fields: role, isAdmin, admin, price, amount, balance, ownerId, userId, deluxeToken`,
        `2. Try to escalate privileges by setting role=admin or isAdmin=true on PUT /api/Users/{id}`,
        `3. Try to manipulate prices, amounts, ownership in basket/order endpoints`,
        `4. Test both JSON body and form-encoded parameters`,
        `5. POST /api/Users with extra role:"admin" during registration`,
        `6. PUT /api/Products/{id} to change product descriptions/prices`,
        `7. report_vulnerability for each confirmed finding`,
        `8. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-ssrf": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for SSRF and open redirect`,
        endpointBlock,
        `Test for Server-Side Request Forgery and URL-based attacks:`,
        `1. Find URL parameters (url, imageUrl, redirect, callback, next, link)`,
        `2. Test with internal addresses: http://localhost, http://127.0.0.1, http://[::1]`,
        `3. Test cloud metadata: http://169.254.169.254/latest/meta-data/`,
        `4. Test file:// protocol: file:///etc/passwd`,
        `5. Test open redirects: /redirect?to=https://evil.com, use allowlisted domains with subdomain tricks`,
        `6. Profile image URL: POST /api/Users with photoUrl pointing to internal resource`,
        `7. Chatbot URL injection: interact with /api/Chatbot, ask it to open/fetch URLs`,
        `8. report_vulnerability for each confirmed finding`,
        `9. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-file-attacks": [
        `Target: ${input.target}`,
        tokenBlock,
        intelBlock,
        `## Endpoints to test for file-based attacks`,
        endpointBlock,
        `Test for file upload, XXE, path traversal, LFI:`,
        `1. File upload: bypass extension filters (double ext, null byte, case), upload web shells`,
        `2. XXE: submit XML with external entity declarations to read /etc/passwd`,
        `3. Path traversal: ../../../etc/passwd in file path parameters`,
        `4. LFI: include local files via path params`,
        `5. Check /ftp directory listing — download confidential files (acquisitions.md, etc.)`,
        `6. Poison null byte: GET /ftp/eastere.gg%2500.md to bypass extension allowlist`,
        `7. Path traversal on /ftp: GET /ftp/../../etc/passwd via URL-encoded ../ (%2e%2e%2f)`,
        `8. Allowed MIME types bypass: change Content-Type when uploading to /profile/image/file/upload`,
        `9. report_vulnerability for each confirmed finding`,
        `10. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
    }

    log.info("auto-dispatch starting", {
      sessionID: rootID,
      target: input.target,
      endpoints: input.endpoints.length,
      classes: TESTER_CLASSES.length,
    })

    const batches: (typeof TESTER_CLASSES)[number][][] = []
    for (let i = 0; i < TESTER_CLASSES.length; i += MAX_CONCURRENT) {
      batches.push([...TESTER_CLASSES.slice(i, i + MAX_CONCURRENT)])
    }

    for (let bi = 0; bi < batches.length; bi++) {
      const batch = batches[bi]
      log.info("auto-dispatch: batch start", { batch: bi + 1, total: batches.length, classes: batch })
      const results = await Promise.allSettled(
        batch.map(async (cls) => {
          const skillSnippets = await loadSkillSnippets(cls)
          log.info("auto-dispatch: skills loaded", { class: cls, snippetLen: skillSnippets.length })
          const prompt = (classPrompts[cls] ?? "") + skillSnippets
          return dispatchOne({
            rootID,
            agentName: cls,
            prompt,
          })
        }),
      )
      const failed = results.filter((r) => r.status === "rejected")
      if (failed.length > 0) {
        log.warn("auto-dispatch: batch had failures", {
          batch: bi + 1,
          failed: failed.length,
          reasons: failed.map((r) => (r as PromiseRejectedResult).reason?.toString()),
        })
      }
      log.info("auto-dispatch: batch done", { batch: bi + 1 })
    }

    log.info("auto-dispatch complete", { sessionID: rootID })
  }

  async function dispatchOne(input: { rootID: string; agentName: string; prompt: string }): Promise<void> {
    try {
      const agent = await Agent.get(input.agentName)
      if (!agent) {
        log.warn("auto-dispatch: agent not found", { agent: input.agentName })
        return
      }

      const config = await Config.get()
      const hasTaskPermission = agent.permission.some((rule) => rule.permission === "task")

      const session = await Session.create({
        parentID: input.rootID,
        title: `${input.agentName} (auto-dispatch)`,
        permission: [
          { permission: "todowrite" as const, pattern: "*" as const, action: "deny" as const },
          { permission: "todoread" as const, pattern: "*" as const, action: "deny" as const },
          ...(hasTaskPermission
            ? []
            : [{ permission: "task" as const, pattern: "*" as const, action: "deny" as const }]),
          ...(config.experimental?.primary_tools?.map((t: string) => ({
            pattern: "*" as const,
            action: "allow" as const,
            permission: t,
          })) ?? []),
        ],
      })

      const model = agent.model ?? (await SessionPrompt.lastModel(input.rootID))
      const parts = await SessionPrompt.resolvePromptParts(input.prompt)

      log.info("auto-dispatch: starting subagent", {
        agent: input.agentName,
        sessionID: session.id,
        parentID: input.rootID,
      })

      const promptTask = SessionPrompt.prompt({
        messageID: Identifier.ascending("message"),
        sessionID: session.id,
        model: { modelID: model.modelID, providerID: model.providerID },
        agent: input.agentName,
        tools: {
          todowrite: false,
          todoread: false,
          ...(hasTaskPermission ? {} : { task: false }),
          ...Object.fromEntries((config.experimental?.primary_tools ?? []).map((t: string) => [t, false])),
        },
        parts,
      })

      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`dispatch timeout after ${DISPATCH_TIMEOUT_MS / 60000}min`)), DISPATCH_TIMEOUT_MS),
      )

      await Promise.race([promptTask, timeout])

      log.info("auto-dispatch: subagent finished", {
        agent: input.agentName,
        sessionID: session.id,
      })
    } catch (e) {
      log.warn("auto-dispatch: subagent failed", { agent: input.agentName, error: String(e) })
    }
  }
}
