import { Session } from "."
import { Agent } from "../agent/agent"
import { SessionPrompt } from "./prompt"
import { Identifier } from "../id/id"
import { WebCredential } from "./web/web-credential"
import { Config } from "../config/config"
import { PermissionNext } from "../permission/next"
import { Log } from "../util/log"

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

const MAX_CONCURRENT = 3

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

    const classPrompts: Record<string, string> = {
      "proxy-tester-injection": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for injection (SQLi, XSS, SSTI, command injection, NoSQLi)`,
        endpointBlock,
        `Test EVERY endpoint above for injection vulnerabilities. For each:`,
        `1. Identify all input parameters (query, body, path, headers)`,
        `2. Test SQLi: UNION, blind boolean, blind time, error-based on each param`,
        `3. Test XSS: reflected, stored. Try <script>, img onerror, svg onload`,
        `4. Test SSTI: {{7*7}}, ${"`${7*7}`"} in template-rendered fields`,
        `5. Drive each finding to FULL impact (extract data, execute code)`,
        `6. report_vulnerability for each confirmed finding`,
        `7. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-idor": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for BOLA/IDOR`,
        endpointBlock,
        `Test EVERY endpoint above for Insecure Direct Object References:`,
        `1. Identify object IDs in path, query, body (numeric IDs, UUIDs)`,
        `2. With two different credentials: access user A's objects as user B`,
        `3. Try sequential IDs, ID+1, ID-1, 0, negative, other users' known IDs`,
        `4. Prove cross-user data access with the response`,
        `5. report_vulnerability for each confirmed finding`,
        `6. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-authz": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for authorization bypass / privilege escalation`,
        endpointBlock,
        `Test EVERY endpoint above for broken access control:`,
        `1. Access admin-only endpoints with a regular user token`,
        `2. Access authenticated endpoints with no token (remove Authorization header)`,
        `3. Try horizontal privilege escalation (user A accessing user B's resources)`,
        `4. Try vertical privilege escalation (normal user → admin functions)`,
        `5. report_vulnerability for each confirmed finding`,
        `6. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-authn": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for authentication bypass`,
        endpointBlock,
        `Test authentication mechanisms:`,
        `1. JWT attacks: alg=none, alg=HS256 with public key (key confusion), weak secret`,
        `2. Forge tokens with modified claims (role, isAdmin, userId)`,
        `3. Test token expiration, reuse after logout`,
        `4. Default credentials, credential stuffing on login endpoint`,
        `5. Password reset flow abuse`,
        `6. report_vulnerability for each confirmed finding`,
        `7. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-business-logic": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for business logic flaws`,
        writes.length > 0
          ? `### Write endpoints (high priority)\n${writes.map((e) => `- ${e.method} ${e.path}`).join("\n")}`
          : "",
        `### All endpoints\n${endpointBlock}`,
        `Test for business logic vulnerabilities:`,
        `1. Negative quantities/amounts in orders, payments, transfers`,
        `2. Price tampering: modify price/total in request body`,
        `3. Workflow bypass: skip required steps (e.g. payment before checkout)`,
        `4. Race conditions on balance-changing operations (concurrent requests)`,
        `5. Integer overflow/underflow on numeric fields`,
        `6. Coupon/discount abuse, reuse, forging`,
        `7. report_vulnerability for each confirmed finding`,
        `8. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-mass-assignment": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for mass assignment`,
        writes.length > 0
          ? writes.map((e) => `- ${e.method} ${e.path}`).join("\n")
          : endpointBlock,
        `Test EVERY write endpoint for mass assignment / parameter pollution:`,
        `1. Add extra fields: role, isAdmin, admin, price, amount, balance, ownerId, userId`,
        `2. Try to escalate privileges by setting role=admin or isAdmin=true`,
        `3. Try to manipulate prices, amounts, ownership`,
        `4. Test both JSON body and form-encoded parameters`,
        `5. report_vulnerability for each confirmed finding`,
        `6. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-ssrf": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for SSRF and open redirect`,
        endpointBlock,
        `Test for Server-Side Request Forgery:`,
        `1. Find URL parameters (url, imageUrl, redirect, callback, next, link)`,
        `2. Test with internal addresses: http://localhost, http://127.0.0.1, http://[::1]`,
        `3. Test cloud metadata: http://169.254.169.254/latest/meta-data/`,
        `4. Test file:// protocol: file:///etc/passwd`,
        `5. Test open redirects on redirect/callback params`,
        `6. report_vulnerability for each confirmed finding`,
        `7. record_coverage_note + update_vrt_check for clean endpoints`,
      ].join("\n"),
      "proxy-tester-file-attacks": [
        `Target: ${input.target}`,
        tokenBlock,
        `## Endpoints to test for file-based attacks`,
        endpointBlock,
        `Test for file upload, XXE, path traversal, LFI:`,
        `1. File upload: bypass extension filters (double ext, null byte, case), upload web shells`,
        `2. XXE: submit XML with external entity declarations to read /etc/passwd`,
        `3. Path traversal: ../../../etc/passwd in file path parameters`,
        `4. LFI: include local files via path params`,
        `5. Check /ftp, backup files, .git, .env, .bak exposure`,
        `6. Poison null byte to bypass allowlists on file access`,
        `7. report_vulnerability for each confirmed finding`,
        `8. record_coverage_note + update_vrt_check for clean endpoints`,
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

    for (const batch of batches) {
      await Promise.allSettled(
        batch.map((cls) =>
          dispatchOne({
            rootID,
            agentName: cls,
            prompt: classPrompts[cls] ?? "",
          }),
        ),
      )
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

      await SessionPrompt.prompt({
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

      log.info("auto-dispatch: subagent finished", {
        agent: input.agentName,
        sessionID: session.id,
      })
    } catch (e) {
      log.warn("auto-dispatch: subagent failed", { agent: input.agentName, error: String(e) })
    }
  }
}
