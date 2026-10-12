import z from "zod"
import { Tool } from "./tool"
import { Intel } from "../methodology/intel"
import { Session } from "../session"
import { vrtScopeViolation, offLaneMessage } from "./vuln-scope"
import { resolveCategory, isValidTechnique, requiredCount, remainingTechniques } from "../methodology/technique-taxonomy"

export const UpdateVrtCheckTool = Tool.define("update_vrt_check", {
  description:
    "Update a VRT (Vulnerability Rating Taxonomy) check for an intel entry. After testing an endpoint/parameter for a specific vulnerability category, record the result here. This feeds the coverage tracking system — every check moved from 'pending' to a tested state improves coverage. " +
    "For categories with a fixed technique taxonomy (SQLi, XSS, NoSQLi, SSTI, Command Injection, XXE, LDAP Injection, IDOR, Auth Bypass, Authentication, SSRF, File Attacks, Mass Assignment, Business Logic, Race Condition, Privilege Escalation, Known CVE, Framework Vuln, Config Manipulation, Default Creds, Weak Crypto, Open Redirect, Info Disclosure, Subdomain Takeover, CORS), `technique` MUST be one of that category's defined values — an unrecognized value is rejected with the valid list. " +
    "Closing a check as 'tested_not_vulnerable' requires having attempted a majority of that category's known techniques (or a `single_technique_justification` for a genuinely single-technique case) — a single shallow test does not prove absence of the vulnerability. If you haven't tried enough yet, this call records progress and tells you exactly which techniques remain.",
  parameters: z.object({
    entry_id: z.string().describe("The intel entry ID to update the VRT check for"),
    vrt_category: z.string().describe("The VRT category being tested (e.g., IDOR, XSS, SQLi, SSRF, Auth Bypass)"),
    status: z.enum(["tested_vulnerable", "tested_not_vulnerable", "not_applicable"]).describe("Result of the test"),
    technique: z
      .string()
      .describe(
        "Testing technique used in THIS call. For categories with a fixed taxonomy, must match one of the defined values exactly (e.g. 'error-based', 'boolean-blind' for SQLi) — an invalid value is rejected with the valid list for that category. Required — accumulates across calls for the same check.",
      ),
    single_technique_justification: z
      .string()
      .min(40)
      .optional()
      .describe(
        "Only needed to close a check as tested_not_vulnerable after a SINGLE technique. Explain concretely why no second technique is applicable to this category/entry (min 40 chars). Do not use this to skip testing — it's for genuinely single-technique categories only (e.g. a plain banner-grab).",
      ),
    evidence: z
      .object({
        requestSent: z.string().optional().describe("The HTTP request sent (must contain HTTP verb or curl command)"),
        responseCode: z.number().optional().describe("HTTP response status code"),
        responseSummary: z
          .string()
          .optional()
          .describe(
            "Summary of the response (min 50 chars for vulnerable findings). Include actual data if exploited.",
          ),
        reasoning: z
          .string()
          .optional()
          .describe("Explanation of why this is/isn't vulnerable (min 100 chars for vulnerable findings)"),
        requestCount: z
          .number()
          .optional()
          .describe("Number of HTTP requests made during testing (min 1 for valid testing)"),
        findingRef: z.string().optional().describe("Reference to a report_vulnerability call if applicable"),
      })
      .optional()
      .describe("Evidence supporting the test result. Required for 'tested_vulnerable' status."),
  }),
  async execute(params, ctx) {
    // Lane discipline: a proxy-tester may only record VRT checks in its own
    // vulnerability class. Off-class checks are rejected (not written) with a
    // hand-off hint — structural, capability-agnostic (Phase 2).
    const violation = vrtScopeViolation(ctx.agent, params.vrt_category)
    if (violation) {
      return {
        title: `VRT rejected — ${params.vrt_category} out of ${violation.cls} scope`,
        output: offLaneMessage(violation.cls, violation.allowed, params.vrt_category),
        metadata: { entryID: params.entry_id, category: params.vrt_category, status: params.status },
      }
    }

    const sessionID = Session.root(ctx.sessionID)

    // Gate 1 v2 (plan_A1.md §4.3, "Hướng B"): categories with a defined technique
    // taxonomy reject an unrecognized `technique` value outright — this prevents
    // the free-text loophole where two differently-worded labels for the SAME
    // underlying test both counted as "distinct" progress. Categories without a
    // taxonomy entry yet accept any technique string (old free-text behavior).
    const submittedTechnique = params.technique.trim().toLowerCase()
    const taxonomyKey = resolveCategory(params.vrt_category)
    if (taxonomyKey && !isValidTechnique(params.vrt_category, submittedTechnique)) {
      return {
        title: `VRT: unrecognized technique "${params.technique}" for ${params.vrt_category}`,
        output: `"${params.technique}" is not a defined technique for ${taxonomyKey}. Resubmit with one of: ${remainingTechniques(params.vrt_category, []).join(", ")}.`,
        metadata: { entryID: params.entry_id, category: params.vrt_category, status: "pending" },
      }
    }

    // Gate 1 (plan_A1.md §4.3): a "tested_not_vulnerable" close is a claim of
    // absence — one shallow technique isn't evidence of that. Accumulate the
    // technique list across calls and require enough distinct entries (or an
    // explicit justification) before the close is accepted. For taxonomy
    // categories the threshold is ~60% of the known technique list
    // (requiredCount); categories without a taxonomy fall back to 2. This holds
    // regardless of whether the model *feels* done — same rationale as the
    // lane-discipline gate above (see vuln-scope.ts comment: "prompt rules
    // can't stop" this class of drift).
    const existing = Intel.getVrtCheck(sessionID, params.entry_id, params.vrt_category)
    const techniquesAttempted = Array.from(new Set([...(existing?.techniquesAttempted ?? []), submittedTechnique]))
    const required = requiredCount(params.vrt_category)

    if (
      params.status === "tested_not_vulnerable" &&
      techniquesAttempted.length < required &&
      !params.single_technique_justification
    ) {
      // Record progress (technique + evidence so far) without closing the
      // check — status stays "pending" so coverage/force-continue correctly
      // still see this as untested.
      Intel.updateVrtCheck(sessionID, params.entry_id, params.vrt_category, {
        status: "pending",
        technique: params.technique,
        techniquesAttempted,
        testedBy: ctx.agent,
        evidence: params.evidence as Record<string, unknown>,
      })
      const remaining = remainingTechniques(params.vrt_category, techniquesAttempted)
      return {
        title: `VRT: ${params.vrt_category} — ${techniquesAttempted.length}/${required} techniques, needs more before closing`,
        output: [
          `Recorded technique "${params.technique}" for ${params.vrt_category} on entry ${params.entry_id} — not closed yet.`,
          `${techniquesAttempted.length}/${required} required techniques attempted: [${techniquesAttempted.join(", ")}].` +
            (remaining.length > 0
              ? ` Try at least ${required - techniquesAttempted.length} more from: [${remaining.join(", ")}].`
              : ` Try at least ${required - techniquesAttempted.length} more distinct technique(s) before calling update_vrt_check again with status "tested_not_vulnerable".`),
          `If this category genuinely has only one applicable technique for this entry, resubmit with ` +
            `\`single_technique_justification\` explaining why (min 40 chars).`,
        ].join("\n"),
        metadata: { entryID: params.entry_id, category: params.vrt_category, status: "pending" },
      }
    }

    Intel.updateVrtCheck(sessionID, params.entry_id, params.vrt_category, {
      status: params.status,
      technique: params.technique,
      techniquesAttempted,
      justification: params.single_technique_justification,
      testedBy: ctx.agent,
      evidence: params.evidence as Record<string, unknown>,
    })

    const icon =
      params.status === "tested_vulnerable"
        ? "VULNERABLE"
        : params.status === "tested_not_vulnerable"
          ? "NOT VULNERABLE"
          : "N/A"

    return {
      title: `VRT: ${params.vrt_category} — ${icon}`,
      output: `Updated VRT check for entry ${params.entry_id}: ${params.vrt_category} = ${icon}${params.technique ? ` (technique: ${params.technique})` : ""}`,
      metadata: { entryID: params.entry_id, category: params.vrt_category, status: params.status },
    }
  },
})
