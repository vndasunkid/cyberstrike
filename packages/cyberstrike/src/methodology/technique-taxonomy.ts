// ============================================================
// TECHNIQUE TAXONOMY — Gate 1 v2 (plan_A1.md §4.3, hướng B)
//
// Danh sách kỹ thuật hợp lệ CỐ ĐỊNH cho từng VRT category, đối chiếu trực
// tiếp với nội dung thật trong .cyberstrike/skill/WEB/OWASP_WSTG_4.2/*.
// Category không có mặt ở đây → Gate 1 rơi về luật cũ (≥2 kỹ thuật free-text)
// để không chặn oan trong lúc taxonomy chưa phủ hết.
//
// Đã wire vào tool/vrt-check.ts (Gate 1 v2).
// ============================================================

export const TECHNIQUE_TAXONOMY: Record<string, string[]> = {
  // wstg-inpv-05
  SQLi: ["error-based", "boolean-blind", "time-blind", "union-based", "waf-bypass", "second-order", "oob-dns"],

  // wstg-inpv-01 / wstg-inpv-02 / wstg-clnt-01
  XSS: ["reflected", "stored", "dom-based", "header-based", "encoding-bypass", "polyglot"],

  // NoSQL injection (Mongo-style operators)
  NoSQLi: ["operator-injection", "auth-bypass-operator", "blind-nosqli"],

  // SSTI (template engines)
  SSTI: ["basic-payload", "blind-oob", "sandbox-escape"],

  // Command Injection
  "Command Injection": ["direct-concat", "blind-time-based", "out-of-band"],

  // wstg-inpv-07
  XXE: ["external-entity-file-read", "blind-oob", "billion-laughs", "parameter-entity"],

  // LDAP injection (ít gặp, taxonomy ngắn)
  "LDAP Injection": ["filter-injection", "blind-boolean"],

  // wstg-authz-04, proxy-tester-idor prompt
  IDOR: ["sequential-id", "cross-credential-swap", "uuid-manipulation", "batch-array"],

  // wstg-authz-01/02/03, proxy-tester-authz
  "Auth Bypass": ["vertical-privesc", "horizontal-privesc", "method-tampering", "forced-browsing", "cors-misconfig"],

  // wstg-athn-*, wstg-auth-session, proxy-tester-authn
  // "parameter-omission" và "client-validation-bypass" thêm sau khi đối chiếu
  // với case Juice Shop thật (Change Bender's Password, Repetitive Registration
  // — xem tonghop.md mục kiểm tra chéo taxonomy).
  Authentication: [
    "default-creds",
    "brute-force",
    "jwt-alg-none",
    "jwt-weak-secret",
    "jwt-kid-injection",
    "session-fixation",
    "password-reset-flaw",
    "parameter-omission",
    "client-validation-bypass",
  ],

  // wstg-inpv-19
  SSRF: ["cloud-metadata", "internal-ip", "dns-rebind", "protocol-smuggle", "blind-oob"],

  // wstg-busl-08/09, proxy-tester-file-attacks
  // "size-limit-bypass" thêm sau đối chiếu case Juice Shop "Upload Size"
  "File Attacks": [
    "extension-bypass",
    "path-traversal",
    "zip-slip",
    "xxe-via-upload",
    "magic-byte-spoof",
    "polyglot-file",
    "size-limit-bypass",
  ],

  // wstg-inpv-20, wstg-busl-02, proxy-tester-mass-assignment
  "Mass Assignment": ["role-field-injection", "price-field-injection", "ownership-field-injection"],

  // wstg-busl-04/05, wstg-logic-client-api (LƯU Ý: skill này là phantom — xem tonghop.md mục 5)
  // "price-tampering" thêm sau đối chiếu case Juice Shop "Deluxe Fraud".
  // Race condition KHÔNG nằm ở đây — phase.ts sinh "Race Condition" như category
  // riêng (endpoint, authentication_flow type), tách hẳn khỏi "Business Logic".
  "Business Logic": ["workflow-step-skip", "negative-value", "integer-overflow", "price-tampering"],

  // MỚI — phase.ts VRT_CATEGORIES_BY_TYPE sinh "Race Condition" độc lập cho
  // type "endpoint" và "authentication_flow". Trước đó bị gộp nhầm vào Business
  // Logic nên không bao giờ khớp category thật hệ thống tự sinh ra.
  // Case Juice Shop: Multiple Likes.
  "Race Condition": ["parallel-request", "toctou", "state-manipulation"],

  // MỚI — phase.ts, type "credential"
  "Privilege Escalation": ["vertical-privesc", "horizontal-privesc", "credential-abuse"],

  // MỚI — phase.ts, type "technology" (tech-stack fingerprinting, thường do
  // web-application/cloud-security agent phụ trách, không qua pipeline proxy)
  "Known CVE": ["version-fingerprint-cve-lookup", "public-exploit-verification"],
  "Framework Vuln": ["default-config-check", "known-misconfig-pattern"],

  // MỚI — phase.ts, type "configuration"
  "Config Manipulation": ["parameter-pollution", "config-endpoint-write", "feature-flag-tamper"],

  // MỚI — phase.ts, type "infrastructure" (tách khỏi Authentication vì đây là
  // category riêng hệ thống tự sinh, ưu tiên thấp hơn với web pentest — chủ
  // yếu dùng bởi cloud-security/internal-network agent)
  "Default Creds": ["known-vendor-default", "blank-password", "admin-admin"],

  // wstg-cryp-04 — MỚI: chưa có lane tester nào phụ trách (không nằm trong
  // TESTER_VRT_SCOPE của vuln-scope.ts) — cần gán tạm vào "business-logic"
  // khi wire vào pipeline, hoặc tạo lane riêng. Case Juice Shop: Forged Coupon.
  "Weak Crypto": ["base64-decode-analysis", "ecb-pattern-detection", "predictable-token", "coupon-forge"],

  // wstg-clnt-04 — MỚI: cũng chưa có lane tester riêng (gần "authz" nhất vì
  // là redirect/access-control liên quan). Case Juice Shop: Allowlist Bypass.
  "Open Redirect": ["at-symbol-bypass", "subdomain-confusion", "nested-url-bypass", "protocol-relative-bypass"],

  // wstg-conf-04/05, wstg-info-02
  "Info Disclosure": ["backup-files", "verbose-errors", "security-headers", "directory-listing", "banner-grab"],

  // attack_script: subdomain_takeover
  "Subdomain Takeover": ["dangling-cname"],

  // attack_script: cors_checker
  CORS: ["wildcard-origin", "reflected-origin", "null-origin"],
}

const MIN_COVERAGE_RATIO = 0.6

/** Số kỹ thuật tối thiểu cần thử trước khi được đóng "tested_not_vulnerable".
 *  Category chưa có taxonomy → fallback 2 (luật cũ). Dùng resolveCategory() để
 *  category tự do ("sql injection") vẫn khớp đúng key ("SQLi") — nhất quán với
 *  isValidTechnique()/remainingTechniques(). */
export function requiredCount(category: string): number {
  const key = resolveCategory(category)
  if (!key) return 2
  return Math.max(1, Math.ceil(TECHNIQUE_TAXONOMY[key]!.length * MIN_COVERAGE_RATIO))
}

/** Chuẩn hoá tên category tự do (agent gõ "sql injection", "SQLI"...) về đúng
 *  key trong taxonomy. Cùng kiểu matching với categoryInLane() trong vuln-scope.ts. */
export function resolveCategory(raw: string): string | undefined {
  const norm = raw.toLowerCase().trim()
  return Object.keys(TECHNIQUE_TAXONOMY).find(
    (k) => k.toLowerCase() === norm || norm.includes(k.toLowerCase()) || k.toLowerCase().includes(norm),
  )
}

/** Technique hợp lệ cho category này? Category chưa có taxonomy → luôn true (free-text vẫn được). */
export function isValidTechnique(category: string, technique: string): boolean {
  const key = resolveCategory(category)
  if (!key) return true
  return TECHNIQUE_TAXONOMY[key]!.includes(technique.trim().toLowerCase())
}

/** Danh sách kỹ thuật chưa thử, dùng để nhắc agent trong message từ chối. */
export function remainingTechniques(category: string, attempted: string[]): string[] {
  const key = resolveCategory(category)
  if (!key) return []
  const attemptedSet = new Set(attempted.map((t) => t.toLowerCase()))
  return TECHNIQUE_TAXONOMY[key]!.filter((t) => !attemptedSet.has(t))
}
