/** Capability catalog, intents, DLP, injection detection and loop heuristics (design §5, §6, §7). */

export const POLICY_VERSION = "2026.10.1-mvp";

export type Risk = "low" | "medium" | "high" | "critical";
export interface CapabilityDef { id: string; risk: Risk; default: boolean; pregrantable: boolean; perUseApproval: boolean; desc: string }

export const CAPABILITIES: Record<string, CapabilityDef> = {
  "chat.public": { id: "chat.public", risk: "low", default: true, pregrantable: true, perUseApproval: true, desc: "General chat (public information only)" },
  "profile.read": { id: "profile.read", risk: "low", default: true, pregrantable: true, perUseApproval: false, desc: "Read public profile" },
  "calendar.freebusy.read": { id: "calendar.freebusy.read", risk: "medium", default: false, pregrantable: true, perUseApproval: false, desc: "Query busy/free intervals (no details)" },
  "calendar.book": { id: "calendar.book", risk: "high", default: false, pregrantable: true, perUseApproval: true, desc: "Book meetings (approved each time)" },
  "commitment.make": { id: "commitment.make", risk: "high", default: false, pregrantable: false, perUseApproval: true, desc: "Make commitments (approved each time)" },
  "data.share.private": { id: "data.share.private", risk: "high", default: false, pregrantable: false, perUseApproval: true, desc: "Share non-public information" },
  "payment.initiate": { id: "payment.initiate", risk: "critical", default: false, pregrantable: false, perUseApproval: true, desc: "Payments (not supported in MVP)" },
  "message.external": { id: "message.external", risk: "high", default: false, pregrantable: false, perUseApproval: true, desc: "Messages outside the platform (not supported in MVP)" },
};

export const DEFAULT_CAPABILITIES = Object.values(CAPABILITIES).filter((c) => c.default).map((c) => c.id);
export const MVP_GRANTABLE = ["chat.public", "profile.read", "calendar.freebusy.read", "calendar.book"];

/** Conversations have no turn limit (owner decision 2026-10-19 18:05): only rate limits, loop detection for Bot-written lines, and expiry bound them. */
export interface IntentDef { type: string; allowed: string[] }
export const INTENTS: Record<string, IntentDef> = {
  schedule_meeting: { type: "schedule_meeting", allowed: ["chat.public", "profile.read", "calendar.freebusy.read", "calendar.book", "commitment.make"] },
  general_chat: { type: "general_chat", allowed: ["chat.public", "profile.read"] },
};

/** Action types bots may draft, with the capability they exercise. */
export const ACTIONS: Record<string, { capability: string; sensitivity: Risk; reasons: string[] }> = {
  "calendar.book": { capability: "calendar.book", sensitivity: "high", reasons: ["action.commitment", "calendar.write"] },
  "calendar.accept_invite": { capability: "commitment.make", sensitivity: "high", reasons: ["action.commitment"] },
};

/** A positive integer from an env value, else the fallback (unset, empty, zero, negative or not a number). */
export function limitFromEnv(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return value !== undefined && value.trim() !== "" && Number.isInteger(n) && n > 0 ? n : fallback;
}

export const DEFAULT_NEW_CONVERSATIONS_PER_PAIR_PER_DAY = 50;

export const LIMITS = {
  ratePerConversationPerMin: 6,
  ratePerBotPerHour: 60,
  // New conversations per relationship in a rolling 24 h; override with BOTSOCIAL_NEW_CONVERSATIONS_PER_PAIR_PER_DAY.
  // A getter, not a module-level value: botsocial.env is loaded before the server starts, and a module constant
  // would have frozen whatever process.env held when policy.ts happened to be imported.
  get newConversationsPerPairPerDay() {
    return limitFromEnv(process.env.BOTSOCIAL_NEW_CONVERSATIONS_PER_PAIR_PER_DAY, DEFAULT_NEW_CONVERSATIONS_PER_PAIR_PER_DAY);
  },
  tsSkewMs: 5 * 60 * 1000,
  nonceTtlMs: 10 * 60 * 1000,
  approvalTtlMs: 24 * 3600 * 1000,
  meetingApprovalTtlMs: 4 * 3600 * 1000,
  relationshipRequestTtlMs: 7 * 24 * 3600 * 1000,
  declineCooldownMs: 30 * 24 * 3600 * 1000,
  grantDefaultDays: 90,
};

// ---------------------------------------------------------------- DLP
export interface DlpHit { category: string; action: "block" | "approve"; label: string }

function luhn(num: string): boolean {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = +num[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function cnIdValid(id: string): boolean {
  const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const c = "10X98765432";
  let s = 0;
  for (let i = 0; i < 17; i++) s += +id[i] * w[i];
  return c[s % 11] === id[17].toUpperCase();
}

export function dlpScan(text: string, ownerTerms: string[] = []): DlpHit[] {
  const hits: DlpHit[] = [];
  const add = (category: string, action: DlpHit["action"], label: string) => { if (!hits.some((h) => h.category === category)) hits.push({ category, action, label }); };
  for (const m of text.match(/\b\d{17}[\dXx]\b/g) ?? []) if (cnIdValid(m)) add("pii.national_id", "block", "National ID number");
  for (const m of text.match(/\b(?:\d[ -]?){13,19}\b/g) ?? []) { const d = m.replace(/\D/g, ""); if (d.length >= 13 && d.length <= 19 && luhn(d)) add("pii.bank_card", "block", "Bank card number"); }
  if (/\b[EeGg]\d{8}\b/.test(text)) add("pii.passport", "block", "Passport number");
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) add("secret.private_key", "block", "Private key");
  if (/\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|xox[abp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/.test(text)) add("secret.api_key", "block", "API Key / Token");
  if (/(password|passwd|密码)\s*[:：=]\s*\S+/i.test(text)) add("secret.password", "block", "Password");
  if (/(?<!\d)1[3-9]\d{9}(?!\d)/.test(text) || /\+\d{1,3}[ -]?\d{6,}/.test(text)) add("pii.phone", "approve", "Phone number");
  if (/[\w.+-]+@[\w-]+\.[\w.-]+/.test(text)) add("pii.email", "approve", "Email address");
  if (/(¥|￥|\$|USD|RMB|元)\s*\d|\d+\s*(元|块钱|美元)/.test(text)) add("money", "approve", "Money amount");
  // No commitment-language scan (#13): promises in prose (保证, 一定会, 我答应, "I promise") are the Bot's call, made from its
  // own instructions, not a keyword here. Binding actions stay gated by capability (commitment.make, calendar.book, …).
  for (const t of ownerTerms) if (t && text.toLowerCase().includes(t.toLowerCase())) add("owner.sensitive_term", "approve", `Owner sensitive term`);
  return hits;
}

/** Flag outbound text that leaks owner calendar details (titles/locations of busy entries). */
export function calendarDetailLeak(text: string, details: string[]): boolean {
  return details.some((d) => d && d.length >= 2 && text.includes(d));
}

// ---------------------------------------------------------------- injection
const INJECTION_PATTERNS = [
  /ignore (all |any )?(previous|prior|above) (instructions|prompts)/i,
  /忽略(之前|以上|前面|先前)的?(所有)?(指令|提示|设定)/,
  /(system prompt|系统提示|developer message)/i,
  /(you are now|从现在起你是|扮演)/i,
  /(把|将).{0,20}(所有|全部).{0,20}(发给我|发送给我|告诉我)/,
  /(send|forward|reveal|leak) (me )?(all|every|your owner'?s?)/i,
  /\[(SYSTEM|ADMIN|PLATFORM)\]|<\/?system>/i,
  /(api[_ ]?key|password|密码|token|私钥)/i,
];

export function detectInjection(text: string): { suspected: boolean; matches: string[] } {
  const matches = INJECTION_PATTERNS.filter((p) => p.test(text)).map((p) => p.source);
  return { suspected: matches.length > 0, matches };
}

// ---------------------------------------------------------------- loops
const PLEASANTRY = /^(谢谢|多谢|不客气|好的|收到|祝好|再见|没问题|thanks?( you)?|thank you|you'?re welcome|ok(ay)?|cheers|bye|great|sounds good|have a (nice|great) day)[!！。.~\s]*$/i;

export const normalize = (t: string) => t.toLowerCase().replace(/[\s\p{P}]+/gu, "");

/**
 * Rule-based loop detection (MVP replacement for embedding similarity). It guards Bot-to-Bot
 * exchanges only: the platform skips it for a line the owner typed (server-attested typed_by_owner).
 * - the new text duplicates one of the last 3 messages, or
 * - the new message plus the previous 3 are all content-free pleasantries.
 */
export function detectLoop(recent: { text: string; structured: boolean }[], next: { text: string; structured: boolean }): boolean {
  const n = normalize(next.text);
  if (!next.structured && n && recent.slice(-3).some((m) => !m.structured && normalize(m.text) === n)) return true;
  const window = [...recent.slice(-3), next];
  return window.length >= 4 && window.every((m) => !m.structured && PLEASANTRY.test(m.text.trim()));
}
