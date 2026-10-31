import Database from "better-sqlite3";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { AuditLog } from "./audit.js";
import { openDb } from "./db.js";
import { ApiError, assert } from "./errors.js";
import { newId, randomToken } from "./ids.js";
import { seal, unseal, publicRawFromPrivatePem } from "./custody.js";
import { Envelope, envelopeSigningInput, generateEd25519, signEnvelope, hashToken, jcs, payloadDigest, signString, verifyString, webhookSignature, publicKeyFromRaw } from "./crypto.js";
import { ACTIONS, CAPABILITIES, DEFAULT_CAPABILITIES, INTENTS, LIMITS, MVP_GRANTABLE, POLICY_VERSION, calendarDetailLeak, detectInjection, detectLoop, dlpScan } from "./policy.js";
import { WebhookOptions, WebhookPusher, redactHeaders, redactUrl, validateHeaders, validateUrl } from "./webhooks.js";
import { AttachmentLimits, AttachmentRef, DEFAULT_ATTACHMENT_LIMITS, checkFile, humanSize, refOf, sealBytes, sha256Hex, unsealBytes } from "./attachments.js";
import { avatarFingerprint, lookOf, validateAvatar, validateColor } from "./bot-look.js";
import { PRESENCE_DEFAULT_TTL_S, PRESENCE_MAX_TTL_S, PRESENCE_MIN_TTL_S, PRESENCE_WRITES_PER_MIN, PresenceStore } from "./presence.js";
import { ianaTimezone, isoInTz, localMinutes, localWeekday, overlaps, parseHours } from "./time.js";
import {
  FACE_ROOM_NAME_MAX, FACE_ROOM_ROLE_MAX, FaceRoomLimits, isFaceCode, isInviteTicket, joinSystemText, leadSystemText, leaveSystemText, loadFaceRoomLimits, memberLabel, newInviteTicket, peerBotName, peerDisplayName, peerOwnerName, sanitizePeerName,
} from "./face-rooms.js";
import { LOCAL_INVITE_MAX_BOTS, LOCAL_INVITE_NO_DEADLINE, isLocalInviteTicket, isLocalRoomId, newLocalInviteTicket } from "./local-room-invites.js";

export type Principal = { kind: "owner"; ownerId: string; scope?: "connector"; tokenId?: string; attestTyped?: boolean } | { kind: "bot"; botId: string; ownerId: string };

/** Comparison key for a Bot handle: surrounding spaces and an optional leading `@` removed, lowercased.
 *  Writes store this form; lookups compare `LOWER(handle)` with it, so `@Zed.Bot` and `@zed.bot` are one Bot. */
const handleKey = (ref: unknown) => String(ref ?? "").trim().replace(/^@/, "").toLowerCase();
/** The handle as the caller spelled it (spaces and one leading `@` removed, case kept). */
const handleRef = (ref: unknown) => String(ref ?? "").trim().replace(/^@/, "");
/** A reference that names rows differing only by case is refused, never guessed. */
const ambiguous = (raw: string, n: number) => new ApiError(409, "ambiguous_handle", `"${raw}" matches ${n} Bots that differ only by case; name the exact handle`);
/** In-memory version of the same rule: exact spelling wins, else the unique case-insensitive match. */
const pickByHandle = <T extends { handle?: string | null }>(rows: T[], ref: unknown): T | undefined => {
  const raw = handleRef(ref);
  if (!raw) return undefined;
  const exact = rows.find((r) => String(r.handle ?? "").replace(/^@/, "") === raw);
  if (exact) return exact;
  const ci = rows.filter((r) => handleKey(r.handle) === raw.toLowerCase());
  if (ci.length > 1) throw ambiguous(raw, ci.length);
  return ci[0];
};

/**
 * A row of `relationships`: the two endpoint Bots and the owners behind them. One pair can hold several rows —
 * a friendship (`active`) and one `room` row per shared room — and code that picks a door must say which one.
 */
export type Relationship = { id: string; requester_bot: string; target_bot: string; requester_owner: string; target_owner: string; status: string; created_at: string; updated_at: string; [column: string]: any };

export interface PlatformOptions { kmsKey?: Buffer; dbPath?: string; auditPath?: string; publicBaseUrl?: string; fetchImpl?: typeof fetch; webhooks?: WebhookOptions; attachments?: Partial<AttachmentLimits>; now?: () => number; faceRooms?: Partial<FaceRoomLimits> }

/**
 * Why a held send waits (#49), so a client branches on one field instead of reading `policy.reasons`.
 * The strongest finding wins: risk > attachment > policy > blanket_outbound. `blanket_outbound` is the
 * owner's own default hold and the only one a connector may decide; everything else is the owner's.
 *
 * `face_room_auto_send_off` (#49 follow-up) is a face-room draft that nothing else holds: the room's own
 * Auto-send switch is off. It cannot be folded into `blanket_outbound`, or a connector allowed to clear a
 * blanket hold could clear this card too and send into a room whose Auto-send the owner turned off.
 */
export type HoldReason = "blanket_outbound" | "risk" | "attachment" | "policy" | "face_room_auto_send_off";
export function holdReasonOf(found: { riskFlags?: readonly unknown[]; attachments?: readonly unknown[]; injectionSuspected?: boolean } = {}): HoldReason {
  if ((found.riskFlags?.length ?? 0) > 0) return "risk";
  if ((found.attachments?.length ?? 0) > 0) return "attachment";
  if (found.injectionSuspected) return "policy";
  return "blanket_outbound";
}

const nowIso = () => new Date().toISOString();
/** Why a home could not hand a delivered message to its Bot (reportNotDelivered). A fixed list: the sender is shown a fixed line. */
const NOT_DELIVERED_REASONS = ["not_shared_yet"];
/** A join budget counts real door checks only, both the 6-digit code and the invite ticket. A request refused
 *  for being over budget is not another check, so counting it cannot keep the budget full by itself. */
const FACE_JOIN_OUTCOMES = ["invalid_code", "room_full", "code_void", "created", "joined", "rejoined",
  "invited", "already_member", "invite_not_found", "ended", "revoked", "expired",
  "claimed", "already_claimed", "bot_revoked"];
/** Invite previews are reads: they get their own per-address budget and never spend the join one. */
const FACE_PREVIEW_OUTCOMES = ["preview", "invite_not_found", "ended", "revoked", "expired"];
const J = (s: string | null | undefined, d: any = null) => (s ? JSON.parse(s) : d);
const ms = (iso: string) => {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new ApiError(400, "invalid_time", `bad timestamp: ${iso}`);
  return t;
};

function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString("hex")}$${scryptSync(pw, salt, 32).toString("hex")}`;
}
function checkPassword(pw: string, stored: string): boolean {
  const [, salt, hash] = stored.split("$");
  const got = scryptSync(pw, Buffer.from(salt, "hex"), 32);
  return timingSafeEqual(got, Buffer.from(hash, "hex"));
}

/**
 * The core platform: identity, relationships, grants, conversations, approvals,
 * calendar capability (mock), events/webhooks and audit. HTTP / MCP layers are thin wrappers.
 */
/** Parse a stored mentions column (JSON array of handles, or null). */
function mentionsOf(raw: unknown): string[] {
  if (typeof raw !== "string" || !raw) return [];
  try { const v = JSON.parse(raw); return Array.isArray(v) ? v.filter((x) => typeof x === "string") : []; } catch { return []; }
}

/**
 * What an owner's edit may change on a held line: the text, the structured payload, the reply expectation. Nothing
 * else is merged into the delivered payload -- an attachment ref in an edit never passed the draft's attachment
 * checks, and `trust`, a mention list or a platform flag must never be writable through this door. `attachments: []`
 * is tolerated (the console sends the list back), but the draft's own refs are kept because the merge starts from
 * the signed payload. A refused edit throws before anything is written.
 */
function editedPayloadOf(body: any): { text: string; structured?: unknown; expects_reply?: boolean } {
  const ep = body?.edited_payload;
  assert(ep && typeof ep === "object" && !Array.isArray(ep), 400, "invalid_request", "edited_payload must be an object");
  assert(typeof ep.text === "string" && ep.text.length >= 1 && ep.text.length <= 4000, 400, "invalid_request", "edited_payload.text (1-4000 chars) required");
  const out: { text: string; structured?: unknown; expects_reply?: boolean } = { text: ep.text };
  if (ep.structured !== undefined) {
    assert(ep.structured === null || (typeof ep.structured === "object" && !Array.isArray(ep.structured)), 400, "invalid_request", "edited_payload.structured must be an object or null");
    out.structured = ep.structured;
  }
  if (ep.expects_reply !== undefined) {
    assert(typeof ep.expects_reply === "boolean", 400, "invalid_request", "edited_payload.expects_reply must be a boolean");
    out.expects_reply = ep.expects_reply;
  }
  const atts = ep.attachments;
  assert(atts === undefined || (Array.isArray(atts) && atts.length === 0), 400, "invalid_request", "attachments cannot be added or changed at approval; edit the draft instead");
  return out;
}

/** An owner-side write body is a JSON object or absent. `null` is normalised to `{}` by the route, and `{}` is a
 *  legal "take the default" body; a string, number, boolean or array is a 400. Without this, `POST /v1/invites`
 *  with `"x"` minted a live link for the caller's oldest Bot. */
function ownerWriteBody(body: any): any {
  if (body === undefined) return {};
  assert(body !== null && typeof body === "object" && !Array.isArray(body), 400, "invalid_request", "body must be a JSON object");
  return body;
}

/** #211: capabilities whose implementation reads a grant's `scope`. Free/busy is the only one: it bounds the
 *  query by `window_days` and `hours` (`freebusy`); every other capability ignores `scope`, so a scope sent
 *  with it is refused instead of stored with no effect. */
const SCOPED_CAPABILITIES = new Set(["calendar.freebusy.read"]);

export class Platform {
  db: Database.Database;
  audit: AuditLog;
  platformKey = generateEd25519();
  platformKid = "platform_" + new Date().toISOString().slice(0, 7).replace("-", "_");
  publicBaseUrl: string;
  private fetchImpl: typeof fetch;
  readonly webhooks: WebhookPusher;

  private kmsKey: Buffer;
  readonly attachmentLimits: AttachmentLimits;
  readonly faceRoomLimits: FaceRoomLimits;
  /** Ephemeral "thinking" signals (memory only, see presence.ts). */
  readonly presence = new PresenceStore();
  nowMs: () => number;
  constructor(opts: PlatformOptions = {}) {
    this.attachmentLimits = { ...DEFAULT_ATTACHMENT_LIMITS, ...Object.fromEntries(Object.entries(opts.attachments ?? {}).filter(([, v]) => typeof v === "number" && v > 0)) };
    this.faceRoomLimits = loadFaceRoomLimits(opts.faceRooms);
    this.nowMs = opts.now ?? (() => Date.now());
    this.db = openDb(opts.dbPath ?? ":memory:");
    this.audit = new AuditLog(opts.auditPath ?? ":memory:");
    this.publicBaseUrl = opts.publicBaseUrl ?? "http://localhost:8787";
    this.kmsKey = opts.kmsKey ?? randomBytes(32);
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.webhooks = new WebhookPusher(this.db, this.fetchImpl, () => this.publicBaseUrl, opts.webhooks);
    this.audit.append("platform", "platform.started", null, [], { policy_version: POLICY_VERSION, platform_kid: this.platformKid, platform_public_key: this.platformKey.publicKey });
  }
  private ts() { return new Date(this.nowMs()).toISOString(); }

  close() { this.webhooks.stop(); this.db.close(); this.audit.db.close(); }
  /** Send queued (debounced) webhook pushes now and wait for them. */
  async flushWebhooks() { await this.webhooks.flush(); }

  // ================================================================ helpers
  private get<T = any>(sql: string, ...args: unknown[]): T | undefined { return this.db.prepare(sql).get(...args) as T | undefined; }
  private all<T = any>(sql: string, ...args: unknown[]): T[] { return this.db.prepare(sql).all(...args) as T[]; }
  private run(sql: string, ...args: unknown[]) { return this.db.prepare(sql).run(...args); }

  bot(id: string) {
    const b = this.get("SELECT * FROM bots WHERE id = ?", id);
    assert(b, 404, "bot_not_found", `bot ${id} not found`);
    return b;
  }
  botByHandle(handle: string) {
    const b = this.botByRef(handle);
    assert(b, 404, "bot_not_found", `bot ${handle} not found`);
    return b;
  }

  /** Bot lookup by handle: the exact spelling wins; only when nothing matches exactly does the unique
   *  case-insensitive match count. Two rows that differ only by case make a case-variant reference
   *  ambiguous — refuse rather than silently pick one, so an old mixed-case row cannot shadow the real Bot. */
  private botByRef(ref: unknown, where = "", args: unknown[] = []) {
    const raw = handleRef(ref);
    if (!raw) return undefined;
    const tail = where ? ` AND ${where}` : "";
    const exact = this.get(`SELECT * FROM bots WHERE handle = ?${tail}`, raw, ...args);
    if (exact) return exact;
    const rows = this.all(`SELECT * FROM bots WHERE LOWER(handle) = ?${tail}`, raw.toLowerCase(), ...args);
    if (rows.length > 1) throw ambiguous(raw, rows.length);
    return rows[0];
  }
  owner(id: string) {
    const o = this.get("SELECT * FROM owners WHERE id = ?", id);
    assert(o, 404, "owner_not_found");
    return o;
  }
  /** Two different things here, and only one of them is opt-in.
   *  `look` (avatar/color) is opt-in per call site: it is added only where the viewer may already see the Bot
   *  (own bots, active friends, grants, profile.read).
   *  `display_name` and `owner_display_name` are not opt-in: they are the peer's own names, written by the
   *  peer's owner, and they reach every surface that names a peer — events, messages, invites, pending
   *  requests and approval cards. They are cleaned here on read as well as on write, because rows written
   *  before the write-side check (legacy SQLite rows are the likeliest) may still hold control characters,
   *  an over-long name or an empty string. */
  private publicBot(b: any, look = false) {
    const o = this.owner(b.owner_id);
    return { bot_id: b.id, handle: "@" + b.handle, display_name: peerBotName(b), owner_display_name: peerOwnerName(o), owner_verified: true, ...(look ? lookOf(b) : {}) };
  }
  private requireOwner(p: Principal): string {
    if (p.kind !== "owner") throw new ApiError(403, "owner_only", "this operation can only be performed by the owner");
    return p.ownerId;
  }
  private requireBot(p: Principal): { botId: string; ownerId: string } {
    if (p.kind !== "bot") throw new ApiError(403, "bot_only", "this operation must be performed with a bot token");
    return p;
  }

  /** Append an event to a bot's queue (pull via /v1/events or MCP) and push to its webhook if configured. */
  emit(botId: string, type: string, data: Record<string, unknown>) {
    const id = newId("evt");
    const created_at = nowIso();
    const info = this.run("INSERT INTO events (id, bot_id, type, data, created_at) VALUES (?,?,?,?,?)", id, botId, type, JSON.stringify(data), created_at);
    this.webhooks.enqueue(botId, { event_id: id, type, created_at, data });
    void info;
    return id;
  }

  private countersign(obj: Record<string, unknown>): string {
    return signString(this.platformKey.privateKeyPem, jcs(obj));
  }
  verifyCountersig(obj: Record<string, unknown>): boolean {
    const { platform_countersig, ...rest } = obj as any;
    return verifyString(this.platformKey.publicKey, jcs(rest), platform_countersig);
  }

  // ================================================================ owners & auth
  registerOwner(body: { username: string; display_name?: string; password: string; timezone?: string }) {
    assert(body?.username && /^[a-z0-9._-]{2,32}$/i.test(body.username), 400, "invalid_request", "username: 2-32 chars [a-z0-9._-]");
    assert(typeof body.password === "string" && body.password.length >= 6, 400, "invalid_request", "password must be >= 6 chars");
    assert(!this.get("SELECT 1 FROM owners WHERE username = ?", body.username), 409, "username_taken");
    assert(body.display_name === undefined || typeof body.display_name === "string", 400, "invalid_request", "display_name must be a string");
    const displayName = peerDisplayName(body.display_name, body.username);
    // Absent timezone keeps today's default; a supplied one must be a zone Intl can use (P5).
    const timezone = body.timezone ? this.validateTimezone(body.timezone) : "Asia/Shanghai";
    const id = newId("own");
    this.run("INSERT INTO owners (id, username, display_name, password_hash, timezone, created_at) VALUES (?,?,?,?,?,?)",
      id, body.username, displayName, hashPassword(body.password), timezone, nowIso());
    this.audit.append(`owner:${id}`, "owner.registered", id, [id], { username: body.username });
    return { owner_id: id, owner_token: this.issueToken("owner", id) };
  }

  /** Write-side IANA check (P5): Intl is the authority on what a zone name means, so a string it refuses is a
   *  400 invalid_timezone here instead of an owners row that 500s every calendar/freebusy answer later. */
  private validateTimezone(raw: unknown): string {
    const tz = ianaTimezone(raw);
    if (!tz) throw new ApiError(400, "invalid_timezone", 'timezone must be an IANA zone name, e.g. "Asia/Shanghai" or "UTC"');
    return tz;
  }

  login(body: { username: string; password: string }) {
    const o = this.get("SELECT * FROM owners WHERE username = ?", body?.username);
    if (!o || !checkPassword(String(body.password ?? ""), o.password_hash)) throw new ApiError(401, "invalid_credentials");
    this.audit.append(`owner:${o.id}`, "owner.login", o.id, [o.id]);
    return { owner_id: o.id, owner_token: this.issueToken("owner", o.id) };
  }

  /** Revoke the login token that made this request. The console's "Log out" used to forget the token locally
   *  only, so a copied token stayed valid. Connector tokens are deliberately not accepted here (they are
   *  listed and revoked separately); this signs out one login session, not every session of the owner. */
  logout(p: Principal, token: string | undefined) {
    const ownerId = this.requireOwner(p);
    const row = token
      ? this.get("SELECT * FROM tokens WHERE token_hash = ? AND kind = 'owner' AND scope IS NULL AND revoked_at IS NULL", hashToken(token))
      : undefined;
    assert(row && row.subject_id === ownerId, 401, "unauthorized", "invalid or revoked token");
    this.run("UPDATE tokens SET revoked_at = ? WHERE token_hash = ?", nowIso(), row.token_hash);
    this.audit.append(`owner:${ownerId}`, "owner.logout", ownerId, [ownerId], {});
    return { ok: true };
  }

  private issueToken(kind: "owner" | "bot", subject: string) {
    const t = randomToken(kind === "owner" ? "otk" : "btk");
    this.run("INSERT INTO tokens (token_hash, kind, subject_id, created_at) VALUES (?,?,?,?)", hashToken(t), kind, subject, nowIso());
    return t;
  }

  authenticate(token: string | undefined): Principal {
    assert(token, 401, "unauthorized", "missing bearer token");
    const row = this.get("SELECT * FROM tokens WHERE token_hash = ? AND revoked_at IS NULL", hashToken(token));
    assert(row, 401, "unauthorized", "invalid or revoked token");
    if (row.kind === "owner") {
      if (row.scope === "connector") {
        this.run("UPDATE tokens SET last_used_at = ? WHERE token_hash = ?", nowIso(), row.token_hash);
        return { kind: "owner", ownerId: row.subject_id, scope: "connector", tokenId: row.id, attestTyped: row.attest_typed === 1 };
      }
      // a login (owner console / REST) session is the person at the keyboard
      return { kind: "owner", ownerId: row.subject_id, attestTyped: true };
    }
    const b = this.bot(row.subject_id);
    return { kind: "bot", botId: b.id, ownerId: b.owner_id };
  }

  // ================================================================ connector tokens (owner MCP)
  /** Labelled, revocable owner token that only works at /mcp. Minting needs a full (login) owner token. */
  createConnectorToken(p: Principal, body: { label?: string; attest_typed_by_owner?: boolean }) {
    const ownerId = this.requireOwner(p);
    assert(p.kind === "owner" && !p.scope, 403, "forbidden", "a connector token cannot mint tokens");
    const label = String(body?.label ?? "Grok Bot").trim().slice(0, 60) || "Grok Bot";
    assert((this.get("SELECT COUNT(*) n FROM tokens WHERE kind='owner' AND scope='connector' AND subject_id = ? AND revoked_at IS NULL", ownerId).n) < 20, 409, "too_many_tokens", "revoke an old connector token first (max 20 active)");
    const id = newId("ctk");
    const token = randomToken("otk");
    const attest = body?.attest_typed_by_owner === true ? 1 : 0;
    this.run("INSERT INTO tokens (token_hash, kind, subject_id, created_at, id, label, scope, attest_typed) VALUES (?,?,?,?,?,?,?,?)", hashToken(token), "owner", ownerId, nowIso(), id, label, "connector", attest);
    this.audit.append(`owner:${ownerId}`, "connector_token.created", id, [ownerId], { label, attest_typed_by_owner: !!attest });
    return { token_id: id, label, token, attest_typed_by_owner: !!attest, ...this.connectorConfig(token) };
  }

  connectorConfig(token: string) {
    const url = `${this.publicBaseUrl}/mcp`;
    return {
      mcp_url: url,
      headers: { Authorization: `Bearer ${token}` },
      json_config: { mcpServers: { "bot-social": { type: "http", url, headers: { Authorization: `Bearer ${token}` } } } },
      paste_to_grok_bot: `Please add an MCP server (custom connector): name Bot Social, URL ${url}, transport Streamable HTTP, header Authorization: Bearer ${token}`,
    };
  }

  listConnectorTokens(p: Principal) {
    const ownerId = this.requireOwner(p);
    return this.all("SELECT id, label, created_at, last_used_at, revoked_at, attest_typed FROM tokens WHERE kind='owner' AND scope='connector' AND subject_id = ? ORDER BY created_at DESC", ownerId)
      .map((t) => ({ token_id: t.id, label: t.label, attest_typed_by_owner: t.attest_typed === 1, created_at: t.created_at, last_used_at: t.last_used_at, status: t.revoked_at ? "revoked" : "active", revoked_at: t.revoked_at }));
  }

  revokeConnectorToken(p: Principal, tokenId: string) {
    const ownerId = this.requireOwner(p);
    const t = this.get("SELECT * FROM tokens WHERE id = ? AND kind='owner' AND scope='connector' AND subject_id = ?", tokenId, ownerId);
    assert(t, 404, "token_not_found");
    if (!t.revoked_at) this.run("UPDATE tokens SET revoked_at = ? WHERE id = ?", nowIso(), tokenId);
    this.audit.append(`owner:${ownerId}`, "connector_token.revoked", tokenId, [ownerId], { label: t.label });
    return { token_id: tokenId, status: "revoked" };
  }

  /** One-step onboarding: new owner + their bot (platform-generated key) + a connector token. */
  onboard(body: { username?: string; password?: string; display_name?: string; bot_handle?: string; bot_display_name?: string; label?: string; integration_type?: string }, opts: { attestTyped?: boolean } = {}) {
    body = { ...(body ?? {}) };
    const generated: { username?: string; password?: string } = {};
    if (!body.username) {
      const base = String(body.display_name ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 16) || "owner";
      do { body.username = `${base}${randomBytes(3).toString("hex")}`; } while (this.get("SELECT 1 FROM owners WHERE username = ?", body.username));
      generated.username = body.username;
    }
    if (!body.password) { body.password = randomBytes(12).toString("base64url"); generated.password = body.password; }
    const handle = handleKey(body.bot_handle || `${body.username}.bot`);
    assert(/^[a-z0-9._-]{2,40}$/i.test(handle), 400, "invalid_request", "bot handle: 2-40 chars [a-z0-9._-]");
    // A brand-new owner cannot own an existing row yet, so this is always the generic (no-name) refusal.
    this.assertHandleFree(handle);
    let out: any;
    this.db.transaction(() => {
      const o = this.registerOwner(body as { username: string; password: string; display_name?: string });
      const p: Principal = { kind: "owner", ownerId: o.owner_id };
      const bot = this.registerBot(p, { handle, display_name: body.bot_display_name || body.display_name || handle, integration_type: body.integration_type || "grok-bot" });
      // custodial: the platform keeps the (generated) signing key encrypted, so the connector can chat
      this.storeCustody(bot.bot_id, bot.key.kid, bot.key.private_key_pem!);
      const conn = this.createConnectorToken(p, { label: body.label, attest_typed_by_owner: opts.attestTyped === true });
      out = {
        owner_id: o.owner_id, username: body.username,
        ...(generated.password ? { generated_password: generated.password, password_note: "auto-generated web login (for /ui); tell the owner once, do not store it" } : {}),
        bot: { bot_id: bot.bot_id, handle: bot.handle, custodial: true },
        connector: conn,
      };
    })();
    return out;
  }

  /** One-call onboarding for a FlyBot install: owner + custodial bot + connector token + optional push webhook. */
  onboardFlybot(body: { username?: string; password?: string; display_name?: string; bot_handle?: string; bot_display_name?: string; webhook_url?: string; webhook_headers?: unknown }) {
    body = { ...(body ?? {}) };
    if (body.webhook_url) validateUrl(body.webhook_url);
    // The bot made here is the owner's FlyBot home (e.g. @danyang.home); local Bots join it as members.
    const base = String(body.display_name ?? body.username ?? "owner").toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 20) || "owner";
    const out = this.onboard({ ...body, bot_handle: body.bot_handle || `${base}.home`, label: "FlyBot", integration_type: "flybot-home" }, { attestTyped: true });
    const p: Principal = { kind: "owner", ownerId: out.owner_id };
    let webhook: unknown = null;
    if (body.webhook_url) {
      this.setWebhook(p, out.bot.bot_id, { url: body.webhook_url, ...(body.webhook_headers !== undefined ? { headers: body.webhook_headers } : {}) });
      const row = this.get("SELECT webhook_url, webhook_secret FROM bots WHERE id = ?", out.bot.bot_id);
      webhook = { url: row.webhook_url, secret: row.webhook_secret, signature_header: "x-botsocial-signature", timestamp_header: "x-botsocial-timestamp", signature_scheme: "v1=hex(HMAC-SHA256(secret, `${timestamp}.${body}`))" };
    }
    return { ...out, home: out.bot, mcp_url: `${this.publicBaseUrl}/mcp`, webhook };
  }

  private ownHome(ownerId: string, homeId: string) {
    const home = this.get("SELECT * FROM bots WHERE id = ? AND owner_id = ?", homeId, ownerId) ?? this.botByRef(homeId, "owner_id = ?", [ownerId]);
    assert(home && home.integration_type === "flybot-home", 404, "home_not_found", "no FlyBot home with that id for this owner");
    return home;
  }

  /** Registers (or reactivates) a local FlyBot Bot as @<name>.<home>, its key custodied with the home. */
  addHomeMember(p: Principal, homeId: string, body: { name?: string; display_name?: string; local_id?: string; avatar?: string | null; color?: string | null }) {
    const ownerId = this.requireOwner(p);
    assert(body?.display_name === undefined || typeof body.display_name === "string", 400, "invalid_request", "display_name must be a string");
    const home = this.ownHome(ownerId, homeId);
    const look = { avatar: body?.avatar !== undefined ? validateAvatar(body.avatar) : undefined, color: body?.color !== undefined ? validateColor(body.color) : undefined };
    const room = 40 - home.handle.length - 1;
    assert(room >= 2, 400, "invalid_request", "home handle too long for members");
    const name = String(body?.name ?? "").toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, room);
    assert(name.length >= 1, 400, "invalid_request", "member name required");
    const handle = `${name}.${handleKey(home.handle)}`;
    const existing = this.botByRef(handle);
    if (existing) {
      assert(existing.home_bot_id === home.id, 409, "handle_taken");
      // Re-adding the name is the documented way back from a removal (#173) and also lifts an emergency stop, so the
      // row can move `revoked`/`frozen` -> `active` here. That is a state change and is audited like every other one.
      // Re-adding a member that is already active is the idempotent upsert FlyBot does on every start: no entry.
      const previousStatus = existing.status;
      this.run("UPDATE bots SET status = 'active', display_name = ? WHERE id = ?", peerDisplayName(body?.display_name, existing.display_name || handle), existing.id);
      this.applyLook(existing.id, look);
      if (previousStatus !== "active") this.audit.append(`owner:${ownerId}`, "home.member_reactivated", existing.id, [ownerId], { home: home.id, from: previousStatus });
      return { bot_id: existing.id, handle: "@" + handle, home: "@" + home.handle, status: "active", reactivated: true };
    }
    const bot = this.registerBot(p, { handle, display_name: body?.display_name || name, integration_type: "flybot-member" });
    this.run("UPDATE bots SET home_bot_id = ? WHERE id = ?", home.id, bot.bot_id);
    this.applyLook(bot.bot_id, look);
    this.storeCustody(bot.bot_id, bot.key.kid, bot.key.private_key_pem!);
    this.audit.append(`owner:${ownerId}`, "home.member_added", bot.bot_id, [ownerId], { home: home.id, handle });
    return { bot_id: bot.bot_id, handle: bot.handle, home: "@" + home.handle, status: "active" };
  }

  removeHomeMember(p: Principal, homeId: string, memberId: string) {
    const ownerId = this.requireOwner(p);
    const home = this.ownHome(ownerId, homeId);
    const m = this.get("SELECT * FROM bots WHERE id = ? AND home_bot_id = ?", memberId, home.id) ?? this.botByRef(memberId, "home_bot_id = ?", [home.id]);
    assert(m, 404, "member_not_found");
    const conversations = this.all("SELECT DISTINCT conversation_id FROM messages WHERE sender_bot = ? AND status = 'pending_approval'", m.id)
      .map((r: any) => r.conversation_id as string);
    const rooms = this.all("SELECT * FROM face_room_members WHERE bot_id = ? AND left_at IS NULL", m.id);
    let revokedInvites = 0;
    let revokedFaceInvites = 0;
    let clearedNotifyOutlet = 0;
    this.db.transaction(() => {
      // Stop the push first: a revoked identity must not keep receiving metadata through its webhook.
      this.run("UPDATE bots SET status = 'revoked', webhook_url = NULL, webhook_headers = '[]', webhook_updated_at = ? WHERE id = ?", nowIso(), m.id);
      this.run("UPDATE tokens SET revoked_at = ? WHERE kind = 'bot' AND subject_id = ? AND revoked_at IS NULL", nowIso(), m.id);
      // An owner who made this Bot the approval outlet would otherwise keep announcing cards into a queue that
      // this transaction just made unreadable: skip the dead outlet instead of silently dropping the cards.
      clearedNotifyOutlet = this.run("UPDATE owners SET notify_bot_id = NULL WHERE notify_bot_id = ?", m.id).changes;
      // An invite for a Bot that no longer exists must not share it again. Pending owner approvals for those
      // invites are cancelled by the bot_id below, with the member's other drafts.
      revokedInvites = this.run("UPDATE invites SET status = 'revoked' WHERE bot_id = ? AND status IN ('active','pending_owner')", m.id).changes;
      // A revoked identity must not keep in-flight drafts: the owner can otherwise approve one later and the
      // platform would deliver a message as a Bot that no longer exists. `cancelPendingFor` cancels the
      // approvals and marks their messages / actions / face-room drafts cancelled.
      this.cancelPendingFor("bot_id = ?", [m.id], "member_revoked");
      for (const id of conversations) this.refreshConversationStatus(id);
      // A revoked identity must also leave the rooms it was in; otherwise it stays a visible member and the
      // room keeps writing events (and countersignatures) for a Bot nobody can read.
      for (const room of rooms) {
        const member = this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", room.room_id, m.id);
        if (member) this.removeFaceMember(room.room_id, member);
        this.endRoomGrantsForBots(room.room_id, [m.id]);
      }
      // #90: the local-room tickets this identity minted are reach of its own. Withdraw them and end every claim
      // they made, so the room-scoped grants those claims wrote stop being active. This includes a ticket already
      // withdrawn while the identity lived: owner decision 2026-10-24 keeps the seats of a withdrawn link, not the
      // seats of a revoked identity that can no longer answer in that room.
      for (const inv of this.all("SELECT * FROM local_room_invites WHERE inviter_bot = ?", m.id)) {
        if (!inv.revoked_at) this.run("UPDATE local_room_invites SET revoked_at = ? WHERE ticket = ?", nowIso(), inv.ticket);
        for (const claim of this.localInviteClaims(inv)) {
          this.run("UPDATE local_room_invite_claims SET released_at = ? WHERE ticket = ? AND owner_id = ?", nowIso(), inv.ticket, claim.owner_id);
          this.endLocalPairGrants(inv.room_id, inv.inviter_bot, claim.bots);
        }
      }
      // #183: the same rule holds for the face-room tickets this identity minted. A ticket is a bearer
      // credential, so one handed out before the revocation would otherwise keep previewing the room and
      // seating new people in it. Owner-minted tickets (`created_by_bot IS NULL`) are not this identity's reach.
      revokedFaceInvites = this.run("UPDATE face_room_invites SET revoked_at = ? WHERE created_by_bot = ? AND revoked_at IS NULL", nowIso(), m.id).changes;
    })();
    this.audit.append(`owner:${ownerId}`, "home.member_revoked", m.id, [ownerId], { home: home.id, revoked_invites: revokedInvites, revoked_face_invites: revokedFaceInvites, rooms_left: rooms.length, notify_outlet_cleared: clearedNotifyOutlet > 0 });
    return { bot_id: m.id, handle: "@" + m.handle, status: "revoked" };
  }

  homeMembers(homeId: string) {
    return this.all("SELECT id, handle, display_name, avatar, color, avatar_updated_at FROM bots WHERE home_bot_id = ? AND status = 'active' ORDER BY created_at", homeId)
      .map((b: any) => ({ bot_id: b.id, handle: "@" + b.handle, display_name: b.display_name, ...lookOf(b) }));
  }

  listHomeMembers(p: Principal, homeId: string) {
    const ownerId = this.requireOwner(p);
    return { members: this.homeMembers(this.ownHome(ownerId, homeId).id) };
  }

  /**
   * Bots granted TO me (default deny: nothing appears unless that bot's owner created an
   * active relationship + grant to one of my bots). Home / Chief bots are not a wildcard.
   * `home` is optional grouping: when set, only grants held by that home or its members.
   */
  remoteBots(p: Principal, homeId?: string) {
    return this.listRemoteBots(p, homeId);
  }

  /**
   * `typed_by_owner` attestation: the platform stamps it on a message only when the caller is an owner principal
   * that may attest (owner login, or a connector token minted for a trusted host such as FlyBot) and says so
   * explicitly. Bot tokens and plain connector tokens are refused; message text and signed envelopes are never read for it.
   */
  private typedByOwner(p: Principal, body: any): boolean {
    const v = body?.typed_by_owner;
    if (v === undefined || v === null || v === false) return false;
    assert(v === true, 400, "invalid_request", "typed_by_owner must be a boolean");
    if (p.kind !== "owner") throw new ApiError(403, "typed_attestation_forbidden", "typed_by_owner can only be set with the owner's own credential, never a Bot token");
    if (!p.attestTyped) throw new ApiError(403, "typed_attestation_forbidden", "this connector token may not attest typed_by_owner (use the token FlyBot onboarding issued, or an owner login)");
    return true;
  }

  /**
   * `mentions`: the Bot handles the sender says the line is addressed to (the composer's @ picks). Optional and
   * backward compatible: absent, null and [] all mean "none". Validated, not trusted: a list of at most 8 handles
   * (`@name.home`, 2-40 chars [a-z0-9._-]), normalised to lowercase `@handle`, deduplicated; anything else is a 400.
   * The platform keeps it with the message and countersigns it; whether a receiver acts on it is its own rule.
   */
  private mentionList(raw: unknown): string[] {
    if (raw === undefined || raw === null) return [];
    assert(Array.isArray(raw), 400, "invalid_request", "mentions must be an array of Bot handles");
    assert(raw.length <= 8, 400, "invalid_request", "mentions: at most 8 handles");
    const out: string[] = [];
    for (const item of raw) {
      assert(typeof item === "string" && /^@?[a-z0-9._-]{2,40}$/i.test(item), 400, "invalid_request", "mentions: each item is a Bot handle (2-40 chars [a-z0-9._-], optional leading @)");
      const handle = "@" + item.replace(/^@/, "").toLowerCase();
      if (!out.includes(handle)) out.push(handle);
    }
    return out;
  }

  /** The handles of `mentions` that are current members of the face room right now (lowercase `@handle`). */
  private roomMentions(roomId: string, mentions: string[]): string[] {
    if (!mentions.length) return [];
    const inRoom = new Set(this.all("SELECT handle FROM face_room_members WHERE room_id = ? AND left_at IS NULL", roomId).map((r) => "@" + String(r.handle).replace(/^@/, "").toLowerCase()));
    return mentions.filter((h) => inRoom.has(h));
  }

  // ================================================================ idempotency (#47)
  /** A caller-supplied key makes a retry safe: the same key and the same payload returns the first answer
   * verbatim, the same key with a different payload is a conflict, and an absent key changes nothing.
   * Keys are scoped to the calling owner (home) plus the tool, so two homes may use one string, and kept
   * 24 hours. Only a successful call is recorded, so a failed one can be retried with the same key. */
  private idempotent<T>(p: Principal, tool: string, key: unknown, payload: unknown, run: () => T): T {
    if (key === undefined || key === null) return run();
    assert(typeof key === "string", 400, "invalid_request", "idempotency_key must be a string");
    const k = key.trim();
    assert(k.length >= 8 && k.length <= 128, 400, "invalid_request", "idempotency_key: 8-128 characters");
    const ownerId = this.requireOwner(p);
    const hash = sha256Hex(Buffer.from(jcs(payload as any)));
    const ttlMs = 24 * 60 * 60 * 1000;
    const now = Date.now();
    this.run("DELETE FROM idempotency_keys WHERE created_at <= ?", now - ttlMs);
    // Claim the key first, in one statement, so two overlapping retries cannot both miss and both run:
    // the loser sees the winner's row (and its hash) instead of sending or deciding a second time.
    const claim = this.run("INSERT OR IGNORE INTO idempotency_keys (owner_id, tool, key, request_hash, response, created_at) VALUES (?,?,?,?,?,?)",
      ownerId, tool, k, hash, "", now) as any;
    if (!claim?.changes) {
      const hit = this.get("SELECT request_hash, response, created_at FROM idempotency_keys WHERE owner_id = ? AND tool = ? AND key = ?", ownerId, tool, k);
      assert(hit, 409, "idempotency_conflict", "this idempotency_key is being used by another call");
      assert(String(hit.request_hash) === hash, 409, "idempotency_conflict", "this idempotency_key was used with a different request");
      // An empty stored answer means that call is still running: never run it twice, and let the caller retry.
      assert(String(hit.response) !== "" && hit.response !== null, 409, "idempotency_in_progress", "the same idempotency_key is still being processed; retry shortly");
      return J(hit.response, {}) as T;
    }
    try {
      const out = run();
      this.run("UPDATE idempotency_keys SET response = ?, created_at = ? WHERE owner_id = ? AND tool = ? AND key = ?", JSON.stringify(out ?? null), now, ownerId, tool, k);
      return out;
    } catch (error) {
      // A call that threw wrote nothing that counts, so the key is released for a retry.
      this.run("DELETE FROM idempotency_keys WHERE owner_id = ? AND tool = ? AND key = ?", ownerId, tool, k);
      throw error;
    }
  }

  /** A signed message from one of my home's members to any bot of a friend home; reuses the pair's active conversation. */
  sendAsMember(p: Principal, body: { from_bot_id: string; to: string; text: string; attachments?: AttachmentRef[]; typed_by_owner?: boolean; mentions?: string[] | null; room_id?: string; conversation_id?: string; idempotency_key?: string }) {
    const { idempotency_key: key, ...rest } = body as any;
    return this.idempotent(p, "send_as_member", key, rest, () => this.sendAsMemberOnce(p, rest));
  }

  private sendAsMemberOnce(p: Principal, body: { from_bot_id: string; to: string; text: string; attachments?: AttachmentRef[]; typed_by_owner?: boolean; mentions?: string[] | null; room_id?: string; conversation_id?: string }) {
    const ownerId = this.requireOwner(p);
    const typed = this.typedByOwner(p, body);
    const mentions = this.mentionList(body?.mentions);
    const cb = this.custodialBot(p, body?.from_bot_id);
    const to = this.get("SELECT * FROM bots WHERE id = ?", body?.to) ?? this.botByRef(body?.to);
    assert(to && to.status === "active", 404, "bot_not_found", "no such remote bot");
    void ownerId;
    // #45: optional room context. The line names the room it belongs to; the server checks that a room-scoped grant
    // exists (the owners put both Bots in that room, so that click was the consent) and only then lifts the blanket
    // outbound hold. A room id with no such grant is refused whole: never an approval, never a message.
    const roomId = body?.room_id === undefined || body?.room_id === null ? null : String(body.room_id).trim();
    if (roomId !== null) {
      assert(/^[A-Za-z0-9._:-]{1,64}$/.test(roomId), 400, "invalid_request", "room_id: 1-64 chars [A-Za-z0-9._:-]");
      assert(this.findRoomGrant(to.owner_id, cb.botId, "chat.public", to.id, roomId), 403, "room_not_shared", "no active room-scoped grant for that room between these Bots", { suggestion: "join the room together again, or send without room_id" });
    }
    // #43: a claimed room invite is reach by itself — the guest may answer the inviter in that room, without a
    // friendship and without a fresh conversation elsewhere.
    const roomRel = roomId === null ? null : this.roomReach(cb.botId, to.id, roomId);
    if (roomId !== null) assert(roomRel, 403, "no_relationship", "no room reach to that Bot in this room", { suggestion: "join the room with the invite link first" });
    // The console reads one chat and names it when the owner writes, so the line lands in the thread on screen
    // instead of the pair's newest one. An explicit target must already be a conversation between these two Bots
    // that can still take a line: nothing is created and nothing falls back to another thread. The same answer is
    // given for a conversation that does not exist and for one of another pair, so ids cannot be probed.
    const rawTarget = body?.conversation_id;
    assert(rawTarget === undefined || rawTarget === null || typeof rawTarget === "string", 400, "invalid_request", "conversation_id must be a string");
    const explicit = rawTarget === undefined || rawTarget === null ? null : String(rawTarget).trim();
    assert(explicit === null || explicit.length > 0, 400, "invalid_request", "conversation_id must be a non-empty string");
    let conversationId: string;
    if (explicit !== null) {
      const named = this.get("SELECT id, initiator_bot, peer_bot, status, outcome FROM conversations WHERE id = ?", explicit);
      const mine = named && ((named.initiator_bot === cb.botId && named.peer_bot === to.id) || (named.initiator_bot === to.id && named.peer_bot === cb.botId));
      assert(mine, 404, "conversation_not_found", "no such conversation between these Bots");
      assert(named.status === "open" || named.status === "awaiting_approval", 409, named.status === "closed" ? "conversation_closed" : "conversation_paused", `conversation is ${named.status}${named.outcome ? ` (${named.outcome})` : ""}`);
      conversationId = named.id;
    } else {
      const rel = roomRel ?? this.activeRelationship(cb.botId, to.id);
      // Conversation statuses are open / awaiting_approval / closed; 'active' never matches,
      // so every send opened a new conversation and hit newConversationsPerPairPerDay (then 5).
      // The door is part of the lookup: a pair can share several rooms, and reusing the conversation opened in
      // another room would judge this room by that room's relationship (and, once it is gone, fail mid-draft).
      const conv = this.get("SELECT id FROM conversations WHERE status IN ('open', 'awaiting_approval') AND (expires_at IS NULL OR expires_at > ?) AND ((initiator_bot = ? AND peer_bot = ?) OR (initiator_bot = ? AND peer_bot = ?)) AND relationship_id = ? ORDER BY updated_at DESC LIMIT 1", nowIso(), cb.botId, to.id, to.id, cb.botId, rel.id);
      conversationId = conv?.id ?? (this.createConversation(cb.bp, cb.sign("conversation.create", { type: "direct", peer_bot_id: to.id, intent: { type: "general_chat", summary: "chat" } }, { to: to.id }), roomId) as any).conversation_id;
    }
    const message = this.draftMessage(cb.bp, conversationId, cb.sign("message.draft", { text: body.text, ...(body.attachments?.length ? { attachments: body.attachments } : {}) }, { conversation_id: conversationId }), typed, mentions, roomId);
    return { conversation_id: conversationId, message, typed_by_owner: typed, ...(roomId !== null ? { room_id: roomId } : {}) };
  }

  // ================================================================ attachments
  /** Upload a file for one of my bots (owner: bot_id names it; bot: itself). Stored sealed with the KMS key; expires. */
  uploadAttachment(p: Principal, body: { bot_id?: string; name: string; mime?: string; content_base64: string }) {
    const { botId, ownerId } = this.attachmentBot(p, body?.bot_id);
    assert(typeof body?.content_base64 === "string", 400, "invalid_request", "content_base64 required");
    assert(body.content_base64.length <= Math.ceil(this.attachmentLimits.maxBytes / 3) * 4 + 4, 413, "attachment_too_large", `file exceeds ${this.attachmentLimits.maxBytes} bytes`);
    const bytes = Buffer.from(body.content_base64, "base64");
    const check = checkFile(body.name, body.mime, bytes, this.attachmentLimits);
    if (!check.ok) throw new ApiError(check.code === "attachment_too_large" ? 413 : 415, check.code, check.message);
    this.cleanupAttachments();
    const id = newId("att"), now = Date.now();
    const sha256 = sha256Hex(bytes);
    this.run("INSERT INTO attachments (id, owner_id, bot_id, name, mime, size, sha256, sealed, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
      id, ownerId, botId, check.name, check.mime, bytes.length, sha256, sealBytes(this.kmsKey, bytes, `attachment:${id}:${sha256}`), new Date(now).toISOString(), new Date(now + this.attachmentLimits.ttlMs).toISOString());
    this.audit.append(`bot:${botId}`, "attachment.uploaded", id, [ownerId], { name: check.name, mime: check.mime, size: bytes.length, sha256 });
    return { attachment: { id, name: check.name, size: bytes.length, mime: check.mime, sha256 }, expires_at: new Date(now + this.attachmentLimits.ttlMs).toISOString(), limits: this.attachmentLimits };
  }

  private attachmentBot(p: Principal, botId?: string) {
    if (p.kind === "owner") {
      const ownerId = this.requireOwner(p);
      const b = botId ? this.ownBot(ownerId, botId) : this.get("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' ORDER BY created_at LIMIT 1", ownerId);
      assert(b, 404, "bot_not_found", "no bot to upload for");
      return { botId: b.id as string, ownerId };
    }
    return this.requireBot(p);
  }

  /** Validates a draft's refs: each one my bot's upload, unexpired, not yet sent, and matching the stored file exactly. */
  private checkRefs(botId: string, refs: unknown): AttachmentRef[] {
    if (refs === undefined || refs === null) return [];
    assert(Array.isArray(refs), 400, "invalid_request", "payload.attachments must be an array");
    const list = refs as any[];
    assert(list.length <= this.attachmentLimits.maxPerMessage, 400, "invalid_request", `at most ${this.attachmentLimits.maxPerMessage} attachments per message`);
    assert(new Set(list.map((r) => r?.id)).size === list.length, 400, "invalid_request", "duplicate attachment");
    return list.map((r) => {
      const row = this.get("SELECT id, bot_id, name, mime, size, sha256, message_id, expires_at FROM attachments WHERE id = ?", r?.id);
      assert(row && row.bot_id === botId, 404, "attachment_not_found", "no such attachment for this bot");
      assert(Date.parse(row.expires_at) > Date.now(), 410, "attachment_expired", "attachment expired");
      assert(!row.message_id, 409, "attachment_in_use", "attachment already sent; upload it again");
      const ref = refOf(row);
      assert(ref.name === r.name && ref.size === r.size && ref.mime === r.mime && ref.sha256 === r.sha256, 400, "attachment_mismatch", "attachment ref does not match the uploaded file");
      return ref;
    });
  }

  /** Download for the recipient (bot, or its owner) of a delivered message only; the hash is verified. */
  getAttachment(p: Principal, body: { attachment_id: string; bot_id?: string }) {
    const row = this.get("SELECT * FROM attachments WHERE id = ?", body?.attachment_id);
    assert(row, 404, "attachment_not_found", "no such attachment");
    const m = row.message_id ? this.get("SELECT id, recipient_bot, sender_bot, status FROM messages WHERE id = ?", row.message_id) : undefined;
    let allowed = false;
    if (m && m.status === "delivered") {
      if (p.kind === "owner") allowed = this.bot(m.recipient_bot).owner_id === this.requireOwner(p) && (!body.bot_id || body.bot_id === m.recipient_bot);
      else allowed = this.requireBot(p).botId === m.recipient_bot;
    }
    // Same answer whether it exists or not, so ids cannot be probed.
    assert(allowed, 404, "attachment_not_found", "no such attachment");
    assert(Date.parse(row.expires_at) > Date.now(), 410, "attachment_expired", "attachment expired");
    const bytes = unsealBytes(this.kmsKey, row.sealed, `attachment:${row.id}:${row.sha256}`);
    assert(sha256Hex(bytes) === row.sha256, 500, "attachment_corrupt", "attachment hash mismatch");
    this.audit.append("platform", "attachment.downloaded", row.id, [row.owner_id, this.bot(m.recipient_bot).owner_id], { message_id: m.id, sha256: row.sha256 });
    return { attachment: refOf(row), message_id: m.id, from: this.publicBot(this.bot(m.sender_bot)), trust: "peer_untrusted", content_base64: bytes.toString("base64") };
  }

  /** Deletes expired files. Returns how many went. */
  cleanupAttachments(now = Date.now()) {
    const r = this.run("DELETE FROM attachments WHERE expires_at <= ?", new Date(now).toISOString()) as any;
    return r?.changes ?? 0;
  }

  // ================================================================ custodial signing keys
  private storeCustody(botId: string, kid: string, pem: string) {
    const now = nowIso();
    this.run(`INSERT INTO bot_custody (bot_id, kid, sealed_key, created_at, updated_at) VALUES (?,?,?,?,?)
      ON CONFLICT(bot_id) DO UPDATE SET kid = excluded.kid, sealed_key = excluded.sealed_key, updated_at = excluded.updated_at`, botId, kid, seal(this.kmsKey, pem, `${botId}:${kid}`), now, now);
  }

  custodyStatus(p: Principal, botId?: string) {
    const ownerId = this.requireOwner(p);
    const bots = botId ? [this.ownBot(ownerId, botId)] : this.all("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at", ownerId);
    return bots.map((b: any) => { const c = this.get("SELECT kid, created_at, updated_at FROM bot_custody WHERE bot_id = ?", b.id); return { bot_id: b.id, handle: "@" + b.handle, custodial: !!c, kid: c?.kid ?? null, since: c?.created_at ?? null }; });
  }

  /** Opt a bot into custody. With private_key_pem: upload an already-registered key (kid looked up by public key).
   *  Without: rotate to a new platform-generated kid; existing kids stay valid (botctl keeps working). */
  enableCustody(p: Principal, botId: string | undefined, body: { private_key_pem?: string } = {}) {
    const ownerId = this.requireOwner(p);
    const b = botId ? this.ownBot(ownerId, botId) : this.get("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at LIMIT 1", ownerId);
    assert(b, 404, "bot_not_found");
    let kid: string, mode: string;
    if (body?.private_key_pem) {
      let pub: string;
      try { pub = publicRawFromPrivatePem(body.private_key_pem); } catch { throw new ApiError(400, "invalid_private_key", "private_key_pem must be an Ed25519 PKCS#8 PEM"); }
      const k = this.get("SELECT * FROM bot_keys WHERE bot_id = ? AND public_key = ? AND status = 'active' AND (expires_at IS NULL OR expires_at > ?)", b.id, pub, nowIso());
      assert(k, 400, "key_not_registered", "this private key does not match any active key of the bot");
      kid = k.kid; mode = "uploaded";
      this.storeCustody(b.id, kid, body.private_key_pem);
    } else {
      const kp = generateEd25519();
      kid = `cust_${new Date().toISOString().slice(0, 10).replaceAll("-", "")}_${randomBytes(2).toString("hex")}`;
      this.run("INSERT INTO bot_keys (bot_id, kid, alg, public_key, created_at) VALUES (?,?,?,?,?)", b.id, kid, "Ed25519", kp.publicKey, nowIso());
      mode = "rotated";
      this.storeCustody(b.id, kid, kp.privateKeyPem);
    }
    this.audit.append(`owner:${ownerId}`, "bot.custody_enabled", b.id, [ownerId], { kid, mode });
    return { bot_id: b.id, handle: "@" + b.handle, custodial: true, kid, mode, note: mode === "rotated" ? "new platform-held key added; existing keys (e.g. botctl) remain valid" : "uploaded key is now also held by the platform" };
  }

  disableCustody(p: Principal, botId: string) {
    const ownerId = this.requireOwner(p);
    const b = this.ownBot(ownerId, botId);
    const c = this.get("SELECT * FROM bot_custody WHERE bot_id = ?", b.id);
    assert(c, 404, "not_custodial");
    this.run("DELETE FROM bot_custody WHERE bot_id = ?", b.id);
    if (c.kid.startsWith("cust_")) this.run("UPDATE bot_keys SET status = 'revoked', expires_at = ? WHERE bot_id = ? AND kid = ?", nowIso(), b.id, c.kid);
    this.audit.append(`owner:${ownerId}`, "bot.custody_disabled", b.id, [ownerId], { kid: c.kid });
    return { bot_id: b.id, custodial: false };
  }

  /** Act as the owner's custodial bot: a bot principal plus a signer using the platform-held key. */
  custodialBot(p: Principal, botId?: string) {
    const ownerId = this.requireOwner(p);
    const c = botId
      ? this.get("SELECT c.* FROM bot_custody c JOIN bots b ON b.id = c.bot_id WHERE b.id = ? AND b.owner_id = ?", botId, ownerId)
      : this.get("SELECT c.* FROM bot_custody c JOIN bots b ON b.id = c.bot_id WHERE b.owner_id = ? ORDER BY b.created_at LIMIT 1", ownerId);
    assert(c, 409, "not_custodial", "this bot's signing key is not held by the platform; enable custody first (enable_custody)");
    // A stopped Bot and a removed one are different answers on every owner-side door (`assertInvitable`): the
    // home page's "send as member" must say the Bot can be resumed, not that its identity is gone.
    this.assertInvitable(this.bot(c.bot_id));
    const bp: Principal = { kind: "bot", botId: c.bot_id, ownerId };
    const pem = unseal(this.kmsKey, c.sealed_key, `${c.bot_id}:${c.kid}`);
    const sign = (type: string, payload: unknown, extra: { to?: string; conversation_id?: string } = {}) => signEnvelope({ type, from: c.bot_id, payload, kid: c.kid, privateKeyPem: pem, ...extra });
    return { botId: c.bot_id as string, bp, sign, cursor: c.events_cursor as number };
  }

  setCustodyCursor(botId: string, cursor: number) { this.run("UPDATE bot_custody SET events_cursor = ? WHERE bot_id = ?", cursor, botId); }

  changePassword(p: Principal, body: { current_password: string; new_password: string }) {
    const ownerId = this.requireOwner(p);
    const o = this.owner(ownerId);
    assert(checkPassword(String(body?.current_password ?? ""), o.password_hash), 401, "invalid_credentials", "current password is wrong");
    assert(typeof body.new_password === "string" && body.new_password.length >= 6, 400, "invalid_request", "new password must be >= 6 chars");
    this.run("UPDATE owners SET password_hash = ? WHERE id = ?", hashPassword(body.new_password), ownerId);
    // log out every web/login session; connector tokens stay (they are listed/revoked separately)
    this.run("UPDATE tokens SET revoked_at = ? WHERE kind = 'owner' AND subject_id = ? AND scope IS NULL AND revoked_at IS NULL", nowIso(), ownerId);
    this.audit.append(`owner:${ownerId}`, "owner.password_changed", ownerId, [ownerId], {});
    return { ok: true, note: "password changed; all login sessions were signed out (connector tokens unaffected)" };
  }

  /** Stores validated look fields (undefined = leave unchanged, null = clear). Returns the audit-safe change list. */
  private applyLook(botId: string, look: { avatar?: string | null; color?: string | null }) {
    const changed: Record<string, unknown> = {};
    if (look.avatar !== undefined) {
      this.run("UPDATE bots SET avatar = ?, avatar_updated_at = ? WHERE id = ?", look.avatar, nowIso(), botId);
      changed.avatar = avatarFingerprint(look.avatar);
    }
    if (look.color !== undefined) {
      this.run("UPDATE bots SET color = ? WHERE id = ?", look.color, botId);
      changed.color = look.color;
    }
    return changed;
  }

  /** Owner (login or connector) changes the display name and/or look. Fields are optional but at least one is required;
   *  `avatar` / `color` set to null (or "") clear the owner's choice. */
  updateBotProfile(p: Principal, botId: string | undefined, body: { display_name?: string; avatar?: string | null; color?: string | null }) {
    const ownerId = this.requireOwner(p);
    const b = botId ? this.ownBot(ownerId, botId) : this.get("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at LIMIT 1", ownerId);
    assert(b, 404, "bot_not_found");
    const has = (k: string) => body?.[k as keyof typeof body] !== undefined;
    assert(has("display_name") || has("avatar") || has("color"), 400, "invalid_request", "provide display_name, avatar and/or color");
    let name: string | undefined;
    if (has("display_name")) {
      assert(typeof body.display_name === "string", 400, "invalid_request", "display_name must be a string");
      name = peerDisplayName(body.display_name, "");
      assert(name.length >= 1, 400, "invalid_request", "display_name: 1-60 chars");
    }
    const avatar = has("avatar") ? validateAvatar(body.avatar) : undefined;
    const color = has("color") ? validateColor(body.color) : undefined;
    this.db.transaction(() => {
      if (name !== undefined) this.run("UPDATE bots SET display_name = ? WHERE id = ?", name, b.id);
      const changed = this.applyLook(b.id, { avatar, color });
      this.audit.append(`owner:${ownerId}`, "bot.profile_updated", b.id, [ownerId], { ...(name !== undefined ? { display_name: name } : {}), ...changed });
    })();
    return this.publicBot(this.bot(b.id), true);
  }

  me(p: Principal) {
    if (p.kind === "owner") {
      const o = this.owner(p.ownerId);
      // #44: `home` is the owner's FlyBot home Bot in the "@handle" spelling used by event.from / item.peer, so a
      // connector never has to parse connector_identity or reconcile the two spellings. `bots[].handle` stays bare.
      const home = this.get("SELECT handle, display_name FROM bots WHERE owner_id = ? AND integration_type = 'flybot-home' ORDER BY created_at LIMIT 1", p.ownerId);
      return { kind: "owner", owner_id: o.id, username: o.username, display_name: o.display_name, timezone: o.timezone, sensitive_terms: J(o.sensitive_terms, []), auto_approve_face_rooms: !!o.auto_approve_face_rooms, notify_bot_id: o.notify_bot_id ?? null, home: home ? "@" + home.handle : null, home_name: home ? home.display_name : null, bots: this.listBots(p) };
    }
    const b = this.bot(p.botId);
    return { kind: "bot", ...this.publicBot(b, true), status: b.status };
  }

  updateSettings(p: Principal, body: { sensitive_terms?: string[]; timezone?: string; display_name?: string; auto_approve_face_rooms?: boolean; notify_bot_id?: string | null }) {
    const ownerId = this.requireOwner(p);
    // A refused field must not leave the other fields of the same request written: validate first.
    let displayName: string | undefined;
    if (body?.display_name !== undefined) {
      assert(typeof body.display_name === "string", 400, "invalid_request", "display_name must be a string");
      displayName = peerDisplayName(body.display_name, "");
      assert(displayName.length >= 1, 400, "invalid_request", "display_name: 1-60 chars");
    }
    // #139 ② C: the outlet is one of the owner's own Bots, chosen here rather than through a new route. `null` clears it.
    // The refusal never says whether the id exists, so it cannot be used to probe another owner's Bots.
    let notifyBotId: string | null | undefined;
    if (body?.notify_bot_id !== undefined) {
      if (body.notify_bot_id === null) notifyBotId = null;
      else {
        assert(typeof body.notify_bot_id === "string" && body.notify_bot_id.length > 0, 400, "invalid_request", "notify_bot_id must be a Bot id or null");
        const outlet = this.get("SELECT id, owner_id, status FROM bots WHERE id = ?", body.notify_bot_id);
        assert(outlet && outlet.owner_id === ownerId, 400, "invalid_request", "notify_bot_id must name one of your own Bots");
        // A revoked identity can never read its event queue (#177 ③) nor get a token again, so a card announced to
        // it is written and then lost. A frozen one is still a valid outlet: its queue survives the stop and is
        // read after resume.
        assert(outlet.status !== "revoked", 400, "invalid_request", "a revoked Bot cannot be the approval outlet");
        notifyBotId = outlet.id;
      }
    }
    // Validate before any write, so a bad zone cannot leave the rest of the patch behind it half-applied.
    const timezone = body.timezone ? this.validateTimezone(body.timezone) : undefined;
    if (Array.isArray(body.sensitive_terms)) this.run("UPDATE owners SET sensitive_terms = ? WHERE id = ?", JSON.stringify(body.sensitive_terms.map(String)), ownerId);
    if (timezone) this.run("UPDATE owners SET timezone = ? WHERE id = ?", timezone, ownerId);
    if (displayName !== undefined) this.run("UPDATE owners SET display_name = ? WHERE id = ?", displayName, ownerId);
    if (typeof body.auto_approve_face_rooms === "boolean") this.run("UPDATE owners SET auto_approve_face_rooms = ? WHERE id = ?", body.auto_approve_face_rooms ? 1 : 0, ownerId);
    if (notifyBotId !== undefined) this.run("UPDATE owners SET notify_bot_id = ? WHERE id = ?", notifyBotId, ownerId);
    this.audit.append(`owner:${ownerId}`, "owner.settings_updated", ownerId, [ownerId], { fields: Object.keys(body) });
    return this.me(p);
  }

  // ================================================================ bots & keys
  /**
   * Handle uniqueness is global and case-insensitive (see `botByRef`). The refusal names the stored spelling only when
   * the caller already owns that row: for another owner's Bot the message stays generic, because naming it would echo
   * back the one string that addresses that exact row (with a legacy mixed-case pair, the exact spelling) to a caller
   * who could not have known it — a probe for other people's handles.
   */
  private assertHandleFree(handle: string, ownerId?: string) {
    const taken = this.get("SELECT handle, owner_id FROM bots WHERE LOWER(handle) = ?", handle);
    const own = !!taken && ownerId !== undefined && taken.owner_id === ownerId;
    assert(!taken, 409, "handle_taken", own ? `handle @${taken!.handle} is already taken` : "that handle is already taken");
    return taken;
  }

  registerBot(p: Principal, body: { handle: string; display_name?: string; avatar?: string | null; color?: string | null; integration_type?: string; webhook_url?: string; public_key?: { alg?: string; kid: string; value: string } }) {
    const ownerId = this.requireOwner(p);
    assert(body?.display_name === undefined || typeof body.display_name === "string", 400, "invalid_request", "display_name must be a string");
    const handle = handleKey(body?.handle);
    assert(/^[a-z0-9._-]{2,40}$/i.test(handle), 400, "invalid_request", "handle: 2-40 chars [a-z0-9._-]");
    this.assertHandleFree(handle, ownerId);
    const look = { avatar: body?.avatar !== undefined ? validateAvatar(body.avatar) : undefined, color: body?.color !== undefined ? validateColor(body.color) : undefined };
    let generated: { kid: string; publicKey: string; privateKeyPem: string } | undefined;
    let key = body.public_key;
    if (!key) {
      // platform-generated key for hosts that cannot manage keys (returned once; KMS custody is out of MVP scope)
      const kp = generateEd25519();
      generated = { kid: "key_" + new Date().toISOString().slice(0, 7).replace("-", "_"), ...kp };
      key = { alg: "Ed25519", kid: generated.kid, value: kp.publicKey };
    }
    assert(!key.alg || key.alg === "Ed25519", 400, "invalid_request", "only Ed25519 keys are supported");
    try { publicKeyFromRaw(key.value); } catch { throw new ApiError(400, "invalid_public_key", "public_key.value must be base64url raw 32-byte Ed25519 key"); }
    const id = newId("bot");
    const webhookSecret = randomToken("whs");
    this.db.transaction(() => {
      this.run("INSERT INTO bots (id, owner_id, handle, display_name, integration_type, webhook_url, webhook_secret, created_at) VALUES (?,?,?,?,?,?,?,?)",
        id, ownerId, handle, peerDisplayName(body.display_name, handle), body.integration_type || "rest", body.webhook_url ? validateUrl(body.webhook_url) : null, webhookSecret, nowIso());
      this.run("INSERT INTO bot_keys (bot_id, kid, alg, public_key, created_at) VALUES (?,?,?,?,?)", id, key!.kid, "Ed25519", key!.value, nowIso());
    })();
    const botToken = this.issueToken("bot", id);
    const lookChanged = this.applyLook(id, look);
    this.audit.append(`owner:${ownerId}`, "bot.registered", id, [ownerId], { handle, kid: key.kid, public_key: key.value, integration_type: body.integration_type || "rest", ...lookChanged });
    return {
      ...lookOf(this.bot(id)),
      bot_id: id, owner_id: ownerId, handle: "@" + handle, status: "active", bot_token: botToken, webhook_secret: webhookSecret,
      key: { kid: key.kid, public_key: key.value, ...(generated ? { private_key_pem: generated.privateKeyPem, note: "platform-generated; returned once, store it securely" } : {}) },
      mcp: { transport: "stdio", command: "npm run mcp", env: { BOTSOCIAL_URL: this.publicBaseUrl, BOTSOCIAL_BOT_ID: id } },
    };
  }

  listBots(p: Principal) {
    const ownerId = this.requireOwner(p);
    // `custodial` is read-only: whether the platform holds this Bot's signing key (`bot_custody`), which is the only
    // thing that decides if the owner's console may send as it (`custodialBot`). Never inferred from integration_type.
    return this.all("SELECT id, handle, display_name, avatar, color, avatar_updated_at, integration_type, webhook_url, status, created_at, EXISTS (SELECT 1 FROM bot_custody c WHERE c.bot_id = bots.id) AS custodial FROM bots WHERE owner_id = ?", ownerId).map((b) => ({
      ...b, custodial: !!b.custodial, ...lookOf(b), webhook_url: redactUrl(b.webhook_url), webhook: { configured: !!b.webhook_url }, keys: this.all("SELECT kid, alg, public_key, status, created_at, expires_at FROM bot_keys WHERE bot_id = ?", b.id),
    }));
  }

  private ownBot(ownerId: string, botId: string) {
    const b = this.bot(botId);
    assert(b.owner_id === ownerId, 403, "forbidden", "not your bot");
    return b;
  }

  addKey(p: Principal, botId: string, body: { kid: string; value: string; retire_others_in_days?: number }) {
    const ownerId = this.requireOwner(p);
    this.ownBot(ownerId, botId);
    assert(body?.kid && body?.value, 400, "invalid_request", "kid and value required");
    try { publicKeyFromRaw(body.value); } catch { throw new ApiError(400, "invalid_public_key"); }
    assert(!this.get("SELECT 1 FROM bot_keys WHERE bot_id = ? AND kid = ?", botId, body.kid), 409, "kid_exists");
    // rotation: old keys stay valid for a 7-day verification window
    const until = new Date(Date.now() + (body.retire_others_in_days ?? 7) * 86400e3).toISOString();
    this.run("UPDATE bot_keys SET expires_at = ? WHERE bot_id = ? AND status = 'active' AND expires_at IS NULL", until, botId);
    this.run("INSERT INTO bot_keys (bot_id, kid, alg, public_key, created_at) VALUES (?,?,?,?,?)", botId, body.kid, "Ed25519", body.value, nowIso());
    this.audit.append(`owner:${ownerId}`, "bot.key_added", botId, [ownerId], { kid: body.kid, old_keys_expire_at: until });
    return { bot_id: botId, kid: body.kid, status: "active" };
  }

  revokeKey(p: Principal, botId: string, kid: string) {
    const ownerId = this.requireOwner(p);
    this.ownBot(ownerId, botId);
    const r = this.run("UPDATE bot_keys SET status = 'revoked' WHERE bot_id = ? AND kid = ?", botId, kid);
    assert(r.changes, 404, "key_not_found");
    this.audit.append(`owner:${ownerId}`, "bot.key_revoked", botId, [ownerId], { kid });
    return { bot_id: botId, kid, status: "revoked" };
  }

  /** Owner of the bot, or the bot itself, may manage its webhook. */
  private webhookBot(p: Principal, botId: string) {
    if (p.kind === "bot") { assert(p.botId === botId, 403, "forbidden", "a bot may only manage its own webhook"); return this.bot(botId); }
    return this.ownBot(p.ownerId, botId);
  }
  private actorOf(p: Principal) { return p.kind === "bot" ? `bot:${p.botId}` : `owner:${p.ownerId}`; }

  webhookView(botId: string) {
    const b = this.get("SELECT id, handle, webhook_url, webhook_headers, webhook_updated_at FROM bots WHERE id = ?", botId);
    const headers = J(b.webhook_headers, []);
    const o = this.webhooks.opts;
    return {
      bot_id: b.id, configured: !!b.webhook_url, url: redactUrl(b.webhook_url), headers: redactHeaders(headers), updated_at: b.webhook_updated_at,
      queued_events: this.webhooks.queued(botId),
      policy: { debounce_seconds: o.debounceMs / 1000, max_pushes_per_hour: o.maxPerHour, max_attempts: o.maxAttempts, signature: "X-BotSocial-Signature: v1=HMAC-SHA256(webhook_secret, timestamp + '.' + body)" },
      recent_deliveries: this.webhooks.deliveries(botId, 10),
    };
  }
  getWebhook(p: Principal, botId: string) { this.webhookBot(p, botId); return this.webhookView(botId); }

  /** body: { url | webhook_url, headers?: ["Name: value"] | {Name: value} | [{name,value}] (omit = keep, [] = clear) } */
  setWebhook(p: Principal, botId: string, body: any) {
    const b = this.webhookBot(p, botId);
    const rawUrl = body?.url !== undefined ? body.url : body?.webhook_url;
    if (rawUrl === null || rawUrl === "") return this.clearWebhook(p, botId);
    const url = validateUrl(rawUrl);
    const headers = body?.headers === undefined ? J(b.webhook_headers, []) : validateHeaders(body.headers ?? []);
    this.run("UPDATE bots SET webhook_url = ?, webhook_headers = ?, webhook_updated_at = ? WHERE id = ?", url, JSON.stringify(headers), nowIso(), botId);
    this.audit.append(this.actorOf(p), "bot.webhook_set", botId, [b.owner_id], { url: redactUrl(url), header_names: headers.map((h: any) => h.name) });
    return this.webhookView(botId);
  }
  clearWebhook(p: Principal, botId: string) {
    const b = this.webhookBot(p, botId);
    this.run("UPDATE bots SET webhook_url = NULL, webhook_headers = '[]', webhook_updated_at = ? WHERE id = ?", nowIso(), botId);
    this.audit.append(this.actorOf(p), "bot.webhook_cleared", botId, [b.owner_id], {});
    return this.webhookView(botId);
  }
  async testWebhook(p: Principal, botId: string) {
    const b = this.webhookBot(p, botId);
    assert(b.webhook_url, 409, "no_webhook", "no webhook configured");
    const d = await this.webhooks.test(botId);
    this.audit.append(this.actorOf(p), "bot.webhook_tested", botId, [b.owner_id], { delivery_id: d.delivery_id, status: d.status, response_status: d.response_status });
    return d;
  }
  webhookDeliveries(p: Principal, botId: string, limit = 30) { this.webhookBot(p, botId); return { deliveries: this.webhooks.deliveries(botId, Math.min(limit, 200)) }; }

  /** Kill switch: freeze outbound, pause conversations, revoke bot tokens, cancel pending drafts. */
  emergencyStop(p: Principal, body: { bot_id: string }) {
    const ownerId = this.requireOwner(p);
    const b = this.ownBot(ownerId, body?.bot_id);
    // A removed home member is `revoked`, not `frozen`: freezing it would put the identity in the one state
    // resumeBot accepts, handing the owner a working token for an identity whose invites, drafts, rooms and
    // seats were already torn down. Re-adding the handle through the home is the supported way back.
    assert(b.status !== "revoked", 403, "bot_revoked", "this bot identity was revoked");
    this.db.transaction(() => {
      this.run("UPDATE bots SET status = 'frozen' WHERE id = ?", b.id);
      this.run("UPDATE tokens SET revoked_at = ? WHERE kind = 'bot' AND subject_id = ? AND revoked_at IS NULL", nowIso(), b.id);
      this.run("UPDATE conversations SET status = 'paused_stop', updated_at = ? WHERE (initiator_bot = ? OR peer_bot = ?) AND status != 'closed'", nowIso(), b.id, b.id);
      this.cancelPendingFor("bot_id = ?", [b.id], "emergency_stop");
    })();
    this.audit.append(`owner:${ownerId}`, "bot.emergency_stop", b.id, [ownerId], {});
    return { bot_id: b.id, status: "frozen", tokens_revoked: true };
  }

  /** Re-enable a frozen bot and issue a fresh bot token. Paused conversations stay paused until an owner extends them. */
  resumeBot(p: Principal, botId: string) {
    const ownerId = this.requireOwner(p);
    const b = this.ownBot(ownerId, botId);
    // A removed home member is `revoked`, not `frozen`: removeHomeMember already cleared its webhook and revoked its
    // invites, drafts, rooms and seats, and nothing here would restore them. The way back is addHomeMember.
    assert(b.status !== "revoked", 403, "bot_revoked", "this bot identity was revoked");
    this.run("UPDATE bots SET status = 'active' WHERE id = ?", b.id);
    const token = this.issueToken("bot", b.id);
    this.audit.append(`owner:${ownerId}`, "bot.resumed", b.id, [ownerId], {});
    return { bot_id: b.id, status: "active", bot_token: token };
  }

  rotateBotToken(p: Principal, botId: string) {
    const ownerId = this.requireOwner(p);
    const b = this.ownBot(ownerId, botId);
    // A revoked identity is final: removeHomeMember already revoked its tokens and cleared its webhook, invites,
    // drafts and rooms, and rotating would hand it a working token again without restoring any of them. Re-adding
    // the handle through the home is the supported way back.
    assert(b.status !== "revoked", 403, "bot_revoked", "this bot identity was revoked");
    this.run("UPDATE tokens SET revoked_at = ? WHERE kind = 'bot' AND subject_id = ? AND revoked_at IS NULL", nowIso(), b.id);
    const token = this.issueToken("bot", b.id);
    this.audit.append(`owner:${ownerId}`, "bot.token_rotated", b.id, [ownerId], {});
    return { bot_id: b.id, bot_token: token };
  }

  // ================================================================ signatures
  /** Verify a bot's signed envelope (§4.3): signer = caller, active kid, digest, Ed25519 sig, ts skew, nonce replay. */
  verifyEnvelope(p: Principal, env: Envelope, expectedType: string): Envelope {
    const { botId, ownerId } = this.requireBot(p);
    const reject = (status: number, code: string, msg: string): never => {
      this.audit.append(`bot:${botId}`, "signature.rejected", botId, [ownerId], { code, reason: msg, type: env?.type, envelope_id: env?.id });
      throw new ApiError(status, code, msg);
    };
    if (!env || typeof env !== "object" || env.v !== "botsocial/1.0" || !env.sig || !env.id || !env.nonce || !env.ts) reject(400, "invalid_envelope", "request body must be a signed botsocial/1.0 envelope");
    if (env.type !== expectedType) reject(400, "invalid_envelope", `envelope type must be ${expectedType}`);
    if (env.from !== botId) reject(401, "invalid_signature", "envelope.from does not match the authenticated bot");
    const b = this.bot(botId);
    if (b.status !== "active") {
      const frozen = b.status === "frozen";
      reject(403, frozen ? "bot_frozen" : "bot_revoked", frozen ? "bot is frozen (emergency stop)" : "this bot identity was revoked");
    }
    const key = this.get("SELECT * FROM bot_keys WHERE bot_id = ? AND kid = ? AND status = 'active'", botId, env.sig.kid);
    if (!key || (key.expires_at && Date.parse(key.expires_at) < Date.now())) reject(401, "invalid_signature", "unknown, revoked or expired kid");
    if (env.payload_sha256 !== payloadDigest(env.payload)) reject(401, "invalid_signature", "payload digest mismatch");
    if (env.sig.alg !== "Ed25519" || !verifyString(key.public_key, envelopeSigningInput(env), env.sig.value)) reject(401, "invalid_signature", "signature verification failed");
    const ts = Date.parse(env.ts);
    if (Number.isNaN(ts) || Math.abs(Date.now() - ts) > LIMITS.tsSkewMs) reject(401, "replay_detected", "timestamp outside allowed skew");
    this.run("DELETE FROM nonces WHERE seen_at < ?", Date.now() - LIMITS.nonceTtlMs);
    try { this.run("INSERT INTO nonces (bot_id, nonce, seen_at) VALUES (?,?,?)", botId, env.nonce, Date.now()); }
    catch { reject(401, "replay_detected", "nonce already used"); }
    return env;
  }

  // ================================================================ relationships
  private pairRelationships(a: string, b: string) {
    return this.all("SELECT * FROM relationships WHERE (requester_bot = ? AND target_bot = ?) OR (requester_bot = ? AND target_bot = ?) ORDER BY created_at DESC", a, b, b, a);
  }

  private expireStale() {
    this.advanceFaceRooms();
    const now = nowIso();
    for (const r of this.all("SELECT * FROM relationships WHERE status IN ('pending_requester_owner','pending_target') AND expires_at < ?", now)) {
      this.run("UPDATE relationships SET status = 'expired', updated_at = ? WHERE id = ?", now, r.id);
      // Flip each pending approval through `expireApproval`, not one bulk UPDATE. The bulk form is why the
      // `relationship_request` Bot was never told: it flipped the row (no `decided_at`, no `approval.expired` audit,
      // no event) before the approval sweep below could see it, so the real-world path stayed silent. The
      // relationship row above is already terminal, so a reader reacting to the event sees the end state.
      for (const a of this.all("SELECT * FROM approvals WHERE subject_id = ? AND status = 'pending'", r.id)) this.expireApproval(a);
      this.audit.append("platform", "relationship.expired", r.id, [r.requester_owner, r.target_owner], {});
      this.releaseInviteUse(r.id);
    }
    for (const a of this.all("SELECT * FROM approvals WHERE status = 'pending' AND expires_at < ?", now)) this.expireApproval(a);
  }

  /** The home a FlyBot sub-identity belongs to; any other bot is its own home. Display grouping only — never an access wildcard. */
  homeOf(botId: string): string {
    return this.get("SELECT home_bot_id FROM bots WHERE id = ?", botId)?.home_bot_id ?? botId;
  }

  activeRelationship(a: string, b: string) {
    const rel = this.findActiveRelationship(a, b);
    if (!rel) {
      this.audit.append(`bot:${a}`, "policy.denied", b, [this.bot(a).owner_id], { code: "no_relationship" });
      throw new ApiError(403, "no_relationship", "no active relationship between these bots");
    }
    // Revoking a FlyBot home member keeps the relationship rows (so re-adding the same handle can restore
    // them), but the identity itself is gone: a friend must not be able to open a new conversation or draft
    // into an existing one toward it. A frozen Bot is deliberately not filtered here: the kill switch stops its
    // outbound side and stops anything new starting toward it, but it does that where reach is decided -- the peer
    // check in createConversation and the recipient check in deliverMessage -- while a conversation that already
    // exists stays paused_stop, so a draft into it still answers conversation_paused (that pause outlives a
    // resume). The owner's own resume, token rotate, audit read, grant revoke and block never come through here:
    // they resolve the owner principal.
    for (const id of [a, b]) {
      if (this.bot(id).status === "revoked") throw new ApiError(403, "bot_revoked", "a Bot in this relationship was revoked");
    }
    return rel;
  }

  /** The target of reach must be an active Bot: frozen (kill switch) and revoked (identity gone) both refuse. */
  private assertReachable(b: any) {
    if (b.status === "frozen") throw new ApiError(403, "bot_frozen", "a Bot in this relationship is frozen (emergency stop)");
    if (b.status === "revoked") throw new ApiError(403, "bot_revoked", "a Bot in this relationship was revoked");
  }

  /** Access is only the two endpoint bots. Home / Chief never cover their members. */
  private findActiveRelationship(a: string, b: string): any {
    return this.pairRelationships(a, b).find((r) => r.status === "active");
  }

  /** The bot the grantor is sharing (their endpoint on the relationship). */
  private grantedBotOf(g: any, r?: any): string {
    const rel = r ?? this.get("SELECT * FROM relationships WHERE id = ?", g.relationship_id);
    if (!rel) return "";
    return g.grantor_owner === rel.requester_owner ? rel.requester_bot : rel.target_bot;
  }

  requestRelationship(p: Principal, body: any) {
    let fromBot: any, payload: any, viaBot = false;
    if (p.kind === "bot") {
      const env = this.verifyEnvelope(p, body, "relationship.request");
      payload = env.payload ?? {};
      fromBot = this.bot(p.botId);
      viaBot = true;
    } else {
      payload = body ?? {};
      assert(payload.from_bot_id, 400, "invalid_request", "from_bot_id required when an owner sends a request");
      fromBot = this.ownBot(p.ownerId, payload.from_bot_id);
    }
    assert(payload.target_handle || payload.target_bot_id, 400, "invalid_request", "target_handle or target_bot_id required");
    const target = payload.target_bot_id ? this.bot(payload.target_bot_id) : this.botByHandle(payload.target_handle);
    // #90: a revoked Bot answers exactly like one that never existed — same status, code, message and fields.
    // Any difference would turn this door into an oracle for "which handle was revoked".
    assert(target.status === "active", 404, "bot_not_found", payload.target_bot_id ? `bot ${payload.target_bot_id} not found` : `bot ${payload.target_handle} not found`);
    assert(target.id !== fromBot.id && target.owner_id !== fromBot.owner_id, 400, "invalid_request", "cannot befriend your own bot");
    // A pending request that timed out must not keep answering relationship_exists: expire it here, before the
    // duplicate check, because requesting again is the first call after the 7-day window in many clients.
    this.expireStale();
    const existing = this.pairRelationships(fromBot.id, target.id);
    assert(!existing.some((r) => r.status === "blocked"), 403, "blocked", "relationship is blocked");
    assert(!existing.some((r) => ["active", "pending_target", "pending_requester_owner"].includes(r.status)), 409, "relationship_exists");
    const declined = existing.find((r) => r.status === "declined" && r.requester_bot === fromBot.id);
    assert(!declined || Date.now() - Date.parse(declined.updated_at) > LIMITS.declineCooldownMs, 429, "decline_cooldown", "request was declined within the last 30 days");
    const requested = this.validCaps(payload.requested_capabilities ?? DEFAULT_CAPABILITIES);
    const offered = this.validCaps(payload.offered_capabilities ?? DEFAULT_CAPABILITIES);
    const id = newId("rel");
    const status = viaBot ? "pending_requester_owner" : "pending_target";
    const expires = new Date(Date.now() + LIMITS.relationshipRequestTtlMs).toISOString();
    this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, message, requested_caps, offered_caps, created_at, updated_at, expires_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, id, fromBot.id, target.id, fromBot.owner_id, target.owner_id, status, payload.message ?? null, JSON.stringify(requested), JSON.stringify(offered), nowIso(), nowIso(), expires);
    this.audit.append(viaBot ? `bot:${fromBot.id}` : `owner:${fromBot.owner_id}`, "relationship.requested", id, [fromBot.owner_id, target.owner_id], { from: fromBot.id, to: target.id, status, requested, offered });
    let approval_id: string | undefined;
    if (viaBot) {
      approval_id = this.createApproval(fromBot.owner_id, "relationship_request", id, fromBot.id, null, `Your bot wants to send a friend request to @${target.handle}`, ["relationship.requires_owner"], [], LIMITS.relationshipRequestTtlMs);
    } else {
      this.notifyTarget(id);
    }
    return { relationship_id: id, status, awaiting: viaBot ? "requester_owner_approval" : "target_owner_consent", approval_id, expires_at: expires };
  }

  private notifyTarget(relId: string) {
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    this.emit(r.target_bot, "relationship.requested", { relationship_id: r.id, from: this.publicBot(this.bot(r.requester_bot)), note: "Only your owner can accept this request.", trust: "peer_untrusted", untrusted_content: { message: r.message } });
  }

  private validCaps(caps: unknown): string[] {
    assert(Array.isArray(caps), 400, "invalid_request", "capabilities must be an array");
    for (const c of caps as string[]) {
      assert(CAPABILITIES[c], 400, "unknown_capability", `unknown capability ${c}`);
      assert(MVP_GRANTABLE.includes(c) && CAPABILITIES[c].pregrantable, 400, "capability_not_pregrantable", `${c} cannot be pre-granted`);
    }
    return [...new Set(caps as string[])];
  }

  /** #211: a caller-supplied `scope` before it can reach `insertGrant`. `{}` is accepted everywhere because
   *  internal callers write it; a non-empty scope only for a capability whose implementation reads it, and its
   *  values must be ones the read path can enforce (`window_days` a positive whole number, `hours` a parseable
   *  range). */
  private assertScope(capability: string, scope: unknown) {
    if (scope == null) return;
    assert(typeof scope === "object" && !Array.isArray(scope), 400, "invalid_request", "scope must be an object");
    const s = scope as Record<string, unknown>;
    if (!Object.keys(s).length) return;
    assert(SCOPED_CAPABILITIES.has(capability), 400, "invalid_request", `scope is not supported for ${capability}`);
    if (s.window_days != null) assert(Number.isInteger(s.window_days) && (s.window_days as number) > 0, 400, "invalid_request", "scope.window_days must be a positive whole number");
    if (s.hours != null) assert(typeof s.hours === "string" && parseHours(s.hours) !== null, 400, "invalid_request", "scope.hours must be a time range like 09:00-18:00");
  }

  consent(p: Principal, relId: string, body: { decision: "accept" | "decline"; grant_capabilities?: (string | { capability: string; scope?: any; expires_in_days?: number })[] }) {
    const ownerId = this.requireOwner(p);
    this.expireStale();
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    assert(r, 404, "relationship_not_found");
    assert(r.target_owner === ownerId, 403, "forbidden", "only the target owner can consent");
    assert(r.status === "pending_target", 409, "invalid_state", `relationship is ${r.status}`);
    assert(["accept", "decline"].includes(body?.decision), 400, "invalid_request", "decision must be accept|decline");
    if (body.decision === "decline") {
      this.run("UPDATE relationships SET status = 'declined', updated_at = ? WHERE id = ?", nowIso(), relId);
      // A declined join never became a friendship: give the invite slot back, exactly as `expireStale` and a
      // rejected approval do, so a 1-use link does not read "used" while no relationship exists (P9).
      this.releaseInviteUse(relId);
      this.audit.append(`owner:${ownerId}`, "relationship.declined", relId, [r.requester_owner, r.target_owner], {});
      this.emit(r.requester_bot, "relationship.changed", { relationship_id: relId, status: "declined" });
      return { relationship_id: relId, status: "declined" };
    }
    // A pending row names two Bots and can wait for days; either side may be removed from its home while it waits,
    // and a removed member is `revoked` (#173). Every later reach is refused by activeRelationship, so activating
    // here would write an `active` friendship with a full grant set for an identity that cannot answer - and tell
    // both owners it is live. The row stays pending: this is a refusal, not a cancellation.
    for (const id of [r.requester_bot, r.target_bot]) {
      assert(this.bot(id).status !== "revoked", 403, "bot_revoked", "a Bot in this relationship was revoked");
    }
    const specs = (body.grant_capabilities ?? []).map((g) => (typeof g === "string" ? { capability: g } : g));
    this.validCaps(specs.map((s) => s.capability));
    for (const s of specs) this.assertScope(s.capability, s.scope);
    this.activateRelationship(r, specs, `owner:${ownerId}`);
    return { relationship_id: relId, status: "active", grants: this.grantsFor(relId) };
  }

  /** Activate a relationship: minimal defaults both ways + target owner's choices + requester's offered caps. */
  private activateRelationship(r: any, targetSpecs: { capability: string; scope?: any; expires_in_days?: number }[], actor: string) {
    this.writeActivation(r, targetSpecs, actor);
    this.announceActivation(r, targetSpecs, actor);
  }

  /** #30: the grants are written before the relationship reads `active`, in one transaction, so nothing can see a
   *  confirmed friendship whose grants are not durable yet. Announcing it is announceActivation, after the commit. */
  private writeActivation(r: any, targetSpecs: { capability: string; scope?: any; expires_in_days?: number }[], actor: string) {
    const fbScope = { window_days: 14, hours: "09:00-18:00" };
    this.db.transaction(() => {
      const targetToRequester = new Map<string, any>(DEFAULT_CAPABILITIES.map((c) => [c, { capability: c }]));
      for (const s of targetSpecs) targetToRequester.set(s.capability, { scope: s.capability === "calendar.freebusy.read" ? fbScope : {}, ...s });
      for (const s of targetToRequester.values()) this.insertGrant(r.id, r.target_owner, r.requester_bot, s.capability, s.scope, s.expires_in_days, actor);
      const requesterToTarget = new Set<string>([...DEFAULT_CAPABILITIES, ...J(r.offered_caps, [])]);
      // #23: on an invite-born friendship the requester is the joiner. What the joiner's owner gives the inviter's Bot
      // by joining is reply-only: it may answer in a conversation the joiner's Bot started, never start one.
      const replyOnly = !!this.get("SELECT 1 FROM relationship_invites ri JOIN invites i ON i.id = ri.invite_id WHERE ri.relationship_id = ? AND i.bot_id = ?", r.id, r.target_bot);
      for (const c of requesterToTarget) this.insertGrant(r.id, r.requester_owner, r.target_bot, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, `owner:${r.requester_owner}`, { replyOnly });
      this.run("UPDATE relationships SET status = 'active', updated_at = ?, expires_at = NULL WHERE id = ?", nowIso(), r.id);
    })();
  }

  /** Runs only after writeActivation committed. Both Bots' `relationship.changed` carries the grants already written
   *  (`grants_ready: true`), so a home can record them before it handles the first message (FlyBot #442). */
  private announceActivation(r: any, targetSpecs: { capability: string }[], actor: string) {
    this.audit.append(actor, "relationship.accepted", r.id, [r.requester_owner, r.target_owner], { granted_to_requester: targetSpecs.map((s) => s.capability) });
    const grants = this.grantSummary(r.id);
    for (const b of [r.requester_bot, r.target_bot]) this.emit(b, "relationship.changed", { relationship_id: r.id, status: "active", grants_ready: true, grants });
  }

  /** The active relationship-level grants of one relationship, one entry per direction: the Bot that is shared
   *  (`granted_bot`), the Bot it is shared with (`grantee_bot`), the capabilities, and whether it is reply-only (#23). */
  grantSummary(relId: string) {
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    if (!r) return [];
    const groups = new Map<string, any>();
    // Only unexpired rows: this is the internal summary behind `announceActivation`, the join response's
    // `grants_ready` and `grantBotToFriend`, and it used to list a grant whose `expires_at` had already passed —
    // `grantsFor`/`findGrant`/`listBotGrants` expired lazily but this aggregate did not. Strict `>`: an expiry
    // equal to now is already over.
    for (const g of this.all("SELECT * FROM grants WHERE relationship_id = ? AND status = 'active' AND room_id IS NULL AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at, id", relId, nowIso())) {
      const key = `${g.grantor_owner}:${g.grantee_bot}`;
      const granted = this.bot(this.grantedBotOf(g, r));
      const grantee = this.bot(g.grantee_bot);
      const cur = groups.get(key) ?? { grant_id: g.id, granted_bot: { bot_id: granted.id, handle: "@" + granted.handle }, grantee_bot: { bot_id: grantee.id, handle: "@" + grantee.handle }, capabilities: [] as string[], reply_only: this.replyOnlyAccess(relId, g.grantor_owner, g.grantee_bot) };
      if (!cur.capabilities.includes(g.capability)) cur.capabilities.push(g.capability);
      groups.set(key, cur);
    }
    return [...groups.values()];
  }

  /** A caller-supplied `expires_in_days` becomes an expiry here, before anything is written. `null`/omitted keeps
   *  LIMITS.grantDefaultDays; anything that is not a finite positive number of days, or that lands outside the Date
   *  range, is a 400. Doing it in `insertGrant` covers every path that writes a grant (the owner route, the approval
   *  branch's `edited_params`, consent), so a typo is refused instead of superseding a live grant and then answering
   *  500 from `toISOString()`. */
  private grantExpiry(expiresInDays: unknown): string {
    const days = expiresInDays == null ? LIMITS.grantDefaultDays : Number(expiresInDays);
    assert(Number.isFinite(days) && days > 0, 400, "invalid_request", "expires_in_days must be a positive number of days");
    const ms = Date.now() + days * 86400e3;
    assert(Number.isFinite(ms) && Math.abs(ms) <= 8.64e15, 400, "invalid_request", "expires_in_days is too large: the expiry date would be invalid");
    return new Date(ms).toISOString();
  }

  /** `extra.replyOnly` (#23): the grantee may answer in a conversation the granted Bot started, but not start one
   *  or bring the Bot into a face room. Set only for the joiner-side grants a join writes; every explicit grant is full. */
  private insertGrant(relId: string, grantorOwner: string, granteeBot: string, cap: string, scope: any, expiresInDays: unknown, actor: string, extra: { roomId?: string; replyOnly?: boolean } = {}) {
    // Validate and compute the expiry before the supersede: a rejected value must never take the live grant down
    // with it (the UPDATE below would mark the old grant superseded and nothing would replace it).
    const exp = extra.roomId ? null : this.grantExpiry(expiresInDays);
    this.run("UPDATE grants SET status = 'superseded' WHERE relationship_id = ? AND grantor_owner = ? AND capability = ? AND status = 'active' AND IFNULL(room_id,'') = ?", relId, grantorOwner, cap, extra.roomId ?? "");
    const id = newId("grt");
    const sc = extra.roomId ? { ...(scope ?? {}), kind: "room", room_id: extra.roomId } : { ...(scope ?? {}) };
    const replyOnly = !!extra.replyOnly && !extra.roomId;
    this.run("INSERT INTO grants (id, relationship_id, grantor_owner, grantee_bot, capability, scope, created_at, expires_at, room_id, reply_only) VALUES (?,?,?,?,?,?,?,?,?,?)",
      id, relId, grantorOwner, granteeBot, cap, JSON.stringify(sc), nowIso(), exp, extra.roomId ?? null, replyOnly ? 1 : 0);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    this.audit.append(actor, "grant.created", id, [r.requester_owner, r.target_owner], { relationship_id: relId, grantor_owner: grantorOwner, grantee_bot: granteeBot, capability: cap, scope: sc, expires_at: exp, room_id: extra.roomId ?? null, ...(replyOnly ? { reply_only: true } : {}) });
    return id;
  }

  /** The relationship-level grants of one relationship, as `/v1/relationships` lists them.
   *
   *  A row whose expiry has passed is written back to `expired` and left out: this is the read the reach checks share
   *  the shape of, and a lapsed grant must never look live. `includeExpired` is for the owner's own overview only
   *  (#218's expired + Renew has nothing to renew on a cold page): it does the same lazy write-back, then returns the
   *  `expired` rows too, each carrying its `status`, so the card can say the grant ended and offer to renew it.
   *  Nothing about access changes here — `findGrant`, `listBotGrants`, `sendAsMember` and room reach keep dropping a
   *  lapsed row on their own. */
  grantsFor(relId: string, opts: { includeExpired?: boolean } = {}) {
    const out: any[] = [];
    const rows = this.all(
      opts.includeExpired
        ? "SELECT * FROM grants WHERE relationship_id = ? AND status IN ('active','expired') ORDER BY created_at, id"
        : "SELECT * FROM grants WHERE relationship_id = ? AND status = 'active'",
      relId,
    );
    for (const g of rows) {
      // The lazy expiry `findGrant` and `listBotGrants` already do: a row whose expiry has passed must not be listed
      // by `/v1/relationships` while `/v1/bots/:id/grants` hides it.
      const lapsed = g.status === "expired" || (!!g.expires_at && Date.parse(g.expires_at) < Date.now());
      if (lapsed && g.status !== "expired") this.run("UPDATE grants SET status = 'expired' WHERE id = ?", g.id);
      if (lapsed && !opts.includeExpired) continue;
      out.push({ ...g, status: lapsed ? "expired" : "active", scope: J(g.scope, {}) });
    }
    if (!opts.includeExpired) return out;
    // A capability that lapsed and was granted again has two rows: the ended one and the live one. The card shows one
    // chip per capability, so keep the live row; with nothing live, the most recently created ended row.
    const one = new Map<string, any>();
    for (const g of out) {
      const key = `${g.grantee_bot}:${g.capability}`;
      const cur = one.get(key);
      if (!cur || (cur.status === "expired" && (g.status === "active" || (g.status === "expired" && g.created_at > cur.created_at)))) one.set(key, g);
    }
    return [...one.values()];
  }

  /** An active relationship-level grant; a full grant wins over a reply-only one (#23), so check `reply_only` on the result. */
  findGrant(grantorOwner: string, granteeBot: string, cap: string, grantedBot?: string): any {
    const rows = this.all("SELECT g.*, r.requester_bot, r.target_bot, r.requester_owner, r.target_owner FROM grants g JOIN relationships r ON r.id = g.relationship_id WHERE g.grantor_owner = ? AND g.grantee_bot = ? AND g.capability = ? AND g.status = 'active' AND r.status = 'active' AND g.room_id IS NULL ORDER BY g.reply_only", grantorOwner, granteeBot, cap);
    for (const g of rows) {
      if (g.expires_at && Date.parse(g.expires_at) < Date.now()) { this.run("UPDATE grants SET status = 'expired' WHERE id = ?", g.id); continue; }
      if (grantedBot && this.grantedBotOf(g, g) !== grantedBot) continue;
      return { ...g, scope: J(g.scope, {}) };
    }
    return null;
  }

  /**
   * #43: reach without a friendship. A Bot that joined a room with a ticket may send to another Bot of that room
   * while both are in it and the room-scoped grant is alive. Nothing here creates a friendship: the pair can only
   * talk with this room id, and the reach dies with the room.
   *
   * The door is the one named by the grant that was actually checked, never "the newest room between the pair":
   * a pair can share several rooms, and searching for a room relationship hands back whichever room was created
   * last (pairRelationships is ORDER BY created_at DESC), so room 1 would ride on room 2's door.
   */
  private roomReach(a: string, b: string, roomId: string): Relationship | null {
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    // #60: a room that lives in one FlyBot home has no face_rooms row; its door is a live claimed ticket for that
    // room that seats exactly this pair (the inviter's Bot and one Bot the claim brought).
    if (!room) return this.localPairClaim(roomId, a, b) ? this.roomRelationshipOf(a, b, roomId) : null;
    if (room.status === "closed") return null;
    const inRoom = (botId: string) => !!this.get("SELECT 1 FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", roomId, botId);
    if (!inRoom(a) || !inRoom(b)) return null;
    return this.roomRelationshipOf(a, b, roomId);
  }
  private roomRelationshipOf(a: string, b: string, roomId: string): Relationship | null {
    const grant = this.findRoomGrant(this.bot(b).owner_id, a, "chat.public", b, roomId);
    if (!grant) return null;
    return this.get("SELECT * FROM relationships WHERE id = ? AND status = 'room'", grant.relationship_id) ?? null;
  }

  /**
   * #45: an active grant scoped to one room, written when the owners put these two Bots in that room together
   * (syncFaceRoomAccess) or when a room ticket is claimed (#43). It is what lets a send name a room context.
   */
  private findRoomGrant(grantorOwner: string, granteeBot: string, cap: string, grantedBot: string, roomId: string): any {
    // A block is a decision about the pair, and a room door is still a door between the same two Bots: a grant
    // that outlived the block (a row blocked before this rule existed, or one the block could not reach) must not
    // answer for them. Checked here, at the single lookup every room door goes through.
    if (this.pairRelationships(grantedBot, granteeBot).some((r: any) => r.status === "blocked")) return null;
    const rows = this.all("SELECT g.*, r.requester_bot, r.target_bot, r.requester_owner, r.target_owner FROM grants g JOIN relationships r ON r.id = g.relationship_id WHERE g.grantor_owner = ? AND g.grantee_bot = ? AND g.capability = ? AND g.status = 'active' AND g.room_id = ? AND r.status = 'room'", grantorOwner, granteeBot, cap, roomId);
    for (const g of rows) {
      if (g.expires_at && Date.parse(g.expires_at) < Date.now()) { this.run("UPDATE grants SET status = 'expired' WHERE id = ?", g.id); continue; }
      if (this.grantedBotOf(g, g) !== grantedBot) continue;
      return { ...g, scope: J(g.scope, {}) };
    }
    return null;
  }

  addGrant(p: Principal, relId: string, body: { capability: string; scope?: any; expires_in_days?: number }) {
    const ownerId = this.requireOwner(p);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    assert(r, 404, "relationship_not_found");
    assert(r.status === "active", 409, "invalid_state", `relationship is ${r.status}`);
    assert(ownerId === r.requester_owner || ownerId === r.target_owner, 403, "forbidden");
    this.validCaps([body?.capability]);
    this.assertScope(body.capability, body.scope);
    const grantee = ownerId === r.requester_owner ? r.target_bot : r.requester_bot;
    // The supersede and the insert are one write: a throw between them must not leave the old grant revoked.
    const id = this.db.transaction(() => this.insertGrant(relId, ownerId, grantee, body.capability, body.scope, body.expires_in_days, `owner:${ownerId}`)).immediate();
    this.emit(grantee, "grant.changed", { relationship_id: relId, capability: body.capability, status: "granted" });
    return { grant_id: id, capability: body.capability, grantee_bot: grantee, status: "active" };
  }

  revokeGrant(p: Principal, grantId: string) {
    const ownerId = this.requireOwner(p);
    const g = this.get("SELECT * FROM grants WHERE id = ?", grantId);
    assert(g, 404, "grant_not_found");
    assert(g.grantor_owner === ownerId, 403, "forbidden", "only the grantor can revoke");
    this.run("UPDATE grants SET status = 'revoked', revoked_at = ? WHERE id = ?", nowIso(), grantId);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", g.relationship_id);
    this.endGrantRooms([grantId], `owner:${ownerId}`);
    this.audit.append(`owner:${ownerId}`, "grant.revoked", grantId, [r?.requester_owner, r?.target_owner], { capability: g.capability, grantee_bot: g.grantee_bot });
    this.emit(g.grantee_bot, "grant.changed", { relationship_id: g.relationship_id, capability: g.capability, status: "revoked" });
    return { grant_id: grantId, status: "revoked" };
  }

  /**
   * Revoke one person's access to one of my bots (every capability in that bundle) without
   * touching grants of my other bots. Removes the bot from rooms where that grant was used.
   */
  revokeBotGrant(p: Principal, grantId: string, botId?: string) {
    const ownerId = this.requireOwner(p);
    const g = this.get("SELECT * FROM grants WHERE id = ?", grantId);
    assert(g, 404, "grant_not_found");
    assert(g.grantor_owner === ownerId, 403, "forbidden", "only the grantor can revoke");
    const r = this.get("SELECT * FROM relationships WHERE id = ?", g.relationship_id);
    const granted = this.grantedBotOf(g, r);
    if (botId) {
      const bot = this.ownBot(ownerId, this.resolveOwnBot(ownerId, botId).id);
      assert(granted === bot.id, 404, "grant_not_found", "that grant is not for this bot");
    }
    const bundle = this.all("SELECT * FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND IFNULL(room_id,'') = ?",
      g.relationship_id, ownerId, g.grantee_bot, g.room_id ?? "");
    const ids = bundle.map((x: any) => x.id);
    const now = nowIso();
    for (const id of ids) this.run("UPDATE grants SET status = 'revoked', revoked_at = ? WHERE id = ?", now, id);
    const rooms = this.endGrantRooms(ids, `owner:${ownerId}`);
    this.audit.append(`owner:${ownerId}`, "grant.revoked", grantId, [r?.requester_owner, r?.target_owner], {
      capability: g.capability, grantee_bot: g.grantee_bot, granted_bot: granted, bundle: ids, rooms,
    });
    this.emit(g.grantee_bot, "grant.changed", { relationship_id: g.relationship_id, capability: g.capability, status: "revoked", granted_bot: granted });
    return { grant_id: grantId, status: "revoked", revoked: ids, granted_bot: granted, grantee_bot: g.grantee_bot, rooms_removed: rooms };
  }

  /**
   * Recipient side of revoke_bot_grant: the GRANTEE's owner removes a grant that was given to one of their bots.
   * The whole full-share bundle (every non-reply-only capability of that grant to that bot) ends as 'declined';
   * it disappears from the granting owner's list_bot_grants and from the grantee's list_remote_bots. Only this
   * direction ends: the friendship and any grants the other way stay. Reply-only rows (#23 / #35) are kept so
   * the caller's Bot can still answer in conversations the friend's Bot started after "Remove this Bot".
   * Declining a grant_id that is only reply-only is refused (nothing to remove as a share). The Bot leaves
   * rooms where the declined grants were used (same as a revoke). The granting owner may share the Bot again
   * with a fresh invite (see joinInvite). Needs no confirm code: it only reduces the caller's own access.
   */
  declineBotGrant(p: Principal, grantId: string, botId?: string) {
    const ownerId = this.requireOwner(p);
    const g = this.get("SELECT * FROM grants WHERE id = ?", grantId);
    assert(g, 404, "grant_not_found");
    const grantee = this.bot(g.grantee_bot);
    assert(grantee.owner_id === ownerId && g.grantor_owner !== ownerId, 403, "forbidden", "only the owner of the grantee bot can decline this grant");
    assert(g.status === "active", 404, "grant_not_found", "that grant is no longer active");
    const r = this.get("SELECT * FROM relationships WHERE id = ?", g.relationship_id);
    const granted = this.grantedBotOf(g, r);
    if (botId) {
      const ref = this.get("SELECT id FROM bots WHERE id = ?", botId) ?? this.botByRef(botId);
      assert(ref && ref.id === granted, 404, "grant_not_found", "that grant is not for this bot");
    }
    // #35: never decline reply-only rows — those let this Bot answer the friend's Bot after a join.
    const bundle = this.all("SELECT id FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND IFNULL(room_id,'') = ? AND IFNULL(reply_only, 0) = 0",
      g.relationship_id, g.grantor_owner, g.grantee_bot, g.room_id ?? "");
    assert(bundle.length > 0, 404, "grant_not_found", "that grant is reply-only; decline removes a full share only");
    const ids = bundle.map((x: any) => x.id as string);
    const now = nowIso();
    for (const id of ids) this.run("UPDATE grants SET status = 'declined', revoked_at = ? WHERE id = ?", now, id);
    const rooms = this.endGrantRooms(ids, `owner:${ownerId}`);
    this.audit.append(`owner:${ownerId}`, "grant.declined", grantId, [r?.requester_owner, r?.target_owner], {
      capability: g.capability, grantee_bot: g.grantee_bot, granted_bot: granted, grantor_owner: g.grantor_owner, bundle: ids, rooms,
    });
    for (const b of new Set([granted, g.grantee_bot].filter(Boolean))) {
      this.emit(b, "grant.changed", { relationship_id: g.relationship_id, capability: g.capability, status: "declined", granted_bot: granted, grantee_bot: g.grantee_bot });
    }
    return { grant_id: grantId, status: "declined", declined: ids, granted_bot: granted, grantee_bot: g.grantee_bot, rooms_removed: rooms };
  }

  /**
   * #34: owner grants an existing friend access to one of their Bots without an invite code.
   * Creates the same per-Bot full share (and reciprocal reply-only if missing) that accepting an invite would.
   * Idempotent when a live full grant of this Bot to the friend already exists. Friend is notified via grant.changed;
   * they may decline_bot_grant; the owner may revoke_bot_grant.
   * The friend is named by `friend_bot_id` (the peer Bot id `list_friends` returns, #592) or by the older
   * `friend_owner_id`; with a Bot id the owner is derived from it, so a caller never needs an owner id.
   */
  grantBotToFriend(p: Principal, botId: string, friendOwnerId?: string, friendBotId?: string) {
    const ownerId = this.requireOwner(p);
    const namedOwner = typeof friendOwnerId === "string" ? friendOwnerId.trim() : "";
    const namedBot = typeof friendBotId === "string" ? friendBotId.trim() : "";
    assert(namedOwner || namedBot, 400, "invalid_request", "friend_owner_id or friend_bot_id required");
    const bot = this.resolveOwnBot(ownerId, botId);
    const peerBot = namedBot
      ? this.get("SELECT * FROM bots WHERE id = ?", namedBot) ?? this.botByRef(namedBot)
      : undefined;
    if (namedBot) assert(peerBot, 404, "friend_not_found", "no such Bot");
    if (peerBot) assert(peerBot.owner_id !== ownerId, 400, "invalid_request", "cannot grant a Bot to yourself");
    if (peerBot && namedOwner) assert(namedOwner === peerBot.owner_id, 400, "invalid_request", "friend_owner_id and friend_bot_id name different owners");
    const friendOwnerKey: string = peerBot ? String(peerBot.owner_id) : namedOwner;
    assert(friendOwnerKey !== ownerId, 400, "invalid_request", "cannot grant a Bot to yourself");
    friendOwnerId = friendOwnerKey;
    const friendOwner = this.get("SELECT * FROM owners WHERE id = ?", friendOwnerKey);
    assert(friendOwner, 404, "friend_not_found", "no such owner");

    this.expireStale();
    const friendships = this.all(
      `SELECT * FROM relationships WHERE status = 'active'
        AND ((requester_owner = ? AND target_owner = ?) OR (requester_owner = ? AND target_owner = ?))
        ORDER BY updated_at DESC`,
      ownerId, friendOwnerId, friendOwnerId, ownerId,
    );
    assert(friendships.length > 0, 404, "friend_not_found", "that owner is not an active friend");
    if (peerBot) {
      // Named by Bot: the share targets that friend Bot itself, not any other Bot of the same owner.
      const named = friendships.filter((r: any) => r.requester_bot === peerBot.id || r.target_bot === peerBot.id);
      assert(named.length > 0, 404, "friend_not_found", "that Bot is not an active friend");
      friendships.length = 0;
      friendships.push(...named);
    }

    // A block is per Bot pair. Never let this shortcut create a fresh relationship around one:
    // `requestRelationship` and `joinInvite` both refuse a blocked pair, and so must this.
    const pairBotOf = (r: any) => (r.requester_owner === ownerId ? r.target_bot : r.requester_bot);
    const blockedPair = (otherBot: string) => this.pairRelationships(bot.id, otherBot).some((r: any) => r.status === "blocked");
    const usable = friendships.filter((r: any) => !blockedPair(pairBotOf(r)));
    assert(usable.length > 0, 403, "blocked", "relationship is blocked");

    // Idempotent: already a live full share of this Bot to any of the friend's bots.
    for (const rel of usable) {
      const myBot = rel.requester_owner === ownerId ? rel.requester_bot : rel.target_bot;
      const friendBot = rel.requester_owner === ownerId ? rel.target_bot : rel.requester_bot;
      if (myBot !== bot.id) continue;
      if (this.hasLiveGrant(ownerId, friendBot, rel.id)) {
        const listed = this.listBotGrants(p, bot.id).grants.find((g: any) => g.relationship_id === rel.id && (g.grantee.bot_id === friendBot || handleKey(g.grantee.handle) === handleKey(this.bot(friendBot).handle)));
        const summary = this.grantSummary(rel.id).find((g: any) => g.granted_bot.bot_id === bot.id && g.grantee_bot.bot_id === friendBot && !g.reply_only);
        return {
          grant_id: listed?.grant_id ?? summary?.grant_id ?? this.findGrant(ownerId, friendBot, "chat.public", bot.id)?.id,
          bot_id: bot.id,
          friend_owner_id: friendOwnerId,
          grantee_bot: friendBot,
          relationship_id: rel.id,
          status: "active",
          capabilities: listed?.capabilities ?? summary?.capabilities ?? ["chat.public", "profile.read"],
          reply_only: false,
          idempotent: true,
        };
      }
    }

    // Prefer an existing relationship whose endpoint on our side is this Bot; else open one with the friend's bot from the newest friendship.
    let rel = usable.find((r: any) => (r.requester_owner === ownerId ? r.requester_bot : r.target_bot) === bot.id);
    let friendBot: string;
    let createdRel = false;
    if (rel) {
      friendBot = pairBotOf(rel);
    } else {
      const base = usable[0];
      friendBot = base.requester_owner === friendOwnerId ? base.requester_bot : base.target_bot;
      const existingPair = this.findActiveRelationship(bot.id, friendBot);
      if (existingPair) {
        rel = existingPair;
      } else {
        // Mirror an invite join: friend bot is requester, our Bot is target (we are the "inviter").
        const id = newId("rel");
        const now = nowIso();
        this.run(
          `INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, message, requested_caps, offered_caps, created_at, updated_at, expires_at, requester_scope, target_scope)
            VALUES (?,?,?,?,?,'active',?,?,?,?,?,NULL,'bot','bot')`,
          id, friendBot, bot.id, friendOwnerId, ownerId,
          `Granted by owner (no invite)`, JSON.stringify(DEFAULT_CAPABILITIES), JSON.stringify(DEFAULT_CAPABILITIES), now, now,
        );
        rel = this.get("SELECT * FROM relationships WHERE id = ?", id);
        createdRel = true;
      }
    }

    const actor = `owner:${ownerId}`;
    const fbScope = { window_days: 14, hours: "09:00-18:00" };
    const caps = [...DEFAULT_CAPABILITIES];
    this.db.transaction(() => {
      for (const c of caps) this.insertGrant(rel.id, ownerId, friendBot, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, actor);
      // Reciprocal reply-only (#23), same as a join, only when missing.
      for (const c of caps) {
        if (!this.findGrant(friendOwnerKey, bot.id, c, friendBot)) {
          this.insertGrant(rel.id, friendOwnerKey, bot.id, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, `owner:${friendOwnerKey}`, { replyOnly: true });
        }
      }
    })();

    this.audit.append(actor, "grant.created", rel.id, [ownerId, friendOwnerId], {
      relationship_id: rel.id, granted_bot: bot.id, grantee_bot: friendBot, friend_owner_id: friendOwnerId, via: "grant_bot_to_friend", created_relationship: createdRel,
    });
    for (const b of [bot.id, friendBot]) {
      this.emit(b, "grant.changed", { relationship_id: rel.id, status: "granted", granted_bot: bot.id, grantee_bot: friendBot });
    }

    const listed = this.listBotGrants(p, bot.id).grants.find((g: any) => g.grantee.bot_id === friendBot || handleKey(g.grantee.handle) === handleKey(this.bot(friendBot).handle));
    const summary = this.grantSummary(rel.id).find((g: any) => g.granted_bot.bot_id === bot.id && g.grantee_bot.bot_id === friendBot && !g.reply_only);
    return {
      grant_id: listed?.grant_id ?? summary?.grant_id ?? this.findGrant(ownerId, friendBot, "chat.public", bot.id)?.id,
      bot_id: bot.id,
      friend_owner_id: friendOwnerId,
      grantee_bot: friendBot,
      relationship_id: rel.id,
      status: "active",
      capabilities: listed?.capabilities ?? summary?.capabilities ?? caps,
      reply_only: false,
      idempotent: false,
      ...(createdRel ? { created_relationship: true } : {}),
    };
  }

  /** This owner's side of a relationship: "joiner" when their Bot joined the other's invite (or sent the friend
   *  request, the requester), "inviter" when the other side joined theirs. Derived from what every relationship
   *  already stores (requester_* / target_*), so old relationships are classified too. Null for room-only grants. */
  private sideOf(r: { requester_owner: string; rel_status?: string; status?: string }, ownerId: string): "joiner" | "inviter" | null {
    if ((r.rel_status ?? r.status) === "room") return null;
    return r.requester_owner === ownerId ? "joiner" : "inviter";
  }

  /** Grants of one of my bots: who has it, scope, rooms, created/expiry. */
  listBotGrants(p: Principal, botId: string) {
    const ownerId = this.requireOwner(p);
    const bot = this.resolveOwnBot(ownerId, botId);
    this.expireStale();
    const rows = this.all(`SELECT g.*, r.requester_bot, r.target_bot, r.requester_owner, r.target_owner, r.status AS rel_status
      FROM grants g JOIN relationships r ON r.id = g.relationship_id
      WHERE g.grantor_owner = ? AND g.status = 'active' AND r.status IN ('active','room')
      ORDER BY g.created_at`, ownerId);
    const groups = new Map<string, any>();
    for (const g of rows) {
      const granted = this.grantedBotOf(g, g);
      if (granted !== bot.id) continue;
      if (g.expires_at && Date.parse(g.expires_at) < Date.now()) { this.run("UPDATE grants SET status = 'expired' WHERE id = ?", g.id); continue; }
      const key = `${g.relationship_id}:${g.grantee_bot}:${g.room_id ?? ""}`;
      const grantee = this.bot(g.grantee_bot);
      const moreRooms = this.activeGrantRooms(g.id);
      const scope = g.room_id || J(g.scope, {}).kind === "room" ? "room" : (moreRooms.length ? "group" : "person");
      const cur = groups.get(key) ?? {
        grant_id: g.id, grantee: this.publicBot(grantee, true), scope,
        room: g.room_id ? this.grantRoomPublic(g.room_id) : moreRooms[0] ?? null,
        rooms: [] as any[], capabilities: [] as string[], created_at: g.created_at, expires_at: g.expires_at,
        relationship_id: g.rel_status === "room" ? null : g.relationship_id, side: this.sideOf(g, ownerId),
        reply_only: !g.room_id && this.replyOnlyAccess(g.relationship_id, ownerId, g.grantee_bot),
      };
      for (const room of moreRooms) if (!cur.rooms.some((x: any) => x.room_id === room.room_id)) cur.rooms.push(room);
      if (moreRooms.length && cur.scope === "person") cur.scope = "group";
      if (!cur.room) cur.room = g.room_id ? this.grantRoomPublic(g.room_id) : moreRooms[0] ?? null;
      if (!cur.capabilities.includes(g.capability)) cur.capabilities.push(g.capability);
      if (g.created_at < cur.created_at) cur.created_at = g.created_at;
      groups.set(key, cur);
    }
    return { bot: this.publicBot(bot, true), grants: [...groups.values()] };
  }

  /** Bots other owners have granted TO me. */
  listRemoteBots(p: Principal, homeId?: string) {
    const ownerId = this.requireOwner(p);
    let mine: string[];
    if (homeId) {
      const home = this.ownHome(ownerId, homeId);
      mine = [home.id, ...this.homeMembers(home.id).map((m: any) => m.bot_id)];
    } else {
      mine = this.all("SELECT id FROM bots WHERE owner_id = ? AND status = 'active'", ownerId).map((b: any) => b.id);
    }
    if (!mine.length) return { bots: [], homes: [] };
    this.expireStale();
    const marks = mine.map(() => "?").join(",");
    const rows = this.all(`SELECT g.*, r.requester_bot, r.target_bot, r.requester_owner, r.target_owner, r.status AS rel_status
      FROM grants g JOIN relationships r ON r.id = g.relationship_id
      WHERE g.grantee_bot IN (${marks}) AND g.grantor_owner != ? AND g.status = 'active' AND r.status IN ('active','room')
      ORDER BY g.created_at`, ...mine, ownerId);
    const bots: any[] = [];
    const byHome = new Map<string, any>();
    const seen = new Set<string>();
    for (const g of rows) {
      if (g.expires_at && Date.parse(g.expires_at) < Date.now()) { this.run("UPDATE grants SET status = 'expired' WHERE id = ?", g.id); continue; }
      const grantedId = this.grantedBotOf(g, g);
      if (!grantedId || mine.includes(grantedId) || seen.has(grantedId + ":" + g.grantee_bot)) continue;
      const granted = this.get("SELECT * FROM bots WHERE id = ? AND status = 'active'", grantedId);
      if (!granted) continue;
      seen.add(grantedId + ":" + g.grantee_bot);
      const rooms = this.activeGrantRooms(g.id);
      const scope = g.room_id || J(g.scope, {}).kind === "room" ? "room" : (rooms.length ? "group" : "person");
      const item = {
        bot_id: granted.id, handle: "@" + granted.handle, display_name: peerBotName(granted), ...lookOf(granted),
        owner_display_name: peerOwnerName(this.owner(granted.owner_id)),
        grant_id: g.id, scope, room: g.room_id ? this.grantRoomPublic(g.room_id) : rooms[0] ?? null, rooms,
        via: "@" + this.bot(g.grantee_bot).handle, created_at: g.created_at, expires_at: g.expires_at,
        relationship_id: g.rel_status === "room" ? null : g.relationship_id, side: this.sideOf(g, ownerId),
        reply_only: !g.room_id && this.replyOnlyAccess(g.relationship_id, g.grantor_owner, g.grantee_bot),
      };
      bots.push(item);
      const peerHome = this.bot(this.homeOf(granted.id));
      const entry = byHome.get(peerHome.id) ?? {
        relationship_id: item.relationship_id, relationship_ids: [] as string[], side: item.side, relationship_sides: {} as Record<string, "joiner" | "inviter" | null>,
        home: { bot_id: peerHome.id, handle: "@" + peerHome.handle, display_name: peerBotName(peerHome), ...lookOf(peerHome), owner_display_name: peerOwnerName(this.owner(peerHome.owner_id)) },
        bots: [] as any[], scope: "member", via: [] as string[],
      };
      if (item.relationship_id && !entry.relationship_ids.includes(item.relationship_id)) { entry.relationship_ids.push(item.relationship_id); entry.relationship_sides[item.relationship_id] = item.side; }
      if (!entry.bots.some((x: any) => x.bot_id === granted.id)) {
        entry.bots.push({ bot_id: granted.id, handle: "@" + granted.handle, display_name: peerBotName(granted), ...lookOf(granted), grant_id: g.id, scope, room: item.room, rooms, created_at: g.created_at, expires_at: g.expires_at, relationship_id: item.relationship_id, side: item.side, reply_only: item.reply_only });
      }
      if (!entry.via.includes(item.via)) entry.via.push(item.via);
      byHome.set(peerHome.id, entry);
    }
    return { bots, homes: [...byHome.values()] };
  }

  /** #23: is this grantee's access to the grantor's Bot on this relationship reply-only? True when it holds a reply-only
   *  grant from the join and no full `chat.public`: it may answer that Bot, not start a conversation with it or bring it
   *  into a room. A full grant of another capability (say calendar.freebusy.read) does not share the Bot for talking. */
  private replyOnlyAccess(relId: string, grantorOwner: string, granteeBot: string): boolean {
    const rows = this.all("SELECT capability, reply_only, expires_at FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND room_id IS NULL", relId, grantorOwner, granteeBot)
      .filter((g: any) => !g.expires_at || Date.parse(g.expires_at) >= Date.now());
    return rows.some((g: any) => g.reply_only) && !rows.some((g: any) => g.capability === "chat.public" && !g.reply_only);
  }

  /**
   * #23: `senderBot` holds only the reply-only grant a join gave it on `target`, so it may not start a conversation
   * with `target` (or bring it into a face room). Refuse with 403 bot_not_shared, store nothing, and tell the target's
   * owner with a `share.requested` event on the target Bot (at most once a day per sender) so they can choose to
   * share the Bot. Nothing is ever granted automatically.
   */
  private refuseUnshared(senderBot: string, target: any, relId: string, attempted: "conversation.create" | "message.draft" | "face_room.join", convId: string | null = null): never {
    const sender = this.bot(senderBot);
    this.policyDecision(senderBot, convId, [sender.owner_id, target.owner_id], attempted, "deny", ["grant.reply_only:chat.public"]);
    const since = new Date(Date.now() - 86400e3).toISOString();
    const recent = this.get("SELECT 1 FROM events WHERE bot_id = ? AND type = 'share.requested' AND created_at > ? AND json_extract(data, '$.from.bot_id') = ?", target.id, since, senderBot);
    if (!recent) {
      this.emit(target.id, "share.requested", {
        relationship_id: relId, bot_id: target.id, from: this.publicBot(sender), attempted, trust: "platform",
        note: "This Bot is not shared with the sender, so their attempt to start a conversation was refused and nothing was delivered. Only your owner can share this Bot (for example with an invite link for this Bot); nothing is shared automatically.",
      });
    }
    throw new ApiError(403, "bot_not_shared",
      `@${target.handle} is not shared with your Bot: its owner allows replies only in conversations their Bot starts. Nothing was delivered. Their owner has been told and can choose to share it.`,
      { suggestion: "ask_owner_to_share", bot_id: target.id, relationship_id: relId, owner_notified: true });
  }

  private resolveOwnBot(ownerId: string, ref: string) {
    const b = this.get("SELECT * FROM bots WHERE owner_id = ? AND id = ?", ownerId, ref) ?? this.botByRef(ref, "owner_id = ?", [ownerId]);
    assert(b, 404, "bot_not_found", "no such bot on this account");
    return b;
  }

  private grantRoomPublic(roomId: string) {
    const room = this.get("SELECT id, status, expires_at, started_at FROM face_rooms WHERE id = ?", roomId);
    if (!room) return { room_id: roomId, status: "unknown" };
    return { room_id: room.id, status: room.status, expires_at: room.expires_at, started_at: room.started_at };
  }

  private activeGrantRooms(grantId: string) {
    return this.all("SELECT room_id FROM grant_rooms WHERE grant_id = ? AND ended_at IS NULL", grantId)
      .map((x: any) => this.grantRoomPublic(x.room_id));
  }

  private recordGrantRoomUse(grantId: string, roomId: string, actor: string, owners: (string | null | undefined)[]) {
    const existing = this.get("SELECT * FROM grant_rooms WHERE grant_id = ? AND room_id = ?", grantId, roomId);
    if (existing && !existing.ended_at) return;
    if (existing) this.run("UPDATE grant_rooms SET ended_at = NULL, created_at = ? WHERE grant_id = ? AND room_id = ?", nowIso(), grantId, roomId);
    else this.run("INSERT INTO grant_rooms (grant_id, room_id, created_at) VALUES (?,?,?)", grantId, roomId, nowIso());
    this.audit.append(actor, "grant.used_in_room", grantId, owners, { room_id: roomId });
  }

  /** End room usages for these grants and remove the granted bot from those rooms when we added it. */
  private endGrantRooms(grantIds: string[], actor: string): string[] {
    if (!grantIds.length) return [];
    const now = nowIso();
    const removed: string[] = [];
    for (const gid of grantIds) {
      const g = this.get("SELECT * FROM grants WHERE id = ?", gid);
      if (!g) continue;
      const r = this.get("SELECT * FROM relationships WHERE id = ?", g.relationship_id);
      const granted = this.grantedBotOf(g, r);
      const granteeOwner = this.bot(g.grantee_bot).owner_id;
      const usages = this.all("SELECT * FROM grant_rooms WHERE grant_id = ? AND ended_at IS NULL", gid);
      for (const u of usages) {
        this.run("UPDATE grant_rooms SET ended_at = ? WHERE grant_id = ? AND room_id = ?", now, gid, u.room_id);
        removed.push(u.room_id);
        const member = this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", u.room_id, granted);
        if (member && member.added_by_owner_id === granteeOwner && member.added_by_owner_id !== member.owner_id) {
          this.removeFaceMember(u.room_id, member);
          this.endRoomGrantsForBots(u.room_id, [granted]);
        }
      }
      if (g.room_id) {
        const member = this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", g.room_id, granted);
        if (member) {
          this.removeFaceMember(g.room_id, member);
          this.endRoomGrantsForBots(g.room_id, [granted]);
        }
        if (!removed.includes(g.room_id)) removed.push(g.room_id);
      }
    }
    void actor;
    return [...new Set(removed)];
  }

  /** Access grant held by one of my bots on someone else's bot (relationship grants only). */
  private accessGrantTo(ownerId: string, myBotIds: string[], targetBotId: string) {
    if (!myBotIds.length) return null;
    const marks = myBotIds.map(() => "?").join(",");
    const rows = this.all(`SELECT g.*, r.requester_bot, r.target_bot, r.requester_owner, r.target_owner, r.status AS rel_status
      FROM grants g JOIN relationships r ON r.id = g.relationship_id
      WHERE g.grantee_bot IN (${marks}) AND g.grantor_owner != ? AND g.status = 'active' AND r.status = 'active' AND g.room_id IS NULL`,
      ...myBotIds, ownerId).filter((g: any) => this.grantedBotOf(g, g) === targetBotId);
    // #23: a grant whose access is reply-only comes last; the caller refuses it (bot_not_shared).
    const full = rows.find((g: any) => !this.replyOnlyAccess(g.relationship_id, g.grantor_owner, g.grantee_bot));
    return full ? { ...full, reply_only_access: false } : rows[0] ? { ...rows[0], reply_only_access: true } : null;
  }

  requestGrant(p: Principal, env: Envelope) {
    this.verifyEnvelope(p, env, "grant.request");
    const { botId, ownerId } = this.requireBot(p);
    const pl: any = env.payload ?? {};
    const r = this.get("SELECT * FROM relationships WHERE id = ? AND status = 'active'", pl.relationship_id);
    assert(r && (r.requester_bot === botId || r.target_bot === botId), 403, "no_relationship");
    this.validCaps([pl.capability]);
    this.assertScope(pl.capability, pl.scope);
    const peerOwner = r.requester_bot === botId ? r.target_owner : r.requester_owner;
    const aprId = this.createApproval(peerOwner, "grant_request", r.id, botId, null, `@${this.bot(botId).handle} requests capability ${pl.capability}`, ["grant.requires_owner"], [], LIMITS.approvalTtlMs,
      { capability: pl.capability, scope: pl.scope ?? {}, reason: pl.reason ?? null, grantee_bot: botId });
    this.audit.append(`bot:${botId}`, "grant.requested", r.id, [ownerId, peerOwner], { capability: pl.capability, scope: pl.scope ?? {}, approval_id: aprId });
    return { status: "pending_owner_approval", approval_id: aprId };
  }

  private endRelationship(ownerId: string, r: any, status: "revoked" | "blocked") {
    this.db.transaction(() => {
      this.run("UPDATE relationships SET status = ?, blocked_by = ?, updated_at = ? WHERE id = ?", status, status === "blocked" ? ownerId : null, nowIso(), r.id);
      this.run("UPDATE grants SET status = 'revoked', revoked_at = ? WHERE relationship_id = ? AND status = 'active'", nowIso(), r.id);
      this.run("UPDATE conversations SET status = 'closed', outcome = 'revoked', updated_at = ? WHERE relationship_id = ? AND status != 'closed'", nowIso(), r.id);
      // Blocked or revoked ends every card hanging off this relationship. Tell each Bot that owned one: the card
      // leaves its owner's list, and without this the Bot kept waiting on a decision that can no longer arrive.
      // Only this call site opts in — member_revoked and emergency_stop must stay silent (the Bot has no token).
      this.cancelPendingFor("(conversation_id IN (SELECT id FROM conversations WHERE relationship_id = ?) OR subject_id = ?)", [r.id, r.id], status, { notify: true });
    })();
    this.audit.append(`owner:${ownerId}`, `relationship.${status}`, r.id, [r.requester_owner, r.target_owner], {});
    for (const b of [r.requester_bot, r.target_bot]) this.emit(b, "relationship.changed", { relationship_id: r.id, status });
  }

  removeRelationship(p: Principal, relId: string) {
    const ownerId = this.requireOwner(p);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    assert(r, 404, "relationship_not_found");
    assert(ownerId === r.requester_owner || ownerId === r.target_owner, 403, "forbidden");
    assert(r.status !== "blocked", 409, "invalid_state", "relationship is blocked");
    this.endRelationship(ownerId, r, "revoked");
    return { relationship_id: relId, status: "revoked" };
  }

  /** Undo a Block the caller wrote. The row and its pair become `revoked` (what an Unfriend leaves), `blocked_by`
   *  is cleared, and nothing is restored: the grants stay void and the chats stay closed, so the pair can only start
   *  again by asking. `block` ends every row the pair holds (the friendship and one row per shared room), so the undo
   *  takes back every row this owner blocked -- the id locates the pair and decides who may undo it, nothing more. */
  undoBlock(p: Principal, relId: string) {
    const ownerId = this.requireOwner(p);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    // A pair this owner is not part of reads exactly like an id that does not exist: an undo must not become a way
    // to learn whether another pair is blocked (and by whom).
    assert(r && (ownerId === r.requester_owner || ownerId === r.target_owner), 404, "relationship_not_found");
    assert(r.status === "blocked", 409, "invalid_state", "relationship is not blocked");
    assert(r.blocked_by === ownerId, 403, "forbidden", "only the owner who blocked can undo it");
    const rows = this.pairRelationships(r.requester_bot, r.target_bot).filter((x) => x.status === "blocked" && x.blocked_by === ownerId);
    // `updated_at` is left alone: on a revoked row it is the moment the friendship ended, and `connected_at`/the
    // console's "Removed <time>" read it -- undoing the block must not move that moment to the undo.
    this.db.transaction(() => {
      for (const row of rows) this.run("UPDATE relationships SET status = 'revoked', blocked_by = NULL WHERE id = ?", row.id);
    })();
    this.audit.append(`owner:${ownerId}`, "relationship.unblocked", r.id, [r.requester_owner, r.target_owner], { relationship_ids: rows.map((x) => x.id), rows: rows.length });
    for (const botId of new Set(rows.flatMap((x) => [x.requester_bot, x.target_bot]))) this.emit(botId as string, "relationship.changed", { relationship_id: r.id, status: "revoked" });
    return { relationship_id: relId, status: "revoked" };
  }

  block(p: Principal, body: { bot_id?: string; relationship_id?: string; my_bot_id?: string }) {
    const ownerId = this.requireOwner(p);
    let r: any;
    if (body?.relationship_id) {
      r = this.get("SELECT * FROM relationships WHERE id = ?", body.relationship_id);
      assert(r && (ownerId === r.requester_owner || ownerId === r.target_owner), 404, "relationship_not_found");
    } else {
      assert(body?.bot_id, 400, "invalid_request", "bot_id or relationship_id required");
      const other = this.bot(body.bot_id);
      const mine = body.my_bot_id ? this.ownBot(ownerId, body.my_bot_id) : this.get("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at LIMIT 1", ownerId);
      assert(mine, 400, "invalid_request", "you have no bot");
      // A pair can hold several rows (the friendship and one room per shared room, newest first). Blocking a
      // Bot must end every door between the two, not whichever row happens to be newest: a newer room row left
      // the friendship active after "Block". The blocked friendship still makes requestRelationship refuse.
      const rows = this.pairRelationships(mine.id, other.id);
      if (!rows.length) {
        const id = newId("rel");
        this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, requested_caps, offered_caps, created_at, updated_at) VALUES (?,?,?,?,?,'none','[]','[]',?,?)`,
          id, mine.id, other.id, ownerId, other.owner_id, nowIso(), nowIso());
        rows.push(this.get("SELECT * FROM relationships WHERE id = ?", id));
      }
      for (const row of rows) if (row.status !== "blocked") this.endRelationship(ownerId, row, "blocked");
      return { relationship_id: rows[0].id, status: "blocked" };
    }
    // The Block button (`public/ui.js`, `scripts/botctl.ts`) sends the friendship's `relationship_id`, and the
    // room row written when the pair shared a face room is a door between the same two Bots. Ending only the row
    // the caller named left that room open (P23), so both doors now end the whole pair.
    for (const row of this.pairRelationships(r.requester_bot, r.target_bot)) {
      if (row.status !== "blocked") this.endRelationship(ownerId, row, "blocked");
    }
    return { relationship_id: r.id, status: "blocked" };
  }

  listRelationships(p: Principal) {
    this.expireStale();
    const botId = p.kind === "bot" ? p.botId : null;
    const rows = botId
      ? this.all("SELECT * FROM relationships WHERE (requester_bot = ? OR target_bot = ?) AND status != 'room' ORDER BY created_at DESC", botId, botId)
      : this.all("SELECT * FROM relationships WHERE (requester_owner = ? OR target_owner = ?) AND status != 'room' ORDER BY created_at DESC", p.ownerId, p.ownerId);
    return rows.map((r) => {
      const meIsRequester = botId ? r.requester_bot === botId : r.requester_owner === p.ownerId;
      const myBot = meIsRequester ? r.requester_bot : r.target_bot;
      const peerBot = meIsRequester ? r.target_bot : r.requester_bot;
      const grants = this.grantsFor(r.id);
      const fmt = (g: any) => ({ grant_id: g.id, capability: g.capability, scope: g.scope, expires_at: g.expires_at, reply_only: !!g.reply_only });
      return {
        relationship_id: r.id, status: r.status, direction: meIsRequester ? "outgoing" : "incoming", side: meIsRequester ? "joiner" : "inviter", my_bot_id: myBot,
        peer: this.publicBot(this.bot(peerBot), r.status === "active"), message: r.message, requested_capabilities: J(r.requested_caps, []), offered_capabilities: J(r.offered_caps, []),
        created_at: r.created_at, expires_at: r.expires_at, blocked_by_me: r.blocked_by === p.ownerId,
        settings: this.settingsFor(r.id, p.ownerId),
        capabilities: { me_on_peer: grants.filter((g) => g.grantee_bot === myBot).map(fmt), peer_on_me: grants.filter((g) => g.grantee_bot === peerBot).map(fmt) },
      };
    });
  }

  // ================================================================ relationship settings & invites
  settingsFor(relId: string, ownerId: string) {
    const row = this.get("SELECT auto_approve_chat FROM relationship_settings WHERE relationship_id = ? AND owner_id = ?", relId, ownerId);
    return { auto_approve_chat: !!row?.auto_approve_chat };
  }

  /** Per-relationship owner settings. auto_approve_chat: clean low-risk chat messages skip manual approval (DLP flags still force it). */
  updateRelationshipSettings(p: Principal, relId: string, body: { auto_approve_chat?: boolean }) {
    const ownerId = this.requireOwner(p);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    assert(r && (r.requester_owner === ownerId || r.target_owner === ownerId), 404, "relationship_not_found");
    assert(typeof body?.auto_approve_chat === "boolean", 400, "invalid_request", "auto_approve_chat (boolean) required");
    this.run(`INSERT INTO relationship_settings (relationship_id, owner_id, auto_approve_chat, updated_at) VALUES (?,?,?,?)
      ON CONFLICT(relationship_id, owner_id) DO UPDATE SET auto_approve_chat = excluded.auto_approve_chat, updated_at = excluded.updated_at`, relId, ownerId, body.auto_approve_chat ? 1 : 0, nowIso());
    this.audit.append(`owner:${ownerId}`, "relationship.settings_updated", relId, [r.requester_owner, r.target_owner], { auto_approve_chat: body.auto_approve_chat });
    return { relationship_id: relId, settings: this.settingsFor(relId, ownerId) };
  }

  private inviteUrl(code: string) { return `${this.publicBaseUrl.replace(/\/$/, "")}/i/${code}`; }
  private inviteView(i: any) {
    return { invite_id: i.id, code: i.code, url: this.inviteUrl(i.code), bot: this.publicBot(this.bot(i.bot_id)), scope: i.scope ?? null, status: this.inviteStatus(i), offered_capabilities: J(i.offered_caps, []), requested_capabilities: J(i.requested_caps, []), message: i.message, auto_accept: !!i.auto_accept, uses: i.uses, max_uses: i.max_uses, expires_at: i.expires_at, created_at: i.created_at };
  }
  private inviteStatus(i: any) {
    // Stored terminal states win over the clock: a revoked or rejected invite never flips back to expired.
    if (i.status !== "active" && i.status !== "pending_owner") return i.status;
    // Both live states carry their own clock. A pending_owner invite whose approval is gone (or whose own window ran
    // out) must read expired instead of "Awaiting your approval" forever.
    if (Date.parse(i.expires_at) < Date.now()) return "expired";
    if (i.uses >= i.max_uses) return "used";
    return i.status;
  }

  /** The one Bot an owner names as id and/or handle, resolved inside that owner's account with the platform's
   *  usual handle semantics (`resolveOwnBot`). Naming a Bot that does not resolve is a 404 instead of a silent
   *  fallback, and two names that resolve to different Bots are a 400 — `bot_id` never wins silently. */
  private namedOwnBot(ownerId: string, idRef: unknown, handleRef: unknown): any | undefined {
    const id = idRef === undefined || idRef === null ? "" : String(idRef).trim();
    const handle = handleRef === undefined || handleRef === null ? "" : String(handleRef).trim();
    const byId = id ? this.resolveOwnBot(ownerId, id) : undefined;
    const byHandle = handle ? this.resolveOwnBot(ownerId, handle) : undefined;
    if (byId && byHandle && byId.id !== byHandle.id) throw new ApiError(400, "invalid_request", "bot_id and bot_handle name different Bots");
    return byId ?? byHandle;
  }

  /** The Bot an unnamed invite shares or joins with. Compatibility order (owner decision 2026-10-29): the oldest
   *  active member Bot, then any other active non-home Bot, then the active FlyBot home — a home-only account keeps
   *  minting. A home Bot is still only ever shared when it is named. No active Bot at all is a 400. */
  private inviteBotFor(ownerId: string): any {
    const active = this.all("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' ORDER BY created_at, id", ownerId);
    const bot = active.find((b: any) => b.integration_type === "flybot-member")
      ?? active.find((b: any) => b.integration_type !== "flybot-home")
      ?? active.find((b: any) => b.integration_type === "flybot-home");
    assert(bot, 400, "invalid_request", "you have no active member Bot: name one explicitly");
    return bot;
  }

  /** A frozen or revoked Bot is handed out by no invite: the kill switch also closes links that name it, and the
   *  link is checked again when it is joined. A named Bot that exists but is down is a 403, not a 404.
   *  The same check guards the last write of an auto-accept invite, so a stop that happened while the card
   *  waited cannot be undone by approving it. */
  private assertInvitable(bot: any) {
    assert(bot.status === "active", 403, bot.status === "frozen" ? "bot_frozen" : "bot_revoked",
      bot.status === "frozen" ? "this bot is frozen (emergency stop)" : "this bot identity was revoked");
  }

  /** Create an invite link. Owner-created invites are active at once (creating it is the owner's consent);
   *  bot-created invites (signed invite.create) need the owner's approval first. */
  createInvite(p: Principal, body: any) {
    let bot: any, payload: any, viaBot = false;
    if (p.kind === "bot") { const env = this.verifyEnvelope(p, body, "invite.create"); payload = env.payload ?? {}; bot = this.bot(p.botId); viaBot = true; }
    else {
      payload = ownerWriteBody(body);
      bot = this.namedOwnBot(p.ownerId, payload.bot_id, payload.bot_handle) ?? this.inviteBotFor(p.ownerId);
      this.assertInvitable(bot);
    }
    // #90: a revoked identity cannot hand itself out again — an invite for it would share a Bot that no longer answers.
    assert(bot.status === "active", 403, "bot_revoked", "this bot identity was revoked");
    const offered = this.validCaps(payload.offered_capabilities ?? DEFAULT_CAPABILITIES);
    const requested = this.validCaps(payload.requested_capabilities ?? DEFAULT_CAPABILITIES);
    const maxUses = Math.max(1, Math.min(Number(payload.max_uses) || 1, 50));
    const hours = Math.max(1, Math.min(Number(payload.expires_in_hours) || 72, 24 * 30));
    const id = newId("inv");
    const code = randomBytes(9).toString("base64url").replace(/[-_]/g, "x");
    const status = viaBot ? "pending_owner" : "active";
    // Per-bot only: an invite for a home or Chief grants that one bot, never its members.
    const scope = "bot";
    this.run("INSERT INTO invites (id, code, bot_id, owner_id, created_by, offered_caps, requested_caps, message, auto_accept, max_uses, status, expires_at, created_at, scope) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      id, code, bot.id, bot.owner_id, viaBot ? `bot:${bot.id}` : `owner:${bot.owner_id}`, JSON.stringify(offered), JSON.stringify(requested), payload.message ?? null, payload.auto_accept === false ? 0 : 1, maxUses, status,
      new Date(Date.now() + hours * 3600e3).toISOString(), nowIso(), scope);
    let approval_id: string | undefined;
    if (viaBot) approval_id = this.createApproval(bot.owner_id, "invite", id, bot.id, null, `Your bot wants to create a friend invite link (grants to the joiner: ${offered.join(", ")})`, ["invite.requires_owner"], [], LIMITS.approvalTtlMs);
    this.audit.append(viaBot ? `bot:${bot.id}` : `owner:${bot.owner_id}`, "invite.created", id, [bot.owner_id], { offered, requested, max_uses: maxUses, status });
    return { ...this.inviteView(this.get("SELECT * FROM invites WHERE id = ?", id)), approval_id };
  }

  listInvites(p: Principal) {
    const rows = p.kind === "owner" ? this.all("SELECT * FROM invites WHERE owner_id = ? ORDER BY created_at DESC", p.ownerId) : this.all("SELECT * FROM invites WHERE bot_id = ? ORDER BY created_at DESC", p.botId);
    return rows.map((i) => this.inviteView(i));
  }

  revokeInvite(p: Principal, id: string) {
    const ownerId = this.requireOwner(p);
    const i = this.get("SELECT * FROM invites WHERE id = ? OR code = ?", id, id);
    assert(i && i.owner_id === ownerId, 404, "invite_not_found");
    this.run("UPDATE invites SET status = 'revoked' WHERE id = ?", i.id);
    this.audit.append(`owner:${ownerId}`, "invite.revoked", i.id, [ownerId], {});
    return { invite_id: i.id, status: "revoked" };
  }

  /** Public preview of an invite (no secrets). */
  inviteInfo(code: string) {
    const i = this.get("SELECT * FROM invites WHERE code = ?", code);
    assert(i, 404, "invite_not_found");
    const v = this.inviteView(i);
    return { code: v.code, url: v.url, status: v.status, inviter: v.bot, offered_capabilities: v.offered_capabilities, requested_capabilities: v.requested_capabilities, message: v.message, expires_at: v.expires_at, server: this.publicBaseUrl };
  }

  /** Join via invite: creates the friend request from the joiner to the inviter's bot. */
  joinInvite(p: Principal, code: string, body: any) {
    let payload: any, joiner: any, viaBot = false;
    if (p.kind === "bot") { const env = this.verifyEnvelope(p, body, "invite.join"); payload = env.payload ?? {}; joiner = this.bot(p.botId); viaBot = true; }
    else {
      payload = ownerWriteBody(body);
      joiner = this.namedOwnBot(p.ownerId, payload.from_bot_id, payload.bot_handle) ?? this.inviteBotFor(p.ownerId);
      this.assertInvitable(joiner);
    }
    // Give back the use of any earlier pending join before reading this invite's status: the expired
    // relationship may have been the one use this 1-use link had.
    this.expireStale();
    code = payload.code ?? code;
    const i = this.get("SELECT * FROM invites WHERE code = ?", code);
    assert(i, 404, "invite_not_found");
    const st = this.inviteStatus(i);
    assert(st === "active", 410, "invite_unavailable", `invite is ${st}`, { invite_status: st });
    const inviter = this.bot(i.bot_id);
    // A link minted before an emergency stop must not outlive it: both ends are checked at join time, before
    // anything is written. A frozen or revoked Bot at either end is a 403 and spends no use.
    this.assertInvitable(joiner);
    this.assertInvitable(inviter);
    assert(inviter.owner_id !== joiner.owner_id, 400, "invalid_request", "cannot join your own invite");
    const existing = this.pairRelationships(joiner.id, inviter.id);
    assert(!existing.some((r) => r.status === "blocked"), 403, "blocked", "relationship is blocked");
    const live = existing.find((r) => r.status === "active");
    // Re-share: already friends, but the inviter's access to this Bot was removed (declined by the joiner or revoked by the
    // inviter). A fresh owner-joined invite from the inviter (auto_accept) restores it instead of failing with relationship_exists.
    if (live && !viaBot && i.auto_accept && !this.hasLiveGrant(inviter.owner_id, joiner.id, live.id)) return this.regrantViaInvite(i, live, inviter, joiner, payload);
    const blocking = existing.find((r) => ["active", "pending_target", "pending_requester_owner"].includes(r.status));
    assert(!blocking, 409, "relationship_exists", "you are already connected to this Bot (or a request is pending)", { relationship_id: blocking?.id });
    const offered = this.validCaps(payload.offered_capabilities ?? J(i.requested_caps, DEFAULT_CAPABILITIES));
    const id = newId("rel");
    const status = viaBot ? "pending_requester_owner" : "pending_target";
    // Per-bot only. Legacy invite.scope / home endpoints are recorded as 'bot' and never cover members.
    const targetScope = "bot";
    const requesterScope = "bot";
    // #30: the relationship, the invite use and (for an auto-accept invite) every grant are written in one
    // transaction, and only then announced, so a join is never confirmed before its grants are durable.
    const autoAccept = this.db.transaction(() => {
      this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, message, requested_caps, offered_caps, created_at, updated_at, expires_at, requester_scope, target_scope)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, joiner.id, inviter.id, joiner.owner_id, inviter.owner_id, status, payload.message ?? `Joined via invite link`, i.offered_caps, JSON.stringify(offered), nowIso(), nowIso(), new Date(Date.now() + LIMITS.relationshipRequestTtlMs).toISOString(), requesterScope, targetScope);
      this.run("INSERT INTO relationship_invites (relationship_id, invite_id) VALUES (?,?)", id, i.id);
      this.run("UPDATE invites SET uses = uses + 1 WHERE id = ?", i.id);
      return viaBot ? null : this.autoAcceptSpecs(id);
    })();
    this.audit.append(viaBot ? `bot:${joiner.id}` : `owner:${joiner.owner_id}`, "invite.joined", i.id, [joiner.owner_id, inviter.owner_id], { relationship_id: id, offered });
    let approval_id: string | undefined;
    if (viaBot) approval_id = this.createApproval(joiner.owner_id, "relationship_request", id, joiner.id, null, `Your bot wants to befriend @${inviter.handle} via invite (you grant: ${offered.join(", ")})`, ["relationship.requires_owner", "invite"], [], LIMITS.relationshipRequestTtlMs);
    else if (autoAccept) this.announceActivation(this.get("SELECT * FROM relationships WHERE id = ?", id), autoAccept.specs, autoAccept.actor);
    else this.notifyTarget(id);
    const r = this.get("SELECT status FROM relationships WHERE id = ?", id);
    const active = r.status === "active";
    return { relationship_id: id, status: r.status, approval_id, inviter: this.publicBot(inviter), joined_as: { bot_id: joiner.id, handle: "@" + joiner.handle }, awaiting: active ? null : r.status === "pending_requester_owner" ? "your_owner_approval" : "inviter_owner_consent", ...(active ? { grants_ready: true, grants: this.grantSummary(id) } : {}) };
  }

  /** Does `grantorOwner` still share its Bot with `granteeBot` on this relationship (an unexpired, active relationship-level
   *  grant, and not reply-only access)? A reply-only join grant (#23) is not a share: a fresh invite for that Bot shares it. */
  private hasLiveGrant(grantorOwner: string, granteeBot: string, relId: string): boolean {
    const live = this.all("SELECT * FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND room_id IS NULL", relId, grantorOwner, granteeBot)
      .some((g: any) => !g.expires_at || Date.parse(g.expires_at) >= Date.now());
    return live && !this.replyOnlyAccess(relId, grantorOwner, granteeBot);
  }

  private regrantViaInvite(i: any, rel: any, inviter: any, joiner: any, payload: any) {
    // The regrant writes the same grants a first join would, so the same kill-switch rule applies to both ends.
    this.assertInvitable(joiner);
    this.assertInvitable(inviter);
    const offered = this.validCaps(payload.offered_capabilities ?? J(i.requested_caps, DEFAULT_CAPABILITIES));
    const actor = `owner:${i.owner_id}(invite:${i.id})`;
    this.db.transaction(() => {
      this.run("UPDATE invites SET uses = uses + 1 WHERE id = ?", i.id);
      this.run("INSERT OR IGNORE INTO relationship_invites (relationship_id, invite_id) VALUES (?,?)", rel.id, i.id);
      const fbScope = { window_days: 14, hours: "09:00-18:00" };
      // inviter owner -> joiner bot: the same bundle a fresh friendship would give
      for (const c of new Set<string>([...DEFAULT_CAPABILITIES, ...J(i.offered_caps, [])])) this.insertGrant(rel.id, inviter.owner_id, joiner.id, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, actor);
      // joiner owner -> inviter bot: add only what is missing; never replaces grants the joiner already holds.
      // What a join adds on the joiner's side is reply-only (#23), as on a first join.
      for (const c of new Set<string>([...DEFAULT_CAPABILITIES, ...offered])) {
        if (!this.findGrant(joiner.owner_id, inviter.id, c, joiner.id)) this.insertGrant(rel.id, joiner.owner_id, inviter.id, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, `owner:${joiner.owner_id}`, { replyOnly: true });
      }
    })();
    this.audit.append(`owner:${joiner.owner_id}`, "invite.joined", i.id, [joiner.owner_id, inviter.owner_id], { relationship_id: rel.id, regrant: true, offered });
    for (const b of [inviter.id, joiner.id]) this.emit(b, "grant.changed", { relationship_id: rel.id, status: "granted", granted_bot: inviter.id, grantee_bot: joiner.id });
    return { relationship_id: rel.id, status: "active", approval_id: undefined, inviter: this.publicBot(inviter), joined_as: { bot_id: joiner.id, handle: "@" + joiner.handle }, awaiting: null, regranted: true };
  }

  /** A join that never became a friendship (requester owner rejected / request expired) must give its
   *  invite slot back; otherwise a 1-use invite reads "used" while no relationship exists. */
  private releaseInviteUse(relId: string) {
    const link = this.get("SELECT invite_id FROM relationship_invites WHERE relationship_id = ?", relId);
    if (link) this.run("UPDATE invites SET uses = MAX(uses - 1, 0) WHERE id = ?", link.invite_id);
  }

  /** If the relationship came from an auto-accept invite, the inviter owner already consented: activate it. */
  private maybeAutoAcceptInvite(relId: string): boolean {
    const accepted = this.autoAcceptSpecs(relId);
    if (!accepted) return false;
    this.announceActivation(this.get("SELECT * FROM relationships WHERE id = ?", relId), accepted.specs, accepted.actor);
    return true;
  }

  /** Writes (grants first, #30) the activation of an auto-accept invite's relationship without announcing it; the
   *  caller announces once its own transaction has committed. Null when the invite does not auto-accept. */
  private autoAcceptSpecs(relId: string): { specs: { capability: string }[]; actor: string } | null {
    const link = this.get("SELECT i.* FROM relationship_invites ri JOIN invites i ON i.id = ri.invite_id WHERE ri.relationship_id = ?", relId);
    if (!link || !link.auto_accept || link.status === "revoked" || link.status === "pending_owner") return null;
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    if (r.status !== "pending_target") return null;
    // The one place an auto-accept invite writes grants: both ends are checked here, before writeActivation, so a
    // stop that happened while the card waited cannot be undone by approving it. A refusal leaves the card pending.
    this.assertInvitable(this.bot(r.requester_bot));
    this.assertInvitable(this.bot(r.target_bot));
    const specs = J(link.offered_caps, []).map((c: string) => ({ capability: c }));
    const actor = `owner:${link.owner_id}(invite:${link.id})`;
    this.writeActivation(r, specs, actor);
    return { specs, actor };
  }

  /** Per-bot friend overview for the /friends page. Owners may view any of their own bots; a bot only itself. */
  friendsOverview(p: Principal, botId?: string) {
    let bots: any[];
    if (p.kind === "bot") bots = [this.bot(p.botId)];
    else bots = this.all("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at", p.ownerId);
    const selected = botId ? bots.find((b) => b.id === botId) ?? pickByHandle(bots, botId) : bots[0];
    if (botId && !selected) throw new ApiError(403, "forbidden", "not your bot");
    const list = bots.map((b) => ({ bot_id: b.id, handle: "@" + b.handle, display_name: peerBotName(b), ...lookOf(b), status: b.status }));
    if (!selected) return { bots: list, bot: null, friends: [], pending_incoming: [], pending_outgoing: [], others: [] };
    this.expireStale();
    const rows = this.all("SELECT * FROM relationships WHERE (requester_bot = ? OR target_bot = ?) AND status != 'room' ORDER BY updated_at DESC", selected.id, selected.id);
    const items = rows.map((r) => {
      const outgoing = r.requester_bot === selected.id;
      const peerId = outgoing ? r.target_bot : r.requester_bot;
      // The overview is the one read that keeps a lapsed grant: the owner must see it ended and be able to renew it
      // from the card. `/v1/relationships` (and every reach check) keeps the default read, which drops it.
      const grants = this.grantsFor(r.id, { includeExpired: true });
      const convs = this.all("SELECT id, status, outcome, intent, turn_count, max_turns, created_at, updated_at FROM conversations WHERE relationship_id = ? ORDER BY updated_at DESC", r.id);
      const lastMsg = this.get("SELECT MAX(COALESCE(delivered_at, created_at)) t FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE relationship_id = ?)", r.id)?.t ?? null;
      const last = convs[0];
      const times = [r.updated_at, last?.updated_at, lastMsg].filter(Boolean).sort();
      return {
        relationship_id: r.id, status: r.status, direction: outgoing ? "outgoing" : "incoming", side: outgoing ? "joiner" : "inviter",
        peer: this.publicBot(this.bot(peerId), r.status === "active"),
        connected_at: r.status === "active" || r.status === "revoked" || r.status === "blocked" ? r.updated_at : null,
        requested_at: r.created_at, expires_at: r.expires_at, message: r.message, requested_capabilities: J(r.requested_caps, []), offered_capabilities: J(r.offered_caps, []), settings: this.settingsFor(r.id, selected.owner_id), blocked_by_me: !!r.blocked_by && r.blocked_by === selected.owner_id,
        capabilities: {
          granted_to_peer: grants.filter((g) => g.grantee_bot === peerId).map((g) => ({ capability: g.capability, scope: g.scope, expires_at: g.expires_at, status: g.status })),
          granted_to_me: grants.filter((g) => g.grantee_bot === selected.id).map((g) => ({ capability: g.capability, scope: g.scope, expires_at: g.expires_at, status: g.status })),
        },
        conversation_count: convs.length,
        last_conversation: last ? { conversation_id: last.id, status: last.status, outcome: last.outcome, intent: J(last.intent).type, summary: J(last.intent).summary, turn: { count: last.turn_count, max: null }, updated_at: last.updated_at } : null,
        last_activity_at: times[times.length - 1] ?? null,
      };
    });
    return {
      bots: list, bot: { bot_id: selected.id, handle: "@" + selected.handle, display_name: peerBotName(selected), ...lookOf(selected), status: selected.status, owner_display_name: peerOwnerName(this.owner(selected.owner_id)) },
      friends: items.filter((i) => i.status === "active"),
      pending_incoming: items.filter((i) => i.direction === "incoming" && ["pending_target", "pending_requester_owner"].includes(i.status)),
      pending_outgoing: items.filter((i) => i.direction === "outgoing" && ["pending_target", "pending_requester_owner"].includes(i.status)),
      others: items.filter((i) => ["blocked", "revoked", "declined", "expired", "cancelled"].includes(i.status) && !(i.status === "none")),
    };
  }

  listFriends(p: Principal) {
    return this.listRelationships(p).filter((r) => r.status === "active");
  }

  profile(p: Principal, botId: string) {
    const target = this.bot(botId);
    if (p.kind === "bot" && p.botId !== botId) {
      this.activeRelationship(p.botId, botId);
      assert(this.findGrant(target.owner_id, p.botId, "profile.read", target.id), 403, "capability_not_granted", "profile.read not granted", { suggestion: "request_grant" });
    }
    if (p.kind === "owner" && target.owner_id !== p.ownerId) {
      const mine = this.all("SELECT id FROM bots WHERE owner_id = ? AND status = 'active'", p.ownerId);
      assert(mine.some((m: any) => this.findActiveRelationship(m.id, target.id) && this.findGrant(target.owner_id, m.id, "profile.read", target.id)), 404, "bot_not_found", "no such bot");
    }
    const o = this.owner(target.owner_id);
    return { ...this.publicBot(target, true), owner_timezone: o.timezone };
  }

  // ================================================================ approvals
  private createApproval(ownerId: string, kind: string, subjectId: string, botId: string | null, convId: string | null, summary: string, reasons: string[], riskFlags: unknown[], ttlMs: number, extra?: unknown, holdReason: HoldReason | null = null) {
    const id = newId("apr");
    this.run("INSERT INTO approvals (id, owner_id, kind, subject_id, bot_id, conversation_id, summary, reasons, risk_flags, hold_reason, created_at, expires_at, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
      id, ownerId, kind, subjectId, botId, convId, summary, JSON.stringify(reasons), JSON.stringify(riskFlags), holdReason, nowIso(), new Date(Date.now() + ttlMs).toISOString(), extra ? JSON.stringify(extra) : null);
    // #139 ② C: a card that waits only in the database is invisible until someone opens a page. Tell the owner
    // through the Bot they designated, at the one place every card is created.
    this.notifyOwnerOfApproval(id);
    return id;
  }

  /**
   * #139 ② C: announce one waiting card to the owner's designated Bot. Delivery is that Bot's existing webhook,
   * so the owner needs no page open and the platform needs no mail or push service. The event carries no text: the
   * card id, its kind, how many cards wait and when this one expires. One ledger row per card makes a second
   * announcement (a retried or replayed path) a no-op.
   */
  notifyOwnerOfApproval(approvalId: string): boolean {
    const a = this.get("SELECT a.id, a.owner_id, a.kind, a.expires_at, o.notify_bot_id FROM approvals a JOIN owners o ON o.id = a.owner_id WHERE a.id = ?", approvalId);
    if (!a?.notify_bot_id) return false;
    // Defense in depth: a setting written before the revocation checks above can still name a revoked identity.
    // Its queue is refused (#177 ③), so an announcement there would be write-only. A frozen outlet is fine: the
    // queue is read again after resume.
    const outlet = this.get("SELECT status FROM bots WHERE id = ?", a.notify_bot_id);
    if (!outlet || outlet.status === "revoked") return false;
    const ins = this.run("INSERT OR IGNORE INTO approval_notifications (approval_id, owner_id, bot_id, created_at) VALUES (?,?,?,?)", a.id, a.owner_id, a.notify_bot_id, nowIso());
    if (!ins.changes) return false;
    const pending_count = this.get("SELECT COUNT(*) n FROM approvals WHERE owner_id = ? AND status = 'pending'", a.owner_id).n;
    this.emit(a.notify_bot_id, "approval.created", { approval_id: a.id, kind: a.kind, pending_count, expires_at: a.expires_at });
    return true;
  }

  private cancelPendingFor(where: string, args: unknown[], reason: string, opts: { keep?: { where: string; args: unknown[] }; notify?: boolean } = {}) {
    // `keep` is one extra condition on the rows to cancel: a row it excludes (the caller spells that as a NOT) keeps
    // both its pending status and the side effect on its subject row, so the card stays decidable.
    const keepSql = opts.keep ? ` AND ${opts.keep.where}` : "";
    const keepArgs = opts.keep ? opts.keep.args : [];
    for (const a of this.all(`SELECT * FROM approvals WHERE status = 'pending' AND ${where}${keepSql}`, ...args, ...keepArgs)) {
      this.run("UPDATE approvals SET status = 'cancelled', decision = ?, decided_at = ? WHERE id = ?", reason, nowIso(), a.id);
      if (a.kind === "outbound_message") this.run("UPDATE messages SET status = 'cancelled' WHERE id = ?", a.subject_id);
      if (a.kind === "action") this.run("UPDATE actions SET status = 'cancelled' WHERE id = ?", a.subject_id);
      if (a.kind === "face_room_message") this.run("UPDATE face_room_drafts SET status = 'cancelled' WHERE id = ?", a.subject_id);
      // A cancelled card is never silent: the Bot that owned it hears the outcome and the reason it can show.
      if (opts.notify && a.bot_id) this.emit(a.bot_id, "approval.decided", {
        approval_id: a.id, kind: a.kind, decision: "cancelled", reason,
        ...(a.kind === "outbound_message" || a.kind === "face_room_message" ? { message_id: a.subject_id } : {}),
        ...(a.kind === "action" ? { action_id: a.subject_id } : {}),
        ...(a.kind === "invite" ? { invite_id: a.subject_id } : {}),
        // These two kinds carry the relationship in subject_id; without it the Bot cannot tell which relationship
        // the cancelled card belonged to (the expiry path in `expireApproval` already sends it).
        ...(a.kind === "relationship_request" || a.kind === "grant_request" ? { relationship_id: a.subject_id } : {}),
      });
    }
  }

  private expireApproval(a: any) {
    this.run("UPDATE approvals SET status = 'expired', decided_at = ? WHERE id = ?", nowIso(), a.id);
    if (a.kind === "outbound_message") {
      this.run("UPDATE messages SET status = 'expired' WHERE id = ?", a.subject_id);
      const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
      if (m) {
        this.emit(m.recipient_bot, "system.notice", { conversation_id: m.conversation_id, trust: "platform", text: "The other side has not responded (draft approval timed out)" });
        this.emit(m.sender_bot, "approval.decided", { approval_id: a.id, kind: a.kind, message_id: m.id, decision: "expired" });
      }
    }
    if (a.kind === "action") {
      this.run("UPDATE actions SET status = 'expired' WHERE id = ?", a.subject_id);
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, action_id: a.subject_id, decision: "expired" });
    }
    if (a.kind === "face_room_message") {
      this.run("UPDATE face_room_drafts SET status = 'expired' WHERE id = ?", a.subject_id);
      const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", a.subject_id);
      if (d) this.emit(d.sender_bot, "approval.decided", { approval_id: a.id, kind: a.kind, message_id: d.id, room_id: d.room_id, decision: "expired" });
    }
    if (a.kind === "grant_request") {
      // The request exists only as this approval: the grant row is created when the owner approves, so there is
      // nothing else to sweep. Without this branch the card simply left the owner's pending list and the Bot that
      // asked for the capability was never told; the peer owner is not the addressee (same as the invite, #104).
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, relationship_id: a.subject_id, decision: "expired" });
    }
    if (a.kind === "invite") {
      // A Bot-created invite waits at status pending_owner for this approval. Expiring only the approval row left
      // the link stuck: decide answered 409, the joining side read 410 pending_owner, and the Bot heard nothing.
      // Only a still-waiting invite is expired, so an invite approved earlier is never flipped by a later sweep.
      this.run("UPDATE invites SET status = 'expired' WHERE id = ? AND status = 'pending_owner'", a.subject_id);
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, invite_id: a.subject_id, decision: "expired" });
    }
    if (a.kind === "relationship_request") {
      // The relationship row is the business object: `expireStale` flips it before working the approvals, so this
      // branch must not touch any row — it only tells the Bot that asked. Without it the card left the owner's list
      // and the Bot sat in "waiting for my owner" with nothing to read (same shape as #104's invite, P19's grant
      // request). The peer Bot is not the addressee: the requester's owner owns this decision.
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, relationship_id: a.subject_id, decision: "expired" });
    }
    if (a.conversation_id) this.refreshConversationStatus(a.conversation_id);
    this.audit.append("platform", "approval.expired", a.id, [a.owner_id], { kind: a.kind, subject_id: a.subject_id });
  }

  listApprovals(p: Principal, status = "pending") {
    const ownerId = this.requireOwner(p);
    this.expireStale();
    const rows = status === "all" ? this.all("SELECT * FROM approvals WHERE owner_id = ? ORDER BY created_at DESC", ownerId) : this.all("SELECT * FROM approvals WHERE owner_id = ? AND status = ? ORDER BY created_at ASC", ownerId, status);
    return rows.map((a) => this.approvalCard(a));
  }

  private approvalCard(a: any) {
    const card: any = { approval_id: a.id, kind: a.kind, status: a.status, decision: a.decision, summary: a.summary, reasons: J(a.reasons, []), risk_flags: J(a.risk_flags, []), ...(a.hold_reason ? { hold_reason: a.hold_reason } : {}), bot_id: a.bot_id, conversation_id: a.conversation_id, created_at: a.created_at, decided_at: a.decided_at, sender: a.bot_id ? this.publicBot(this.bot(a.bot_id)) : undefined, expires_at: a.expires_at };
    if (a.kind === "outbound_message") {
      const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
      const pl = J(m.payload);
      card.message = { message_id: m.id, to: this.publicBot(this.bot(m.recipient_bot)), payload: pl, ...(mentionsOf(m.mentions).length ? { mentions: mentionsOf(m.mentions) } : {}), status: m.status, ...(pl.attachments ? { attachments: pl.attachments.map((r: AttachmentRef) => ({ ...r, size_label: humanSize(r.size) })) } : {}) };
    } else if (a.kind === "action") {
      const x = this.get("SELECT * FROM actions WHERE id = ?", a.subject_id);
      card.action = { action_id: x.id, action_type: x.action_type, params: J(x.params), justification: x.justification, status: x.status };
    } else if (a.kind === "relationship_request") {
      const r = this.get("SELECT * FROM relationships WHERE id = ?", a.subject_id);
      card.relationship = { relationship_id: r.id, target: this.publicBot(this.bot(r.target_bot)), message: r.message, requested_capabilities: J(r.requested_caps, []), offered_capabilities: J(r.offered_caps, []) };
    } else if (a.kind === "invite") {
      card.invite = this.inviteView(this.get("SELECT * FROM invites WHERE id = ?", a.subject_id));
    } else if (a.kind === "grant_request") {
      card.grant_request = { relationship_id: a.subject_id, ...J(a.note, {}), from: this.publicBot(this.bot(a.bot_id)) };
    } else if (a.kind === "face_room_message") {
      const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", a.subject_id);
      if (d) {
        // What the owner is approving includes whom the line is addressed to; only handles still in the room (as at delivery).
        const listed = d.status === "pending_approval" ? this.roomMentions(d.room_id, mentionsOf(d.mentions)) : mentionsOf(d.mentions);
        card.face_room = { room_id: d.room_id, message_id: d.id, payload: J(d.payload), ...(listed.length ? { mentions: listed } : {}), status: d.status };
      }
    }
    if (a.conversation_id) {
      const c = this.get("SELECT * FROM conversations WHERE id = ?", a.conversation_id);
      if (c) card.conversation = { conversation_id: c.id, intent: J(c.intent), status: c.status, turn: { count: c.turn_count, max: null } };
    }
    return card;
  }

  decideApproval(p: Principal, aprId: string, body: { decision: "approved" | "approved_with_edits" | "rejected"; edited_payload?: any; edited_params?: any; note_to_bot?: string; idempotency_key?: string }, actorOverride?: string) {
    const { idempotency_key: key, ...rest } = body as any;
    // The one-time confirm code is stripped from the request the key is compared against, never from what is
    // decided: a real retry carries a fresh code, so counting it would answer every retry with
    // idempotency_conflict instead of the first outcome. The code itself still travels on `rest`.
    const { confirm_code: _code, ...hashed } = rest;
    return this.idempotent(p, "decide_approval", key, { approval_id: aprId, ...hashed }, () => this.decideApprovalOnce(p, aprId, rest, actorOverride));
  }

  private decideApprovalOnce(p: Principal, aprId: string, body: { decision: "approved" | "approved_with_edits" | "rejected"; edited_payload?: any; edited_params?: any; note_to_bot?: string }, actorOverride?: string) {
    const ownerId = this.requireOwner(p);
    this.expireStale();
    const a = this.get("SELECT * FROM approvals WHERE id = ?", aprId);
    assert(a, 404, "approval_not_found");
    assert(a.owner_id === ownerId, 403, "forbidden", "not your approval");
    // #84 follow-up: a revoked member's card stays as a record, never as a decision. Say why, so the owner
    // is not left guessing at "approval is cancelled"; every other non-pending row keeps the plain state.
    const revokedReason = "the sending Bot was revoked; this draft can no longer be approved";
    if (a.status !== "pending") {
      throw new ApiError(409, "invalid_state", a.status === "cancelled" && a.decision === "member_revoked" ? revokedReason : `approval is ${a.status}`);
    }
    // Last line of defence for a stale row an older build left pending after its sender was revoked. Cancel it
    // now (same record the revoke leaves behind) instead of delivering as a Bot that no longer exists.
    if (a.bot_id && ["outbound_message", "face_room_message", "action"].includes(a.kind) && this.bot(a.bot_id).status !== "active") {
      this.cancelPendingFor("id = ?", [a.id], "member_revoked");
      throw new ApiError(409, "invalid_state", revokedReason);
    }
    const decision = body?.decision;
    assert(["approved", "approved_with_edits", "rejected"].includes(decision), 400, "invalid_request", "decision must be approved|approved_with_edits|rejected");
    const approve = decision !== "rejected";
    let result: any = {};
    if (a.kind === "outbound_message") result = approve ? this.deliverMessage(a, body) : this.rejectMessage(a, body.note_to_bot);
    else if (a.kind === "face_room_message") result = approve ? this.deliverFaceRoomMessage(a, body) : this.rejectFaceRoomMessage(a, body.note_to_bot);
    else if (a.kind === "action") result = approve ? this.executeAction(a, body) : this.rejectAction(a, body.note_to_bot);
    else if (a.kind === "relationship_request") {
      const r = this.get("SELECT * FROM relationships WHERE id = ?", a.subject_id);
      this.run("UPDATE relationships SET status = ?, updated_at = ? WHERE id = ?", approve ? "pending_target" : "cancelled", nowIso(), r.id);
      if (approve && !this.maybeAutoAcceptInvite(r.id)) this.notifyTarget(r.id);
      if (!approve) this.releaseInviteUse(r.id);
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, relationship_id: r.id, decision, note_to_bot: body.note_to_bot ?? null });
      result = { relationship_id: r.id, status: this.get("SELECT status FROM relationships WHERE id = ?", r.id).status };
    } else if (a.kind === "invite") {
      this.run("UPDATE invites SET status = ? WHERE id = ?", approve ? "active" : "rejected", a.subject_id);
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, invite_id: a.subject_id, decision, url: approve ? this.inviteUrl(this.get("SELECT code FROM invites WHERE id = ?", a.subject_id).code) : null });
      result = { invite_id: a.subject_id, status: approve ? "active" : "rejected" };
    } else if (a.kind === "grant_request") {
      const req = J(a.note, {});
      if (approve) {
        // One write, like the owner route: the supersede cannot survive a throw from the insert. The edited scope
        // re-runs the same #211 guard before the transaction, so a bad edit leaves the card pending and writes nothing.
        const scope = body.edited_params?.scope ?? req.scope;
        this.assertScope(req.capability, scope);
        result.grant_id = this.db.transaction(() => this.insertGrant(a.subject_id, ownerId, req.grantee_bot, req.capability, scope, body.edited_params?.expires_in_days, `owner:${ownerId}`)).immediate();
      }
      this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: a.kind, capability: req.capability, decision, note_to_bot: body.note_to_bot ?? null });
    }
    this.run("UPDATE approvals SET status = ?, decision = ?, decided_at = ? WHERE id = ?", approve ? "approved" : "rejected", decision, nowIso(), a.id);
    const flags = J(a.risk_flags, []);
    this.audit.append(actorOverride ?? `owner:${ownerId}`, "approval.decided", a.id, [ownerId], { kind: a.kind, subject_id: a.subject_id, decision, risk_flags: flags, known_risk_approved: approve && flags.length > 0, note_to_bot: body.note_to_bot ?? null });
    if (a.conversation_id) this.refreshConversationStatus(a.conversation_id);
    return { approval_id: a.id, decision, ...result };
  }

  // ================================================================ conversations
  private conv(id: string) {
    const c = this.get("SELECT * FROM conversations WHERE id = ?", id);
    assert(c, 404, "conversation_not_found");
    return c;
  }

  private refreshConversationStatus(convId: string) {
    const c = this.conv(convId);
    if (!["open", "awaiting_approval"].includes(c.status)) return;
    const pending = this.get("SELECT COUNT(*) n FROM approvals WHERE conversation_id = ? AND status = 'pending'", convId).n;
    const s = pending ? "awaiting_approval" : "open";
    if (s !== c.status) this.run("UPDATE conversations SET status = ?, updated_at = ? WHERE id = ?", s, nowIso(), convId);
  }

  private memberConv(botId: string, convId: string) {
    const c = this.conv(convId);
    assert(c.initiator_bot === botId || c.peer_bot === botId, 403, "not_a_member");
    return { c, peer: c.initiator_bot === botId ? c.peer_bot : c.initiator_bot };
  }

  /** Close a conversation whose own clock ran out: the same write the assert used to do inline, without throwing.
   *  Callers that may still act on a closed conversation (an invite acceptance) read the closed state off the row. */
  private materializeExpiry(c: any) {
    if (c.expires_at && Date.parse(c.expires_at) < Date.now() && c.status !== "closed") {
      this.run("UPDATE conversations SET status = 'closed', outcome = 'expired', updated_at = ? WHERE id = ?", nowIso(), c.id);
      c.status = "closed";
      c.outcome = "expired";
    }
  }

  /** Refuse only a chat an owner stopped; a closed chat is not a pause, and a pre-removal paused_limit resumes on use. */
  private assertNotPaused(c: any) {
    if (c.status === "paused_limit") this.resumeConversation(c, "platform", { reason: "turn_limit_removed" });
    else assert(!["paused_loop", "paused_stop"].includes(c.status), 409, "conversation_paused", `conversation is ${c.status}`);
  }

  private assertConvActive(c: any) {
    this.materializeExpiry(c);
    assert(c.status !== "closed", 409, "conversation_closed", `conversation is closed (${c.outcome})`);
    this.assertNotPaused(c);
  }

  private policyDecision(actor: string, convId: string | null, owners: string[], action: string, decision: string, reasons: string[], extra: Record<string, unknown> = {}) {
    this.audit.append(`bot:${actor}`, "policy.decision", convId, owners, { action, decision, reasons, policy_version: POLICY_VERSION, ...extra });
  }

  createConversation(p: Principal, env: Envelope, roomId: string | null = null) {
    this.verifyEnvelope(p, env, "conversation.create");
    const { botId, ownerId } = this.requireBot(p);
    const pl: any = env.payload ?? {};
    assert((pl.type ?? "direct") === "direct", 400, "invalid_request", "MVP supports only direct (1:1) conversations");
    assert(pl.peer_bot_id, 400, "invalid_request", "peer_bot_id required");
    const peer = this.bot(pl.peer_bot_id);
    // #43: a conversation opened from a claimed room runs on that room's grants, not on a friendship.
    const roomRel = roomId ? this.roomReach(botId, peer.id, roomId) : null;
    const rel = roomRel ?? this.activeRelationship(botId, peer.id);
    // A stranger is still answered `no_relationship` above: the peer's status is not a probe. Past that, the room
    // path can reach a peer without a friendship, so the peer's own status is checked here too (activeRelationship
    // only filters a revoked identity). Nothing is written and no event is queued for a Bot the kill switch has
    // taken offline: the check sits before the INSERT and the emit(peer) that follows it.
    this.assertReachable(peer);
    const intentDef = INTENTS[pl.intent?.type];
    if (!intentDef) {
      this.policyDecision(botId, null, [ownerId], "conversation.create", "deny", ["intent.unsupported"]);
      throw new ApiError(403, "intent_scope_violation", "MVP intents: schedule_meeting, general_chat");
    }
    const chat = roomRel ? this.findRoomGrant(peer.owner_id, botId, "chat.public", peer.id, roomId!) : this.findGrant(peer.owner_id, botId, "chat.public", peer.id);
    if (!chat) {
      this.policyDecision(botId, null, [ownerId, peer.owner_id], "conversation.create", "deny", ["capability_not_granted:chat.public"]);
      throw new ApiError(403, "capability_not_granted", "peer has not granted chat.public", { suggestion: "request_grant" });
    }
    if (chat.reply_only) this.refuseUnshared(botId, peer, rel.id, "conversation.create");
    const since = new Date(Date.now() - 86400e3).toISOString();
    const today = this.get("SELECT COUNT(*) n FROM conversations WHERE relationship_id = ? AND created_at > ?", rel.id, since).n;
    if (today >= LIMITS.newConversationsPerPairPerDay) throw new ApiError(429, "rate_limited", "too many new conversations for this relationship today", { retry_after: 3600 });
    const allowed = (pl.intent.allowed_capabilities ?? intentDef.allowed).filter((c: string) => intentDef.allowed.includes(c));
    const intent = { type: intentDef.type, summary: String(pl.intent.summary ?? ""), params: pl.intent.params ?? {}, allowed_capabilities: allowed, success_criteria: pl.intent.success_criteria ?? null, max_turns: null };
    const id = newId("cnv");
    const expires = pl.intent.expires_at ? new Date(ms(pl.intent.expires_at)).toISOString() : new Date(Date.now() + 72 * 3600e3).toISOString();
    this.run("INSERT INTO conversations (id, type, relationship_id, initiator_bot, peer_bot, intent, status, max_turns, created_at, updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
      // max_turns stays in the schema (NOT NULL) but nothing reads it: conversations have no turn limit (owner decision 2026-10-19).
      id, "direct", rel.id, botId, peer.id, JSON.stringify(intent), "open", 0, nowIso(), nowIso(), expires);
    this.policyDecision(botId, id, [ownerId, peer.owner_id], "conversation.create", "allow", [roomRel ? "room.context" : "relationship.active", "intent.allowed"]);
    this.audit.append(`bot:${botId}`, "conversation.created", id, [ownerId, peer.owner_id], { peer: peer.id, intent, envelope_id: env.id, sig: env.sig });
    this.emit(peer.id, "conversation.started", { conversation_id: id, from: this.publicBot(this.bot(botId)), trust: "peer_untrusted", untrusted_content: { intent } });
    return {
      conversation_id: id, status: "open", intent,
      limits: { max_turns: null, rate_per_min: LIMITS.ratePerConversationPerMin, expires_at: expires },
      effective_capabilities: this.effectiveCaps(botId, peer.id, allowed, roomId),
    };
  }

  private effectiveCaps(me: string, peer: string, allowed: string[], roomId: string | null = null) {
    const meB = this.bot(me), peerB = this.bot(peer);
    // #43: a room conversation runs on that room's grants; the friendship grants (room_id IS NULL) are not it.
    const cap = (grantorOwner: string, granteeBot: string, c: string, grantedBot: string) =>
      roomId ? this.findRoomGrant(grantorOwner, granteeBot, c, grantedBot, roomId) : this.findGrant(grantorOwner, granteeBot, c, grantedBot);
    return {
      me_on_peer: allowed.filter((c) => cap(peerB.owner_id, me, c, peer)),
      peer_on_me: allowed.filter((c) => cap(meB.owner_id, peer, c, me)),
    };
  }

  /** `typedByOwner` is internal: set only by sendAsMember after typedByOwner() authorised it, never from the envelope or text. */
  draftMessage(p: Principal, convId: string, env: Envelope, typedByOwner = false, mentions: string[] = [], roomContext: string | null = null) {
    this.verifyEnvelope(p, env, "message.draft");
    const { botId, ownerId } = this.requireBot(p);
    assert(!env.conversation_id || env.conversation_id === convId, 400, "invalid_envelope", "conversation_id mismatch");
    const { peer } = this.memberConv(botId, convId);
    const peerB = this.bot(peer);
    const owners = [ownerId, peerB.owner_id];
    const roomRel = roomContext ? this.roomReach(botId, peer, roomContext) : null;
    if (!roomRel) this.activeRelationship(botId, peer);
    this.expireStale();
    const c = this.conv(convId);
    this.assertConvActive(c);
    const pl: any = env.payload ?? {};
    assert(typeof pl.text === "string" && pl.text.length > 0 && pl.text.length <= 4000, 400, "invalid_request", "payload.text (1-4000 chars) required");
    // Refs live in the signed payload, so the sender's signature covers them.
    const refs = this.checkRefs(botId, pl.attachments);
    const chat = roomRel ? this.findRoomGrant(peerB.owner_id, botId, "chat.public", peerB.id, roomContext!) : this.findGrant(peerB.owner_id, botId, "chat.public", peerB.id);
    if (!chat) {
      this.policyDecision(botId, convId, owners, "message.draft", "deny", ["capability_not_granted:chat.public"]);
      throw new ApiError(403, "capability_not_granted", "peer has not granted chat.public", { suggestion: "request_grant" });
    }
    // #23: a reply-only grant may answer, never start: the peer started this conversation or already wrote in it.
    if (chat.reply_only && c.initiator_bot !== peer && !this.get("SELECT 1 FROM messages WHERE conversation_id = ? AND sender_bot = ? AND status = 'delivered'", convId, peer)) {
      this.refuseUnshared(botId, peerB, c.relationship_id, "message.draft", convId);
    }
    // rate limits
    const minuteAgo = Date.now() - 60e3, hourAgo = Date.now() - 3600e3;
    if (this.get("SELECT COUNT(*) n FROM messages WHERE conversation_id = ? AND sender_bot = ? AND created_ms > ?", convId, botId, minuteAgo).n >= LIMITS.ratePerConversationPerMin)
      throw new ApiError(429, "rate_limited", "per-conversation rate limit (6/min)", { retry_after: 60 });
    if (this.get("SELECT COUNT(*) n FROM messages WHERE sender_bot = ? AND created_ms > ?", botId, hourAgo).n >= LIMITS.ratePerBotPerHour)
      throw new ApiError(429, "rate_limited", "global bot rate limit (60/h)", { retry_after: 3600 });
    // No turn budget (owner decision 2026-10-19 18:05): a conversation never runs out of turns.
    // Loop detection guards Bot-to-Bot exchanges only. A line the owner typed (typed_by_owner, attested
    // by sendAsMember for a trusted host token, never read from the text) is never paused by it: a person
    // saying "Hi" twice is not a loop, and pausing them left the owner unable to send at all.
    const recent = this.all("SELECT payload FROM messages WHERE conversation_id = ? AND status IN ('delivered','pending_approval') ORDER BY created_ms DESC LIMIT 3", convId)
      .reverse().map((m) => { const x = J(m.payload); return { text: x.text ?? "", structured: !!x.structured }; });
    if (!typedByOwner && detectLoop(recent, { text: pl.text, structured: !!pl.structured })) {
      this.pauseConversation(c, "paused_loop", "loop_detected");
      throw new ApiError(409, "conversation_paused", "loop detected (repetitive or content-free exchange); conversation paused");
    }
    // outbound DLP
    const flags = this.dlp(ownerId, pl);
    const blocked = flags.filter((f) => f.action === "block");
    if (blocked.length) {
      this.policyDecision(botId, convId, owners, "message.draft", "deny", ["dlp.blocked"], { categories: blocked.map((b) => b.category) });
      throw new ApiError(422, "dlp_blocked", "outbound DLP blocked this draft", { categories: blocked.map((b) => b.category) });
    }
    const id = newId("msg");
    const reasons = ["mvp.all_outbound_requires_approval", ...flags.map((f) => `dlp.${f.category}`)];
    // #49: one field says why this line is held; a client never has to read `reasons`.
    // The delivery path asks the same question over the same input (text + `structured`); a draft must not answer
    // "nothing found" for content the recipient will receive marked `security.injection_suspected`.
    const injection = detectInjection([pl.text, pl.structured ? JSON.stringify(pl.structured) : ""].join("\n"));
    const injectionSuspected = injection.suspected;
    const holdReason = holdReasonOf({ riskFlags: flags, attachments: refs, injectionSuspected });
    const files = refs.length ? ` [${refs.length} file${refs.length > 1 ? "s" : ""}: ${refs.map((r) => `${r.name} (${humanSize(r.size)})`).join(", ")}]` : "";
    // Only the two ends of this conversation can be mentioned in it.
    const ends = ["@" + String(this.bot(botId).handle).replace(/^@/, "").toLowerCase(), "@" + String(peerB.handle).replace(/^@/, "").toLowerCase()];
    const kept = mentions.filter((h) => ends.includes(h));
    // #139: a line the owner typed themselves does not wait for that same owner again. Four things must hold at
    // once: the owner attestation, a clean DLP scan, no attachments and no suspected injection. Anything else keeps
    // today's card: this narrows `mvp.all_outbound_requires_approval` to Bot-drafted outbound, it never lifts a
    // finding. Room-context sends keep their existing door/auto path (#45/#57), hence `roomContext === null` here.
    if (typedByOwner && roomContext === null && flags.length === 0 && refs.length === 0 && !injectionSuspected) {
      const payload = { kind: pl.kind ?? (pl.structured ? "structured" : "text"), text: pl.text, structured: pl.structured ?? null, expects_reply: pl.expects_reply !== false };
      const row = { id, conversation_id: convId, sender_bot: botId, recipient_bot: peer, envelope: JSON.stringify(env), typed_by_owner: 1, mentions: kept.length ? JSON.stringify(kept) : null };
      const delivered = this.deliveredEvent(row, c, payload, injection);
      this.run("INSERT INTO messages (id, conversation_id, sender_bot, recipient_bot, envelope, payload, delivered_payload, status, risk_flags, injection, expects_reply, approval_id, created_at, created_ms, delivered_at, typed_by_owner, mentions) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        id, convId, botId, peer, row.envelope, JSON.stringify(payload), JSON.stringify(payload), "delivered", "[]", JSON.stringify(injection), payload.expects_reply ? 1 : 0, null, String(delivered.delivered_at), Date.now(), String(delivered.delivered_at), 1, row.mentions);
      this.run("UPDATE conversations SET turn_count = ?, updated_at = ? WHERE id = ?", c.turn_count + 1, nowIso(), convId);
      this.emit(peer, "message.received", delivered);
      this.policyDecision(botId, convId, owners, "message.draft", "allow", ["owner.typed_by_owner", "dlp.clean"], { message_id: id, typed_by_owner: true });
      // The owner's audit page shows why this line needed no approval: the owner wrote it. Actor is the owner, not
      // the Bot (`message.drafted` stays `bot:<id>` for every card).
      this.audit.append(`owner:${ownerId}`, "owner_typed_message_delivered", id, owners, { conversation_id: convId, recipient_bot: peer, dlp_version: POLICY_VERSION, text_length: pl.text.length });
      this.audit.append("platform", "message.delivered", id, owners, { conversation_id: convId, turn: c.turn_count + 1, edited: false, injection_suspected: false, delivered_sha256: payloadDigest(payload), platform_countersig: delivered.platform_countersig, typed_by_owner: true });
      return { message_id: id, status: "delivered", approval_id: undefined, typed_by_owner: true, ...(kept.length ? { mentions: kept } : {}), policy: { decision: "allow", reasons: ["owner.typed_by_owner", "dlp.clean"], risk_flags: [], policy_version: POLICY_VERSION } };
    }
    const aprId = this.createApproval(ownerId, "outbound_message", id, botId, convId, `To @${peerB.handle}: ${pl.text.slice(0, 80)}${files}`, reasons, flags, J(c.intent).type === "schedule_meeting" ? LIMITS.meetingApprovalTtlMs : LIMITS.approvalTtlMs, undefined, holdReason);
    this.run("INSERT INTO messages (id, conversation_id, sender_bot, recipient_bot, envelope, payload, status, risk_flags, expects_reply, approval_id, created_at, created_ms, typed_by_owner, mentions) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      id, convId, botId, peer, JSON.stringify(env), JSON.stringify({ kind: pl.kind ?? (pl.structured ? "structured" : "text"), text: pl.text, structured: pl.structured ?? null, expects_reply: pl.expects_reply !== false, ...(refs.length ? { attachments: refs } : {}) }),
      "pending_approval", JSON.stringify(flags), pl.expects_reply === false ? 0 : 1, aprId, nowIso(), Date.now(), typedByOwner ? 1 : 0, kept.length ? JSON.stringify(kept) : null);
    for (const r of refs) this.run("UPDATE attachments SET message_id = ? WHERE id = ? AND message_id IS NULL", id, r.id);
    this.policyDecision(botId, convId, owners, "message.draft", "require_approval", reasons, { message_id: id });
    this.audit.append(`bot:${botId}`, "message.drafted", id, owners, { conversation_id: convId, envelope_id: env.id, payload_sha256: env.payload_sha256, sig: env.sig, risk_flags: flags, approval_id: aprId, ...(typedByOwner ? { typed_by_owner: true } : {}) });
    this.refreshConversationStatus(convId);
    const rel = roomRel ?? this.activeRelationship(botId, peer);
    const autoChat = this.settingsFor(rel.id, ownerId).auto_approve_chat;
    // #45: a line that names a room both Bots were put in by their owners is already consented (the click that
    // added them was the consent), so the blanket outbound rule alone does not stop it. Anything the platform found
    // on its own — a DLP flag, an attachment, suspected injection — is a finding and keeps the card.
    // #57: the room consent is the room reach that was actually resolved, not the room id in the argument. A send
    // that names a room the Bot is no longer in falls back to the friendship door above; it must not auto-deliver as
    // room context, and its stated reason must name the friendship door it really used.
    const byRoom = !!roomRel && refs.length === 0;
    // This gate reads the reason the card already carries. holdReasonOf ranks its findings
    // risk > attachment > policy > blanket_outbound (:40-45); only the last one is the owner's own default hold,
    // the one thing auto-approve may lift. Every finding ranked above it — a DLP flag, an attachment, suspected
    // injection — keeps the card. Do not re-list the findings here: the next one holdReasonOf learns would
    // drift out of this branch again.
    if ((autoChat || byRoom) && holdReason === "blanket_outbound") {
      this.decideApproval({ kind: "owner", ownerId }, aprId, { decision: "approved" }, byRoom ? "policy:room_context" : "policy:auto_approve");
      return { message_id: id, status: "delivered", approval_id: aprId, auto_approved: true, ...(byRoom ? { room_id: roomContext! } : {}), ...(typedByOwner ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), policy: { decision: "allow", reasons: [byRoom ? "room.context" : "owner.auto_approve_chat", "dlp.clean"], risk_flags: [], policy_version: POLICY_VERSION } };
    }
    return { message_id: id, status: "pending_approval", approval_id: aprId, ...(typedByOwner ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), policy: { decision: "require_approval", reasons, risk_flags: flags, hold_reason: holdReason, policy_version: POLICY_VERSION } };
  }

  private dlp(ownerId: string, pl: any) {
    const o = this.owner(ownerId);
    const text = [pl.text ?? "", pl.structured ? JSON.stringify(pl.structured) : ""].join("\n");
    const flags = dlpScan(text, J(o.sensitive_terms, []));
    const details = this.all("SELECT title, location FROM calendar_entries WHERE owner_id = ?", ownerId).flatMap((e) => [e.title, e.location]).filter(Boolean);
    if (calendarDetailLeak(text, details)) flags.push({ category: "calendar.details", action: "approve", label: "Calendar details" });
    return flags;
  }

  private pauseConversation(c: any, status: string, reason: string) {
    this.run("UPDATE conversations SET status = ?, updated_at = ? WHERE id = ?", status, nowIso(), c.id);
    const owners = [this.bot(c.initiator_bot).owner_id, this.bot(c.peer_bot).owner_id];
    this.audit.append("platform", "conversation.paused", c.id, owners, { status, reason, turn_count: c.turn_count });
    for (const b of [c.initiator_bot, c.peer_bot]) this.emit(b, "conversation.paused", { conversation_id: c.id, status, reason, trust: "platform" });
  }

  /**
   * FlyBot #442: the recipient's home took a delivered message but its Bot did not receive it, because the home had
   * not yet recorded the grant (for example in the seconds after an invite join). The recipient's owner reports it
   * here, and the sender's Bot gets a platform `message.not_delivered` event, so the sender sees "Not sent" instead
   * of silence. Owner-only (owner MCP at /mcp); `reason` is a fixed code, never free
   * text from the recipient; once per message; nothing is stored or forwarded beyond the event and the audit entry.
   */
  reportNotDelivered(p: Principal, body: { message_id: string; reason?: string }) {
    const ownerId = this.requireOwner(p);
    const m = this.get("SELECT * FROM messages WHERE id = ?", String(body?.message_id ?? ""));
    assert(m && this.bot(m.recipient_bot).owner_id === ownerId, 404, "message_not_found", "no such message delivered to one of your bots");
    assert(m.status === "delivered", 409, "invalid_state", `message is ${m.status}`);
    const reason = body?.reason ?? "not_shared_yet";
    assert(NOT_DELIVERED_REASONS.includes(reason), 400, "invalid_request", `reason must be one of ${NOT_DELIVERED_REASONS.join(", ")}`);
    if (m.not_delivered_reason) return { message_id: m.id, status: "not_delivered", reason: m.not_delivered_reason, already_reported: true };
    this.run("UPDATE messages SET not_delivered_reason = ? WHERE id = ?", reason, m.id);
    const recipient = this.bot(m.recipient_bot);
    const sender = this.bot(m.sender_bot);
    this.audit.append(`owner:${ownerId}`, "message.not_delivered", m.id, [sender.owner_id, recipient.owner_id], { conversation_id: m.conversation_id, reason });
    this.emit(sender.id, "message.not_delivered", { message_id: m.id, conversation_id: m.conversation_id, to: this.publicBot(recipient), reason, trust: "platform" });
    return { message_id: m.id, status: "not_delivered", reason };
  }

  /**
   * The one description of a delivered message. An approved card and an owner-typed direct send (#139) must produce
   * the same recipient event, countersignature included, so the shape lives here and nowhere else.
   */
  private deliveredEvent(m: any, c: any, payload: any, inj: { suspected: boolean; matches: string[] }, edited = false) {
    const sender = this.bot(m.sender_bot);
    const env = J(m.envelope);
    const intent = J(c.intent);
    const delivered: Record<string, unknown> = {
      message_id: m.id, conversation_id: c.id, intent: { type: intent.type, summary: intent.summary },
      from: this.publicBot(sender), trust: "peer_untrusted",
      untrusted_content: { text: payload.text, structured: payload.structured ?? null },
      ...(Array.isArray(payload.attachments) && payload.attachments.length ? { attachments: payload.attachments } : {}),
      expects_reply: payload.expects_reply !== false, approved_by_owner: true, edited_by_owner: !!edited,
      ...(m.typed_by_owner ? { typed_by_owner: true } : {}),
      ...(mentionsOf(m.mentions).length ? { mentions: mentionsOf(m.mentions) } : {}),
      security: { injection_suspected: inj.suspected }, turn: { count: c.turn_count + 1, max: null },
      sender_envelope: { id: env.id, ts: env.ts, nonce: env.nonce, payload_sha256: env.payload_sha256, sig: env.sig },
      platform_kid: this.platformKid, delivered_at: nowIso(),
    };
    delivered.platform_countersig = this.countersign(delivered);
    return delivered;
  }

  private deliverMessage(a: any, body: any) {
    const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
    const c = this.conv(m.conversation_id);
    const sender = this.bot(m.sender_bot);
    const recipient = this.bot(m.recipient_bot);
    // #43: a conversation opened from a claimed room delivers on that room's grant, and stops once it is gone.
    const cRel = this.pairRelationships(sender.id, recipient.id).find((r) => r.id === c.relationship_id);
    if (cRel && cRel.status === "room") {
      const roomGrant = this.get("SELECT room_id FROM grants WHERE relationship_id = ? AND status = 'active' AND room_id IS NOT NULL LIMIT 1", cRel.id);
      assert(roomGrant && roomGrant.room_id, 403, "no_relationship", "the room grant is gone");
      assert(this.findRoomGrant(recipient.owner_id, sender.id, "chat.public", recipient.id, roomGrant.room_id), 403, "no_relationship", "the room grant is gone");
    } else if (!this.findActiveRelationship(sender.id, recipient.id)) {
      // #67: a conversation opened under a room keeps that room in its record even after the door closes (the claim
      // was ended, the room expired). With no friendship left either, say that instead of `no active relationship
      // between these bots`: the pair was related, by a room, and the step that is missing is the room grant -- a
      // friendship refusal sends the owner looking for the wrong fix. A friendship is checked first, so a room card
      // that outlives its room still settles for a pair that is also friends.
      const convRoom = this.get("SELECT room_id FROM grants WHERE relationship_id = ? AND room_id IS NOT NULL LIMIT 1", c.relationship_id);
      if (convRoom?.room_id) throw new ApiError(403, "no_relationship", "the room grant is gone");
      this.activeRelationship(sender.id, recipient.id);
    }
    // A frozen recipient holds the card: the kill switch must not let a line written before the freeze land
    // inside it. Nothing is written here -- not the message, not the approval -- and the card stays pending,
    // so the owner can still decide it after a resume.
    this.assertReachable(recipient);
    let payload = J(m.payload);
    const edited = body.decision === "approved_with_edits" && body.edited_payload;
    // Validate the edit before any write: a refused edit must not already have cleared the draft's mention list.
    const patch = edited ? editedPayloadOf(body) : null;
    // The list described the text the sender wrote: an edited message carries none, and none is stored, so no view shows it either.
    if (edited && m.mentions) { this.run("UPDATE messages SET mentions = NULL WHERE id = ?", m.id); m.mentions = null; }
    if (edited) {
      payload = { ...payload, ...patch };
      const blocked = this.dlp(sender.owner_id, payload).filter((f) => f.action === "block");
      assert(!blocked.length, 422, "dlp_blocked", "edited payload blocked by DLP", { categories: blocked.map((b) => b.category) });
    }
    const inj = detectInjection([payload.text, payload.structured ? JSON.stringify(payload.structured) : ""].join("\n"));
    const turn = c.turn_count + 1;
    const delivered = this.deliveredEvent(m, c, payload, inj, !!edited);
    this.run("UPDATE messages SET status = 'delivered', delivered_payload = ?, injection = ?, delivered_at = ? WHERE id = ?", JSON.stringify(payload), JSON.stringify(inj), nowIso(), m.id);
    this.run("UPDATE conversations SET turn_count = ?, updated_at = ? WHERE id = ?", turn, nowIso(), c.id);
    this.emit(recipient.id, "message.received", delivered);
    this.emit(sender.id, "approval.decided", { approval_id: a.id, kind: "outbound_message", message_id: m.id, decision: body.decision, note_to_bot: body.note_to_bot ?? null, delivered_payload: payload });
    this.audit.append("platform", "message.delivered", m.id, [sender.owner_id, recipient.owner_id], { conversation_id: c.id, turn, edited: !!edited, injection_suspected: inj.suspected, delivered_sha256: payloadDigest(payload), platform_countersig: delivered.platform_countersig });
    return { message_id: m.id, status: "delivered" };
  }

  private rejectMessage(a: any, note?: string) {
    const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
    this.run("UPDATE messages SET status = 'rejected' WHERE id = ?", m.id);
    // the peer never sees rejected drafts; only the sender bot is informed
    this.emit(m.sender_bot, "approval.decided", { approval_id: a.id, kind: "outbound_message", message_id: m.id, decision: "rejected", note_to_bot: note ?? null });
    return { message_id: m.id, status: "rejected" };
  }

  /**
   * Resume a paused conversation (loop suspected, emergency-stopped, or a pre-removal paused_limit).
   * The name and `extra_turns` stay for older clients; conversations have no turn limit, so nothing is added.
   */
  extendConversation(p: Principal, convId: string, body: { extra_turns?: number }) {
    const ownerId = this.requireOwner(p);
    const c = this.conv(convId);
    const owners = [this.bot(c.initiator_bot).owner_id, this.bot(c.peer_bot).owner_id];
    assert(owners.includes(ownerId), 403, "forbidden");
    assert(["paused_limit", "paused_loop", "paused_stop", "open", "awaiting_approval"].includes(c.status), 409, "invalid_state", `conversation is ${c.status}`);
    void body;
    this.resumeConversation(c, `owner:${ownerId}`, { resumed_from: c.status });
    return { conversation_id: convId, status: this.conv(convId).status, max_turns: null };
  }

  private resumeConversation(c: any, actor: string, data: Record<string, unknown>) {
    const owners = [this.bot(c.initiator_bot).owner_id, this.bot(c.peer_bot).owner_id];
    if (!["open", "awaiting_approval"].includes(c.status)) {
      this.run("UPDATE conversations SET status = 'open', updated_at = ? WHERE id = ?", nowIso(), c.id);
      c.status = "open";
    }
    this.refreshConversationStatus(c.id);
    c.status = this.conv(c.id).status;
    this.audit.append(actor, "conversation.extended", c.id, owners, data);
    for (const b of [c.initiator_bot, c.peer_bot]) this.emit(b, "conversation.resumed", { conversation_id: c.id, max_turns: null, trust: "platform" });
  }

  closeConversation(p: Principal, convId: string, body: any) {
    let actor: string, outcome: string, summary: string | null;
    const c = this.conv(convId);
    const owners = [this.bot(c.initiator_bot).owner_id, this.bot(c.peer_bot).owner_id];
    if (p.kind === "bot") {
      const env = this.verifyEnvelope(p, body, "conversation.close");
      this.memberConv(p.botId, convId);
      actor = `bot:${p.botId}`;
      outcome = (env.payload as any)?.outcome ?? "abandoned";
      summary = (env.payload as any)?.summary ?? null;
    } else {
      assert(owners.includes(p.ownerId), 403, "forbidden");
      actor = `owner:${p.ownerId}`;
      outcome = body?.outcome ?? "abandoned";
      summary = body?.summary ?? null;
    }
    assert(["agreed", "declined", "abandoned"].includes(outcome), 400, "invalid_request", "outcome must be agreed|declined|abandoned");
    assert(c.status !== "closed", 409, "conversation_closed");
    this.run("UPDATE conversations SET status = 'closed', outcome = ?, summary = ?, updated_at = ? WHERE id = ?", outcome, summary, nowIso(), convId);
    // The invitee's decision about this chat's booking outlives the chat, so that one draft is kept; the subquery is
    // narrowed to this same conversation so an accept drafted in another chat is never exempted. Everything else is
    // cancelled, and each cancellation is announced to the Bot that owned the card.
    this.cancelPendingFor("conversation_id = ?", [convId], "conversation_closed", {
      keep: {
        where: "NOT (kind = 'action' AND subject_id IN (SELECT id FROM actions WHERE conversation_id = ? AND action_type = 'calendar.accept_invite'))",
        args: [convId],
      },
      notify: true,
    });
    this.audit.append(actor, "conversation.closed", convId, owners, { outcome, summary });
    // The summary was written by the Bot (or the owner) that closed the chat, so for the other side it is peer
    // content: it travels inside `untrusted_content` under `trust: "peer_untrusted"`, like every other peer text
    // (README "Untrusted markers", AGENT_GUIDE safety rule 1). Never a bare `summary` next to `trust: "platform"`.
    for (const b of [c.initiator_bot, c.peer_bot]) this.emit(b, "conversation.closed", { conversation_id: convId, outcome, trust: "peer_untrusted", untrusted_content: { summary } });
    return { conversation_id: convId, status: "closed", outcome };
  }

  listConversations(p: Principal) {
    const rows = p.kind === "owner"
      ? this.all("SELECT c.* FROM conversations c WHERE c.initiator_bot IN (SELECT id FROM bots WHERE owner_id = ?) OR c.peer_bot IN (SELECT id FROM bots WHERE owner_id = ?) ORDER BY c.created_at DESC", p.ownerId, p.ownerId)
      : this.all("SELECT * FROM conversations WHERE initiator_bot = ? OR peer_bot = ? ORDER BY created_at DESC", p.botId, p.botId);
    return rows.map((c) => ({ conversation_id: c.id, status: c.status, outcome: c.outcome, intent: J(c.intent), initiator: this.publicBot(this.bot(c.initiator_bot)), peer: this.publicBot(this.bot(c.peer_bot)), turn: { count: c.turn_count, max: null }, created_at: c.created_at, updated_at: c.updated_at }));
  }

  /** #57: the room a conversation is bound to, when its door is a room relationship; null for a 1:1 conversation. */
  private roomOfConversation(c: any): string | null {
    const rel = this.get("SELECT status FROM relationships WHERE id = ?", c.relationship_id);
    if (!rel || rel.status !== "room") return null;
    const g = this.get("SELECT room_id FROM grants WHERE relationship_id = ? AND room_id IS NOT NULL LIMIT 1", c.relationship_id);
    return g?.room_id ?? null;
  }

  /** Conversation view. Peer messages appear only once delivered, always wrapped as untrusted. */
  getConversation(p: Principal, convId: string) {
    const c = this.conv(convId);
    let viewerBot: string;
    if (p.kind === "bot") { this.memberConv(p.botId, convId); viewerBot = p.botId; }
    else {
      const mine = [c.initiator_bot, c.peer_bot].find((b) => this.bot(b).owner_id === p.ownerId);
      assert(mine, 403, "forbidden");
      viewerBot = mine;
    }
    const msgs = this.all("SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_ms ASC", convId)
      .filter((m) => m.sender_bot === viewerBot || m.status === "delivered")
      .map((m) => {
        const content = J(m.delivered_payload) ?? J(m.payload);
        return m.sender_bot === viewerBot
          ? { message_id: m.id, direction: "outbound", status: m.status, content, ...(m.typed_by_owner ? { typed_by_owner: true } : {}), ...(mentionsOf(m.mentions).length ? { mentions: mentionsOf(m.mentions) } : {}), risk_flags: J(m.risk_flags, []), approval_id: m.status === "pending_approval" ? m.approval_id : undefined, created_at: m.created_at, delivered_at: m.delivered_at }
          : { message_id: m.id, direction: "inbound", status: m.status, expects_reply: !!m.expects_reply, from: this.publicBot(this.bot(m.sender_bot)), trust: "peer_untrusted", ...(m.typed_by_owner ? { typed_by_owner: true } : {}), ...(mentionsOf(m.mentions).length ? { mentions: mentionsOf(m.mentions) } : {}), untrusted_content: { text: content.text, structured: content.structured }, security: { injection_suspected: J(m.injection, {}).suspected ?? false }, delivered_at: m.delivered_at };
      });
    const actions = this.all("SELECT * FROM actions WHERE conversation_id = ? ORDER BY created_at", convId)
      .filter((x) => x.actor_bot === viewerBot || ["executed", "failed"].includes(x.status))
      .map((x) => ({ action_id: x.id, actor_bot: x.actor_bot, action_type: x.action_type, params: J(x.params), status: x.status, result: J(x.result) }));
    // `room_id` is read-only: which room this conversation belongs to (null for 1:1), so a console does not offer a
    // 1:1 send on a room chat — that route resolves `activeRelationship` and would land the line in another thread.
    const roomId = this.roomOfConversation(c);
    return {
      conversation_id: c.id, room_id: roomId, status: c.status, outcome: c.outcome, summary: c.summary, intent: J(c.intent), turn: { count: c.turn_count, max: null },
      initiator: this.publicBot(this.bot(c.initiator_bot)), peer: this.publicBot(this.bot(c.peer_bot)), messages: msgs, actions,
      // #57: a conversation bound to a room reports that room's capabilities, not the friendship's; 1:1 is unchanged.
      effective_capabilities: this.effectiveCaps(viewerBot, viewerBot === c.initiator_bot ? c.peer_bot : c.initiator_bot, J(c.intent).allowed_capabilities, roomId),
    };
  }

  // ================================================================ actions
  draftAction(p: Principal, convId: string, env: Envelope) {
    this.verifyEnvelope(p, env, "action.draft");
    const { botId, ownerId } = this.requireBot(p);
    const { c, peer } = this.memberConv(botId, convId);
    const peerB = this.bot(peer);
    const owners = [ownerId, peerB.owner_id];
    this.activeRelationship(botId, peer);
    const pl: any = env.payload ?? {};
    const def = ACTIONS[pl.action_type];
    const isAccept = pl.action_type === "calendar.accept_invite";
    const intent = J(c.intent);
    const params = pl.params ?? {};
    let acceptInvite: any = null;
    if (isAccept) {
      // A booked invitation outlives the chat it was made in: an agreed or expired conversation may still accept it,
      // and the initiator's allowed_capabilities list is not the invitee's veto. The booking is looked up first so a
      // missing invite stays the 404 it always was, and only a paused chat refuses the draft.
      acceptInvite = this.get("SELECT * FROM calendar_entries WHERE booking_id = ? AND owner_id = ? AND status = 'invited'", params.booking_id, ownerId);
      assert(acceptInvite, 404, "invite_not_found", "no pending invite with that booking_id for your owner");
      this.materializeExpiry(c);
      this.assertNotPaused(c);
    } else {
      this.assertConvActive(c);
    }
    if (!def || (!isAccept && !intent.allowed_capabilities.includes(def.capability))) {
      this.policyDecision(botId, convId, owners, "action.draft", "deny", ["intent_scope_violation"], { action_type: pl.action_type });
      throw new ApiError(403, "intent_scope_violation", `action ${pl.action_type} not allowed in ${intent.type} conversation`);
    }
    const tz = this.owner(ownerId).timezone;
    let summary: string;
    if (pl.action_type === "calendar.book") {
      const s = ms(params.start), e = ms(params.end);
      assert(e > s, 400, "invalid_request", "end must be after start");
      const att: string[] = params.attendees ?? [peer];
      assert(att.length === 1 && att[0] === peer, 400, "invalid_request", "attendees must be exactly the peer bot");
      params.attendees = att;
      summary = `Book ${isoInTz(s, tz).slice(0, 16).replace("T", " ")}–${isoInTz(e, tz).slice(11, 16)} (${tz}) and invite @${peerB.handle}?`;
    } else {
      summary = `Accept @${peerB.handle}'s meeting invite at ${isoInTz(Date.parse(acceptInvite.start), tz).slice(0, 16).replace("T", " ")} (${tz})?`;
    }
    const dlpFlags = this.dlp(ownerId, { text: [params.title, pl.justification].filter(Boolean).join(" ") });
    assert(!dlpFlags.some((f) => f.action === "block"), 422, "dlp_blocked", "DLP blocked this action draft");
    const id = newId("act");
    const reasons = [...def.reasons];
    const aprId = this.createApproval(ownerId, "action", id, botId, convId, summary, reasons, dlpFlags, LIMITS.meetingApprovalTtlMs);
    this.run("INSERT INTO actions (id, conversation_id, actor_bot, action_type, params, justification, envelope, status, approval_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
      id, convId, botId, pl.action_type, JSON.stringify(params), pl.justification ?? null, JSON.stringify(env), "pending_approval", aprId, nowIso());
    this.policyDecision(botId, convId, owners, "action.draft", "require_approval", reasons, { action_id: id, action_type: pl.action_type });
    this.audit.append(`bot:${botId}`, "action.drafted", id, owners, { conversation_id: convId, action_type: pl.action_type, params, envelope_id: env.id, sig: env.sig, approval_id: aprId });
    this.refreshConversationStatus(convId);
    return { action_id: id, status: "pending_approval", approval_id: aprId, sensitivity: def.sensitivity, policy: { decision: "require_approval", reasons, policy_version: POLICY_VERSION } };
  }

  private executeAction(a: any, body: any) {
    const x = this.get("SELECT * FROM actions WHERE id = ?", a.subject_id);
    const c = this.conv(x.conversation_id);
    const actor = this.bot(x.actor_bot);
    const peer = this.bot(c.initiator_bot === actor.id ? c.peer_bot : c.initiator_bot);
    this.activeRelationship(actor.id, peer.id);
    const params = { ...J(x.params), ...(body.decision === "approved_with_edits" && body.edited_params ? body.edited_params : {}) };
    // An owner edit amends the bot's draft; it does not create a new unchecked commitment. The invariants the
    // action draft door set (range, attendees, DLP text, and the invite the accept points at) are re-checked here,
    // before any write — before `fail()` and before any calendar/actions/events row — so a refusal leaves the
    // card pending and the same card can be retried with a valid edit. `edited_params: null` is no edit.
    const edit = body.decision === "approved_with_edits" ? body.edited_params : undefined;
    if (edit !== undefined && edit !== null) {
      assert(typeof edit === "object" && !Array.isArray(edit), 400, "invalid_request", "edited_params must be an object");
      if (x.action_type === "calendar.book") {
        const s = ms(params.start), e = ms(params.end);
        assert(e > s, 400, "invalid_request", "end must be after start");
        const att: string[] = params.attendees ?? [peer.id];
        assert(att.length === 1 && att[0] === peer.id, 400, "invalid_request", "attendees must be exactly the peer bot");
        const dlpFlags = this.dlp(actor.owner_id, { text: [params.title, x.justification].filter(Boolean).join(" ") });
        assert(!dlpFlags.some((f) => f.action === "block"), 422, "dlp_blocked", "edited_params blocked by DLP");
      } else if (x.action_type === "calendar.accept_invite") {
        const inv = this.get("SELECT * FROM calendar_entries WHERE booking_id = ? AND owner_id = ? AND status = 'invited'", params.booking_id, actor.owner_id);
        assert(inv, 404, "invite_not_found", "no pending invite with that booking_id for your owner");
      }
    }
    const owners = [actor.owner_id, peer.owner_id];
    const fail = (reason: string, detail: any = {}) => {
      this.run("UPDATE actions SET status = 'failed', result = ? WHERE id = ?", JSON.stringify({ error: reason, ...detail }), x.id);
      this.audit.append("platform", "action.failed", x.id, owners, { reason, ...detail });
      this.emit(actor.id, "action.failed", { action_id: x.id, conversation_id: c.id, reason, trust: "platform" });
      return { action_id: x.id, status: "failed", reason };
    };
    if (x.action_type === "calendar.book") {
      const s = ms(params.start), e = ms(params.end);
      if (this.busyOf(actor.owner_id, s, e).length) return fail("calendar_conflict");
      const bookingId = newId("bkg");
      const title = params.title || J(c.intent).summary || "Meeting";
      const ins = "INSERT INTO calendar_entries (id, owner_id, start, end, title, attendees, source, status, organizer_owner, booking_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
      this.run(ins, newId("cal"), actor.owner_id, new Date(s).toISOString(), new Date(e).toISOString(), title, JSON.stringify([peer.owner_id]), "botsocial", "confirmed", actor.owner_id, bookingId, nowIso());
      this.run(ins, newId("cal"), peer.owner_id, new Date(s).toISOString(), new Date(e).toISOString(), title, JSON.stringify([actor.owner_id]), "botsocial", "invited", actor.owner_id, bookingId, nowIso());
      const result = { booking_id: bookingId, start: new Date(s).toISOString(), end: new Date(e).toISOString(), title, organizer: actor.id, invitee: peer.id, invitee_status: "invited" };
      this.run("UPDATE actions SET status = 'executed', result = ? WHERE id = ?", JSON.stringify(result), x.id);
      this.audit.append("platform", "action.executed", x.id, owners, { action_type: x.action_type, ...result });
      // `title` is written by the requester's Bot (`params.title`, else its intent summary). The requester's own
      // copy can keep it: it is that Bot's text. The invitee's copy carries it as peer content, inside
      // `untrusted_content`, never as a top-level field next to `trust: "platform"`.
      const { title: bookedTitle, ...bookedFacts } = result;
      this.emit(actor.id, "event.meeting_booked", { conversation_id: c.id, action_id: x.id, trust: "platform", ...result });
      this.emit(peer.id, "event.meeting_booked", { conversation_id: c.id, action_id: x.id, trust: "peer_untrusted", ...bookedFacts, untrusted_content: { title: bookedTitle }, note: "Invite pending. Accepting is a commitment requiring your owner's approval: draft action calendar.accept_invite." });
      return { action_id: x.id, status: "executed", result };
    }
    if (x.action_type === "calendar.accept_invite") {
      const inv = this.get("SELECT * FROM calendar_entries WHERE booking_id = ? AND owner_id = ? AND status = 'invited'", params.booking_id, actor.owner_id);
      if (!inv) return fail("invite_not_found");
      if (this.busyOf(actor.owner_id, Date.parse(inv.start), Date.parse(inv.end)).length) return fail("calendar_conflict");
      this.run("UPDATE calendar_entries SET status = 'confirmed' WHERE id = ?", inv.id);
      const result = { booking_id: params.booking_id, invitee_status: "accepted", start: inv.start, end: inv.end };
      this.run("UPDATE actions SET status = 'executed', result = ? WHERE id = ?", JSON.stringify(result), x.id);
      this.audit.append("platform", "action.executed", x.id, owners, { action_type: x.action_type, ...result });
      for (const b of [actor.id, peer.id]) this.emit(b, "event.invite_accepted", { conversation_id: c.id, action_id: x.id, trust: "platform", by: actor.id, ...result });
      return { action_id: x.id, status: "executed", result };
    }
    return fail("unsupported_action");
  }

  private rejectAction(a: any, note?: string) {
    this.run("UPDATE actions SET status = 'rejected' WHERE id = ?", a.subject_id);
    this.emit(a.bot_id, "approval.decided", { approval_id: a.id, kind: "action", action_id: a.subject_id, decision: "rejected", note_to_bot: note ?? null });
    return { action_id: a.subject_id, status: "rejected" };
  }

  // ================================================================ calendar (built-in mock provider)
  private busyOf(ownerId: string, s: number, e: number) {
    return this.all("SELECT * FROM calendar_entries WHERE owner_id = ? AND status = 'confirmed'", ownerId).filter((x) => overlaps(Date.parse(x.start), Date.parse(x.end), s, e));
  }

  addCalendarEntry(p: Principal, body: { start: string; end: string; title?: string; location?: string }) {
    const ownerId = this.requireOwner(p);
    const s = ms(body?.start), e = ms(body?.end);
    assert(e > s, 400, "invalid_request", "end must be after start");
    const id = newId("cal");
    this.run("INSERT INTO calendar_entries (id, owner_id, start, end, title, location, created_at) VALUES (?,?,?,?,?,?,?)", id, ownerId, new Date(s).toISOString(), new Date(e).toISOString(), body.title ?? null, body.location ?? null, nowIso());
    return { id, start: new Date(s).toISOString(), end: new Date(e).toISOString() };
  }

  listCalendar(p: Principal) {
    const ownerId = this.requireOwner(p);
    return this.all("SELECT * FROM calendar_entries WHERE owner_id = ? ORDER BY start", ownerId).map((e) => ({ ...e, attendees: J(e.attendees, []) }));
  }

  /** Free/busy query (§10.10). Peer subjects need calendar.freebusy.read granted by the peer owner; only intervals are returned. */
  freebusy(p: Principal, env: Envelope) {
    this.verifyEnvelope(p, env, "calendar.freebusy.query");
    const { botId, ownerId } = this.requireBot(p);
    const pl: any = env.payload ?? {};
    const { c } = this.memberConv(botId, pl.conversation_id);
    this.assertConvActive(c);
    const intent = J(c.intent);
    if (!intent.allowed_capabilities.includes("calendar.freebusy.read")) throw new ApiError(403, "intent_scope_violation", "freebusy not allowed in this intent");
    const ws = ms(pl.window?.start ?? intent.params?.window?.start), we = ms(pl.window?.end ?? intent.params?.window?.end);
    assert(we > ws && we - ws <= 31 * 86400e3, 400, "invalid_request", "window must be positive and <= 31 days");
    const subjects: string[] = pl.subjects ?? ["self"];
    const results: Record<string, any> = {};
    const hourRules: { tz: string; hours: [number, number] }[] = [{ tz: this.owner(ownerId).timezone, hours: [9 * 60, 18 * 60] }];
    const busyAll: [number, number][] = [];
    const peerOwners: string[] = [];
    for (const sub of subjects) {
      if (sub === "self" || sub === botId) {
        const busy = this.busyOf(ownerId, ws, we).map((x) => ({ start: x.start, end: x.end }));
        results.self = { busy };
        busy.forEach((b) => busyAll.push([Date.parse(b.start), Date.parse(b.end)]));
        continue;
      }
      assert(sub === c.initiator_bot || sub === c.peer_bot, 403, "intent_scope_violation", "subjects must be self or the conversation peer");
      const peerB = this.bot(sub);
      peerOwners.push(peerB.owner_id);
      this.activeRelationship(botId, sub);
      const g = this.findGrant(peerB.owner_id, botId, "calendar.freebusy.read", peerB.id);
      if (!g) {
        this.policyDecision(botId, c.id, [ownerId, peerB.owner_id], "calendar.freebusy.read", "deny", ["capability_not_granted"]);
        throw new ApiError(403, "capability_not_granted", "peer has not granted calendar.freebusy.read", { suggestion: "request_grant", capability: "calendar.freebusy.read" });
      }
      const s = ws;
      let e = we;
      if (g.scope.window_days) e = Math.min(e, Date.now() + g.scope.window_days * 86400e3);
      const hrs = parseHours(g.scope.hours);
      if (hrs) hourRules.push({ tz: this.owner(peerB.owner_id).timezone, hours: hrs });
      const busy = s < e ? this.busyOf(peerB.owner_id, s, e).map((x) => ({ start: x.start, end: x.end })) : [];
      results[sub] = { busy, grant_id: g.id, window: { start: new Date(s).toISOString(), end: new Date(Math.max(s, e)).toISOString() }, scope: g.scope, redacted: ["title", "location", "attendees"] };
      busy.forEach((b) => busyAll.push([Date.parse(b.start), Date.parse(b.end)]));
      if (e < we) busyAll.push([e, we]); // outside the granted window = unknown, treated as unavailable
      this.policyDecision(botId, c.id, [ownerId, peerB.owner_id], "calendar.freebusy.read", "allow", ["grant.active"], { grant_id: g.id });
    }
    const dur = (Number(intent.params?.duration_minutes) || 30) * 60e3;
    const step = 30 * 60e3;
    const suggestions: { start: string; end: string }[] = [];
    for (let t = Math.max(Math.ceil(ws / step) * step, Math.ceil(Date.now() / step) * step); t + dur <= we && suggestions.length < 5; t += step) {
      const okHours = hourRules.every((r) => {
        const wd = localWeekday(t, r.tz);
        const a = localMinutes(t, r.tz);
        return wd >= 1 && wd <= 5 && a >= r.hours[0] && a + dur / 60e3 <= r.hours[1];
      });
      if (okHours && !busyAll.some(([s, e]) => overlaps(t, t + dur, s, e))) suggestions.push({ start: isoInTz(t, hourRules[0].tz), end: isoInTz(t + dur, hourRules[0].tz) });
    }
    this.audit.append(`bot:${botId}`, "calendar.freebusy.queried", c.id, [ownerId, ...peerOwners], { subjects, envelope_id: env.id });
    return { results, common_free_suggestions: suggestions };
  }

  // ================================================================ events & audit
  listEvents(p: Principal, since = 0, limit = 100) {
    const { botId } = this.requireBot(p);
    // Defense in depth (#177 ③): rotateBotToken no longer mints a token for a revoked identity, but a token row
    // that outlives the revocation must not read the pre-revocation queue either. frozen may still read: the
    // kill switch stops reach, not the owner's own view.
    assert(this.bot(botId).status !== "revoked", 403, "bot_revoked", "this bot identity was revoked");
    this.expireStale();
    const rows = this.all("SELECT * FROM events WHERE bot_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?", botId, since, limit);
    return { events: rows.map((r) => ({ cursor: r.seq, event_id: r.id, event_type: r.type, created_at: r.created_at, ...J(r.data) })), next_cursor: rows.length ? rows[rows.length - 1].seq : since };
  }

  auditEvents(p: Principal, opts: { subject?: string; limit?: number } = {}) {
    const ownerId = this.requireOwner(p);
    // The whole chain is verified on every query, but an owner only sees their own numbers: the server-wide
    // record count and head hash would leak overall activity volume.
    const v = this.audit.verify();
    return { events: this.audit.list({ owner: ownerId, subject: opts.subject, limit: opts.limit }), chain: { ok: v.ok, count: this.audit.countFor(ownerId), ...(v.ok ? {} : { broken_at: v.broken_at }) } };
  }

  // ================================================================ face-to-face rooms
  /** `look` adds the Bot's current avatar/color. Only used for the member list of a room the viewer belongs to;
   *  events (persisted, replayed and delivered as inbox items) never carry the avatar. */
  private faceMemberPublic(m: any, look = false) {
    // The member row holds the names as they were when it joined; a row written before #106 may hold controls,
    // U+2028, a leading @ or more than 60 code points, so clean it on read by the same rule as `publicBot`.
    const display_name = peerDisplayName(m.display_name, "Bot");
    const owner_name = peerDisplayName(m.owner_name, "Owner");
    return {
      handle: m.handle, display_name, owner_name,
      label: memberLabel(display_name, owner_name), bot_id: m.bot_id,
      ...(look ? { role: m.role ? sanitizePeerName(m.role, "", FACE_ROOM_ROLE_MAX) || null : null } : {}),
      ...(look ? lookOf(this.get("SELECT avatar, color, avatar_updated_at FROM bots WHERE id = ?", m.bot_id) ?? {}) : {}),
    };
  }
  private faceSnapshot(b: any) {
    const o = this.owner(b.owner_id);
    const display_name = peerBotName(b, "Bot");
    const owner_name = peerOwnerName(o, "Owner");
    return {
      bot_id: b.id, handle: "@" + String(b.handle).replace(/^@/, ""), display_name, owner_name,
      label: memberLabel(display_name, owner_name),
    };
  }
  private faceOwnerIds(roomId: string, includeLeft = false) {
    const q = includeLeft
      ? "SELECT DISTINCT owner_id FROM face_room_members WHERE room_id = ?"
      : "SELECT DISTINCT owner_id FROM face_room_members WHERE room_id = ? AND left_at IS NULL";
    return this.all(q, roomId).map((r: any) => r.owner_id);
  }
  private faceInsertEvent(roomId: string, type: string, actorBot: string | null, data: Record<string, unknown>) {
    const id = newId("fev");
    const created_at = this.ts();
    this.run("INSERT INTO face_room_events (id, room_id, type, actor_bot, data, created_at) VALUES (?,?,?,?,?,?)", id, roomId, type, actorBot, JSON.stringify(data), created_at);
    return { id, seq: this.get("SELECT seq FROM face_room_events WHERE id = ?", id).seq as number, created_at, type };
  }
  private faceEmitMembers(roomId: string, type: string, data: Record<string, unknown>) {
    for (const m of this.all("SELECT bot_id FROM face_room_members WHERE room_id = ? AND left_at IS NULL", roomId)) this.emit(m.bot_id, type, data);
  }
  private faceEventPublic(e: any) {
    return { event_id: e.id, event_cursor: e.seq, type: e.type, created_at: e.created_at, actor_bot: e.actor_bot, ...J(e.data, {}) };
  }
  private faceRecordAttempt(ownerId: string | null, ip: string | null, code: string, outcome: string) {
    this.run("INSERT INTO face_room_attempts (owner_id, ip, code, outcome, created_at) VALUES (?,?,?,?,?)", ownerId, ip, String(code).slice(0, 16), outcome, this.ts());
  }
  private faceSetLockout(key: string, fails: number) {
    this.run(`INSERT INTO face_room_lockouts (key, until, fails, created_at) VALUES (?,?,?,?)
      ON CONFLICT(key) DO UPDATE SET until = excluded.until, fails = excluded.fails`, key, new Date(this.nowMs() + this.faceRoomLimits.lockoutMs).toISOString(), fails, this.ts());
  }
  private faceLockoutUntil(ownerId: string, ip: string | null): string | null {
    const now = this.ts();
    const rows = this.all("SELECT until FROM face_room_lockouts WHERE key IN (?, ?) AND until > ?", `owner:${ownerId}`, ip ? `ip:${ip}` : `owner:${ownerId}`, now);
    return rows.length ? rows.map((r: any) => r.until as string).sort().at(-1)! : null;
  }
  private faceFailOutcomes() { return ["invalid_code", "room_full", "code_void"] as const; }
  private faceMaybeLockout(ownerId: string, ip: string | null): boolean {
    const since = new Date(this.nowMs() - this.faceRoomLimits.attemptWindowMs).toISOString();
    const fails = this.faceFailOutcomes();
    const marks = fails.map(() => "?").join(",");
    let locked = false;
    const acct = this.get(`SELECT COUNT(*) n FROM face_room_attempts WHERE owner_id = ? AND created_at > ? AND outcome IN (${marks})`, ownerId, since, ...fails).n;
    if (acct >= this.faceRoomLimits.failsBeforeLockout) { this.faceSetLockout(`owner:${ownerId}`, acct); locked = true; }
    if (ip) {
      const n = this.get(`SELECT COUNT(*) n FROM face_room_attempts WHERE ip = ? AND created_at > ? AND outcome IN (${marks})`, ip, since, ...fails).n;
      if (n >= this.faceRoomLimits.failsBeforeLockout) { this.faceSetLockout(`ip:${ip}`, n); locked = true; }
    }
    return locked;
  }
  private faceRateFail(message: string, scope: string, windowMs: number) {
    return { ok: false as const, status: 429, code: "rate_limited", message, extra: { retry_after: Math.ceil(windowMs / 1000), scope } };
  }
  /** 6-digit (and invite-join) attempts. A successful invite mint is not one of them: it has its own budget (#69). */
  private faceAttemptRateLimit(ownerId: string, ip: string | null) {
    const since = new Date(this.nowMs() - this.faceRoomLimits.attemptWindowMs).toISOString();
    const marks = FACE_JOIN_OUTCOMES.map(() => "?").join(",");
    if (this.get(`SELECT COUNT(*) n FROM face_room_attempts WHERE owner_id = ? AND created_at > ? AND outcome IN (${marks})`, ownerId, since, ...FACE_JOIN_OUTCOMES).n >= this.faceRoomLimits.attemptsPerAccount)
      return this.faceRateFail("too many code attempts from this account", "account", this.faceRoomLimits.attemptWindowMs);
    // `ended` / `revoked` / `expired` / `invite_not_found` are also preview refusal codes, and a preview row has
    // no owner (`owner_id IS NULL`). Only this owner-bound filter keeps a read out of the per-address join budget.
    if (ip && this.get(`SELECT COUNT(*) n FROM face_room_attempts WHERE ip = ? AND owner_id IS NOT NULL AND created_at > ? AND outcome IN (${marks})`, ip, since, ...FACE_JOIN_OUTCOMES).n >= this.faceRoomLimits.attemptsPerIp)
      return this.faceRateFail("too many code attempts from this address", "ip", this.faceRoomLimits.attemptWindowMs);
    return null;
  }
  /** Invite-link mints (local rooms and face rooms). Counts only `minted` rows, so it cannot starve a code join. */
  private inviteMintRateLimit(ownerId: string, ip: string | null) {
    const since = new Date(this.nowMs() - this.faceRoomLimits.inviteMintWindowMs).toISOString();
    if (this.get("SELECT COUNT(*) n FROM face_room_attempts WHERE owner_id = ? AND created_at > ? AND outcome = 'minted'", ownerId, since).n >= this.faceRoomLimits.invitesPerAccount)
      return this.faceRateFail("too many invite links from this account", "account_invite", this.faceRoomLimits.inviteMintWindowMs);
    if (ip && this.get("SELECT COUNT(*) n FROM face_room_attempts WHERE ip = ? AND created_at > ? AND outcome = 'minted'", ip, since).n >= this.faceRoomLimits.invitesPerIp)
      return this.faceRateFail("too many invite links from this address", "ip_invite", this.faceRoomLimits.inviteMintWindowMs);
    return null;
  }
  private faceCreateRateLimit(ownerId: string, ip: string | null) {
    const since = new Date(this.nowMs() - this.faceRoomLimits.createWindowMs).toISOString();
    if (this.get("SELECT COUNT(*) n FROM face_room_attempts WHERE owner_id = ? AND created_at > ? AND outcome = 'created'", ownerId, since).n >= this.faceRoomLimits.createsPerAccount)
      return this.faceRateFail("too many face rooms created from this account", "account_create", this.faceRoomLimits.createWindowMs);
    if (ip && this.get("SELECT COUNT(*) n FROM face_room_attempts WHERE ip = ? AND created_at > ? AND outcome = 'created'", ip, since).n >= this.faceRoomLimits.createsPerIp)
      return this.faceRateFail("too many face rooms created from this address", "ip_create", this.faceRoomLimits.createWindowMs);
    return null;
  }
  private normalizeBotRefs(body: any): string[] {
    const raw = body?.bots ?? body?.handles ?? body?.bot_ids ?? body?.bot_id ?? body?.bot ?? body?.handle;
    if (raw === undefined || raw === null || raw === "") return [];
    return (Array.isArray(raw) ? raw : [raw]).map((x) => String(x).trim()).filter(Boolean);
  }
  private faceBotsToBring(p: Principal, body: any): { bot: any; viaGrant?: any }[] {
    const wrap = (bot: any, viaGrant?: any) => ({ bot, viaGrant });
    if (p.kind === "bot") {
      const extra = this.normalizeBotRefs(body);
      if (extra.some((r) => r !== p.botId && handleKey(r) !== handleKey(this.bot(p.botId).handle))) throw new ApiError(403, "forbidden", "a bot token may only bring itself");
      const b = this.bot(p.botId);
      this.assertInvitable(b);
      return [wrap(b)];
    }
    const refs = this.normalizeBotRefs(body);
    if (!refs.length) {
      const members = this.all("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' AND integration_type = 'flybot-member' ORDER BY created_at", p.ownerId);
      if (members.length) return [wrap(members[0])];
      const rest = this.all("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' AND integration_type != 'flybot-home' ORDER BY created_at", p.ownerId);
      if (rest.length) return [wrap(rest[0])];
      const any = this.all("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' ORDER BY created_at", p.ownerId);
      assert(any.length, 404, "bot_not_found", "no bot to bring into the room");
      return [wrap(any[0])];
    }
    const out: { bot: any; viaGrant?: any }[] = [];
    const mine = this.all("SELECT id FROM bots WHERE owner_id = ? AND status = 'active'", p.ownerId).map((b: any) => b.id);
    for (const ref of refs) {
      const own = this.get("SELECT * FROM bots WHERE id = ? AND owner_id = ?", ref, p.ownerId) ?? this.botByRef(ref, "owner_id = ?", [p.ownerId]);
      if (own) {
        this.assertInvitable(own);
        if (!out.some((x) => x.bot.id === own.id)) out.push(wrap(own));
        continue;
      }
      const other = this.get("SELECT * FROM bots WHERE id = ?", ref) ?? this.botByRef(ref);
      assert(other && other.status === "active", 404, "bot_not_found", `no bot matching ${ref} on this account`);
      const grant = this.accessGrantTo(p.ownerId, mine, other.id);
      assert(grant, 404, "bot_not_found", `no bot matching ${ref} on this account`);
      // #23: a reply-only grant (from joining an invite) never lets you bring the other owner's Bot into a room.
      if (grant.reply_only_access) this.refuseUnshared(grant.grantee_bot, other, grant.relationship_id, "face_room.join");
      if (!out.some((x) => x.bot.id === other.id)) out.push(wrap(other, grant));
    }
    return out;
  }
  private faceAddMembers(roomId: string, bots: any[], addedByOwnerId: string) {
    const now = this.ts();
    for (const b of bots) {
      const snap = this.faceSnapshot(b);
      const text = joinSystemText(snap.owner_name, snap.display_name);
      const ev = this.faceInsertEvent(roomId, "member.joined", b.id, { text, member: snap, trust: "platform" });
      const existing = this.get("SELECT 1 FROM face_room_members WHERE room_id = ? AND bot_id = ?", roomId, b.id);
      if (existing) {
        this.run("UPDATE face_room_members SET left_at = NULL, joined_at = ?, join_seq = ?, display_name = ?, owner_name = ?, handle = ?, added_by_owner_id = ? WHERE room_id = ? AND bot_id = ?",
          now, ev.seq, snap.display_name, snap.owner_name, snap.handle, addedByOwnerId, roomId, b.id);
      } else {
        this.run("INSERT INTO face_room_members (room_id, bot_id, owner_id, handle, display_name, owner_name, added_by_owner_id, joined_at, join_seq) VALUES (?,?,?,?,?,?,?,?,?)",
          roomId, b.id, b.owner_id, snap.handle, snap.display_name, snap.owner_name, addedByOwnerId, now, ev.seq);
      }
      this.faceEmitMembers(roomId, "face_room.joined", { room_id: roomId, event_id: ev.id, event_cursor: ev.seq, text, member: snap, trust: "platform" });
    }
  }
  /** Implicit room-scoped grants between the newcomers and everyone already in the room (other owners). */
  private syncFaceRoomAccess(roomId: string, newcomers: any[], actorOwnerId: string, bring: { bot: any; viaGrant?: any }[]) {
    const members = this.all("SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL", roomId);
    for (const nb of newcomers) {
      for (const em of members) {
        if (em.bot_id === nb.id || em.owner_id === nb.owner_id) continue;
        this.ensurePairRoomGrant(roomId, nb, this.bot(em.bot_id), actorOwnerId);
      }
    }
    for (const x of bring) {
      if (!x.viaGrant) continue;
      const siblings = this.all("SELECT id FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND room_id IS NULL",
        x.viaGrant.relationship_id, x.viaGrant.grantor_owner, x.viaGrant.grantee_bot);
      const ids = siblings.length ? siblings.map((s: any) => s.id) : [x.viaGrant.id];
      for (const gid of ids) this.recordGrantRoomUse(gid, roomId, `owner:${actorOwnerId}`, [actorOwnerId, x.bot.owner_id]);
    }
  }
  private ensurePairRoomGrant(roomId: string, a: any, b: any, actorOwnerId: string) {
    // Layer 2 of #111: the join doors already refuse a blocked pair, so this is the backstop for any path that
    // still arrives here (a seat sync, a claim). A block outlives the room it was made in; never rebuild its door.
    if (this.pairRelationships(a.id, b.id).some((r: any) => r.status === "blocked")) return;
    const hit = this.get(`SELECT g.id FROM grants g JOIN relationships r ON r.id = g.relationship_id
      WHERE g.room_id = ? AND g.status = 'active' AND r.status = 'room'
      AND ((r.requester_bot = ? AND r.target_bot = ?) OR (r.requester_bot = ? AND r.target_bot = ?))`, roomId, a.id, b.id, b.id, a.id);
    if (hit) return;
    const id = newId("rel");
    const now = nowIso();
    this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, message, requested_caps, offered_caps, created_at, updated_at, requester_scope, target_scope)
      VALUES (?,?,?,?,?,'room',?,?,?,?,?,'bot','bot')`, id, a.id, b.id, a.owner_id, b.owner_id, "face room", "[]", "[]", now, now);
    const actor = `owner:${actorOwnerId}`;
    for (const cap of DEFAULT_CAPABILITIES) {
      this.insertGrant(id, a.owner_id, b.id, cap, { kind: "room", room_id: roomId }, undefined, actor, { roomId });
      this.insertGrant(id, b.owner_id, a.id, cap, { kind: "room", room_id: roomId }, undefined, actor, { roomId });
    }
  }
  private removeFaceMember(roomId: string, m: any) {
    if (m.left_at) return;
    const now = this.ts();
    const n = this.run("UPDATE face_room_members SET left_at = ? WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", now, roomId, m.bot_id);
    if (!n.changes) return;
    const text = leaveSystemText(m.owner_name, m.display_name);
    const member = this.faceMemberPublic(m);
    const ev = this.faceInsertEvent(roomId, "member.left", m.bot_id, { text, member, trust: "platform" });
    this.emit(m.bot_id, "face_room.left", { room_id: roomId, event_id: ev.id, event_cursor: ev.seq, text, member, trust: "platform", self: true });
    this.faceEmitMembers(roomId, "face_room.left", { room_id: roomId, event_id: ev.id, event_cursor: ev.seq, text, member, trust: "platform" });
    // The chosen lead left: back to the default lead (FlyBot #476).
    if (this.get("SELECT 1 FROM face_rooms WHERE id = ? AND lead_bot_id = ?", roomId, m.bot_id)) this.faceSetLead(roomId, null, "lead_left", m.bot_id);
    this.faceCloseIfEmpty(roomId);
  }
  private endRoomGrantsForBots(roomId: string, botIds: string[]) {
    if (!botIds.length) return;
    const now = nowIso();
    const rows = this.all("SELECT * FROM grants WHERE room_id = ? AND status = 'active'", roomId);
    for (const g of rows) {
      const r = this.get("SELECT * FROM relationships WHERE id = ?", g.relationship_id);
      const granted = this.grantedBotOf(g, r);
      if (!botIds.includes(g.grantee_bot) && !botIds.includes(granted)) continue;
      this.run("UPDATE grants SET status = 'revoked', revoked_at = ? WHERE id = ?", now, g.id);
      this.audit.append("platform", "grant.revoked", g.id, [r?.requester_owner, r?.target_owner], { reason: "room_left", room_id: roomId, grantee_bot: g.grantee_bot });
    }
    if (botIds.length) {
      const marks = botIds.map(() => "?").join(",");
      this.run(`UPDATE grant_rooms SET ended_at = ? WHERE room_id = ? AND ended_at IS NULL AND grant_id IN (
        SELECT g.id FROM grants g JOIN relationships r ON r.id = g.relationship_id
        WHERE g.grantee_bot IN (${marks}) OR r.requester_bot IN (${marks}) OR r.target_bot IN (${marks}))`,
        now, roomId, ...botIds, ...botIds, ...botIds);
    }
    this.run("UPDATE relationships SET status = 'revoked', updated_at = ? WHERE status = 'room' AND id IN (SELECT relationship_id FROM grants WHERE room_id = ?) AND NOT EXISTS (SELECT 1 FROM grants g2 WHERE g2.relationship_id = relationships.id AND g2.status = 'active')", now, roomId);
  }
  private faceCloseIfEmpty(roomId: string) {
    if (this.get("SELECT COUNT(*) n FROM face_room_members WHERE room_id = ? AND left_at IS NULL", roomId).n) return;
    const now = this.ts();
    this.run("UPDATE face_rooms SET status = 'closed', closed_at = ?, code = NULL WHERE id = ?", now, roomId);
    this.run("DELETE FROM face_room_codes WHERE room_id = ?", roomId);
    for (const d of this.all("SELECT * FROM face_room_drafts WHERE room_id = ? AND status = 'pending_approval'", roomId)) {
      this.run("UPDATE face_room_drafts SET status = 'cancelled' WHERE id = ?", d.id);
      this.run("UPDATE approvals SET status = 'cancelled', decision = ?, decided_at = ? WHERE id = ? AND status = 'pending'", "room_closed", now, d.approval_id);
    }
    for (const g of this.all("SELECT * FROM grants WHERE room_id = ? AND status = 'active'", roomId)) {
      this.run("UPDATE grants SET status = 'revoked', revoked_at = ? WHERE id = ?", now, g.id);
      this.audit.append("platform", "grant.revoked", g.id, [], { reason: "room_closed", room_id: roomId });
    }
    this.run("UPDATE grant_rooms SET ended_at = ? WHERE room_id = ? AND ended_at IS NULL", now, roomId);
    this.run("UPDATE relationships SET status = 'revoked', updated_at = ? WHERE status = 'room' AND id IN (SELECT relationship_id FROM grants WHERE room_id = ?)", now, roomId);
  }
  private faceStartRoom(room: any, reason: "expired" | "start", actor?: { ownerId: string; botId?: string }) {
    if (room.status !== "candidate") return;
    const now = this.ts();
    this.run("UPDATE face_rooms SET status = 'open', started_at = ?, code = NULL WHERE id = ?", now, room.id);
    this.run("DELETE FROM face_room_codes WHERE room_id = ?", room.id);
    const text = reason === "expired"
      ? "The matching window ended. The room is now open. The number is no longer valid."
      : "The room is now open. The number is no longer valid.";
    const ev = this.faceInsertEvent(room.id, "room.started", actor?.botId ?? null, { text, reason, trust: "platform" });
    this.faceEmitMembers(room.id, "face_room.started", { room_id: room.id, event_id: ev.id, event_cursor: ev.seq, text, reason, trust: "platform" });
    this.audit.append(actor ? `owner:${actor.ownerId}` : "platform", "face_room.started", room.id, this.faceOwnerIds(room.id), { reason });
  }
  /** Promote expired candidate rooms to normal groups and void their numbers. Safe to call often. */
  advanceFaceRooms() {
    for (const r of this.all("SELECT * FROM face_rooms WHERE status = 'candidate' AND expires_at <= ?", this.ts())) this.faceStartRoom(r, "expired");
  }
  private faceRequireMember(p: Principal, roomId: string, asBot?: string) {
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    if (!room) throw new ApiError(404, "face_room_not_found", "no such room");
    const ownerId = p.ownerId;
    let sql = "SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL AND (owner_id = ? OR added_by_owner_id = ?)";
    const args: unknown[] = [roomId, ownerId, ownerId];
    if (p.kind === "bot") { sql += " AND bot_id = ?"; args.push(p.botId); }
    let members = this.all(sql, ...args);
    if (asBot) {
      const raw = handleRef(asBot);
      const exact = members.filter((m: any) => m.bot_id === asBot || String(m.handle ?? "").replace(/^@/, "") === raw);
      members = exact.length ? exact : members.filter((m: any) => handleKey(m.handle) === raw.toLowerCase());
      if (!exact.length && members.length > 1) throw ambiguous(raw, members.length);
    }
    if (!members.length) throw new ApiError(404, "face_room_not_found", "no such room");
    return { ownerId, botIds: members.map((m: any) => m.bot_id as string), members, joinSeq: Math.min(...members.map((m: any) => m.join_seq as number)), room };
  }

  /**
   * #111: a block is a decision about a Bot pair, so seating the pair in a room again must not hand back the room
   * door the block closed. Asked for the Bots about to take a seat against the ones already in the room.
   */
  private facePairBlocked(newcomers: any[], active: any[]): boolean {
    return newcomers.some((n: any) => active.some((m: any) =>
      m.bot_id !== n.id && this.pairRelationships(n.id, m.bot_id).some((r: any) => r.status === "blocked")));
  }

  /** Who made the room: stored at creation; for a room from before that, the owner whose Bot joined first. */
  private faceCreatorOf(room: any): string | null {
    if (room.created_by_owner_id) return room.created_by_owner_id;
    return this.get("SELECT owner_id FROM face_room_members WHERE room_id = ? ORDER BY join_seq ASC LIMIT 1", room.id)?.owner_id ?? null;
  }
  /**
   * The room lead (FlyBot #476): `set` is the Bot the creator picked (null until picked), `effective` the one
   * every home follows: the set lead, else the first Bot of the creator's home that joined (still in the room),
   * else the first Bot that joined.
   */
  private faceLeadOf(room: any): { set: any | null; effective: any | null } {
    const active = this.all("SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL ORDER BY join_seq ASC", room.id);
    const set = room.lead_bot_id ? active.find((m: any) => m.bot_id === room.lead_bot_id) ?? null : null;
    const creator = this.faceCreatorOf(room);
    return { set, effective: set ?? active.find((m: any) => m.owner_id === creator) ?? active[0] ?? null };
  }
  private faceLeadFields(roomId: string) {
    const lead = this.faceLeadOf(this.get("SELECT * FROM face_rooms WHERE id = ?", roomId));
    return { lead_bot_handle: lead.set?.handle ?? null, effective_lead_bot_handle: lead.effective?.handle ?? null };
  }
  /** Store the lead (null = default), and tell every member with a platform event. */
  private faceSetLead(roomId: string, botId: string | null, reason: "set" | "cleared" | "lead_left", actorBot: string | null) {
    this.run("UPDATE face_rooms SET lead_bot_id = ? WHERE id = ?", botId, roomId);
    const m = botId ? this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ?", roomId, botId) : null;
    const lead = m ? this.faceMemberPublic(m) : null;
    const data = { text: leadSystemText(lead, reason), reason, lead, ...this.faceLeadFields(roomId), trust: "platform" };
    const ev = this.faceInsertEvent(roomId, "room.lead_changed", actorBot, data);
    this.faceEmitMembers(roomId, "face_room.lead_changed", { room_id: roomId, event_id: ev.id, event_cursor: ev.seq, ...data });
  }
  private faceRoomView(roomId: string, viewer: { joinSeq?: number; ownerId?: string }, opts: { after?: number } = {}) {
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    const creator = this.faceCreatorOf(room);
    const creatorOwner = creator ? this.get("SELECT display_name, username FROM owners WHERE id = ?", creator) : null;
    const members = this.all("SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL ORDER BY joined_at", roomId).map((m: any) => this.faceMemberPublic(m, true));
    const floor = (viewer.joinSeq ?? 1) - 1;
    const after = opts.after !== undefined ? opts.after : floor;
    const events = this.all("SELECT * FROM face_room_events WHERE room_id = ? AND seq > ? ORDER BY seq ASC", roomId, after).map((e: any) => this.faceEventPublic(e));
    return {
      room_id: room.id, status: room.status, expires_at: room.expires_at, started_at: room.started_at, closed_at: room.closed_at,
      created_by: creatorOwner ? { owner_name: peerOwnerName(creatorOwner, "Owner") } : null,
      created_by_me: Boolean(creator && viewer.ownerId === creator),
      ...this.faceLeadFields(roomId),
      members, event_cursor: events.length ? events[events.length - 1].event_cursor : after, events,
    };
  }

  /**
   * Enter a 6-digit code: create a candidate room if none exists, otherwise join it.
   * Never returns room contents on failure. Race-safe (BEGIN IMMEDIATE).
   */
  joinFaceRoom(p: Principal, body: any, ctx: { ip?: string } = {}) {
    const ownerId = p.ownerId;
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const bring = this.faceBotsToBring(p, body);
    const bots = bring.map((x) => x.bot);
    const rawCode = body?.code;
    const codeOk = isFaceCode(rawCode);
    const code = codeOk ? String(rawCode).trim() : "";
    type Fail = { ok: false; status: number; code: string; message: string; extra?: Record<string, unknown>; lockout?: boolean };
    type Ok = { ok: true; created: boolean; roomId: string };
    const txn = this.db.transaction((): Ok | Fail => {
      this.advanceFaceRooms();
      const locked = this.faceLockoutUntil(ownerId, ip);
      if (locked) {
        this.faceRecordAttempt(ownerId, ip, code || String(rawCode ?? ""), "locked_out");
        return { ok: false, status: 429, code: "locked_out", message: "too many failed code attempts; try again later", extra: { retry_after: Math.max(1, Math.ceil((Date.parse(locked) - this.nowMs()) / 1000)) } };
      }
      const attemptBlock = this.faceAttemptRateLimit(ownerId, ip);
      // Refused for being over budget is not an attempt: it writes no row, or the client's own retries would
      // keep the window full. A lockout hit still writes one: that is a separate, older judgement.
      if (attemptBlock) return { ...attemptBlock };
      if (!codeOk) {
        this.faceRecordAttempt(ownerId, ip, String(rawCode ?? ""), "invalid_code");
        return { ok: false, status: 400, code: "invalid_code", message: "code must be exactly 6 digits", lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      const mapping = this.get("SELECT * FROM face_room_codes WHERE code = ?", code);
      if (!mapping) {
        const createBlock = this.faceCreateRateLimit(ownerId, ip);
        if (createBlock) return { ...createBlock };
        if (bots.length > this.faceRoomLimits.maxMembers) {
          this.faceRecordAttempt(ownerId, ip, code, "room_full");
          return { ok: false, status: 409, code: "room_full", message: `this room is full (max ${this.faceRoomLimits.maxMembers} bots); no second room is opened`, lockout: this.faceMaybeLockout(ownerId, ip) };
        }
        const id = newId("frm");
        const now = this.ts();
        const expires = new Date(this.nowMs() + this.faceRoomLimits.ttlMs).toISOString();
        this.run("INSERT INTO face_rooms (id, code, status, created_at, expires_at, created_by_owner_id) VALUES (?,?,?,?,?,?)", id, code, "candidate", now, expires, ownerId);
        this.run("INSERT INTO face_room_codes (code, room_id, expires_at) VALUES (?,?,?)", code, id, expires);
        this.faceAddMembers(id, bots, ownerId);
        this.syncFaceRoomAccess(id, bots, ownerId, bring);
        this.faceRecordAttempt(ownerId, ip, code, "created");
        return { ok: true, created: true, roomId: id };
      }
      const room = this.get("SELECT * FROM face_rooms WHERE id = ?", mapping.room_id);
      if (!room || room.status !== "candidate" || Date.parse(room.expires_at) <= this.nowMs()) {
        this.faceRecordAttempt(ownerId, ip, code, "code_void");
        return { ok: false, status: 409, code: "code_void", message: "this number is no longer valid", lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      const active = this.all("SELECT bot_id FROM face_room_members WHERE room_id = ? AND left_at IS NULL", room.id);
      const activeSet = new Set(active.map((m: any) => m.bot_id));
      const newcomers = bots.filter((b) => !activeSet.has(b.id));
      if (active.length + newcomers.length > this.faceRoomLimits.maxMembers) {
        this.faceRecordAttempt(ownerId, ip, code, "room_full");
        return { ok: false, status: 409, code: "room_full", message: `this room is full (max ${this.faceRoomLimits.maxMembers} bots); no second room is opened`, lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      if (newcomers.length && this.facePairBlocked(newcomers, active)) {
        // #111: a block closes this pair's room door, so re-entering the same number must not seat them again.
        // Refused whole, before a seat is written, in the answer this door already gives for a number that has
        // just died: a valid number is not refused this way, so the caller reads it as the room ending, not as a
        // block. The attempt is counted as the same kind of failure, so the lockout bookkeeping is unchanged.
        this.faceRecordAttempt(ownerId, ip, code, "code_void");
        return { ok: false, status: 409, code: "code_void", message: "this number is no longer valid", lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      if (newcomers.length) {
        this.faceAddMembers(room.id, newcomers, ownerId);
        this.syncFaceRoomAccess(room.id, newcomers, ownerId, bring.filter((x) => newcomers.some((n) => n.id === x.bot.id)));
      }
      this.faceRecordAttempt(ownerId, ip, code, newcomers.length ? "joined" : "rejoined");
      return { ok: true, created: false, roomId: room.id };
    });
    const out = txn.immediate();
    if (!out.ok) {
      if (out.lockout) this.audit.append(`owner:${ownerId}`, "face_room.lockout", null, [ownerId], { ip, reason: out.code });
      throw new ApiError(out.status, out.code, out.message, out.extra);
    }
    this.audit.append(`owner:${ownerId}`, out.created ? "face_room.created" : "face_room.joined", out.roomId, this.faceOwnerIds(out.roomId), { bots: bots.map((b) => b.id), ip });
    const viewer = this.faceRequireMember(p, out.roomId);
    return this.faceRoomView(out.roomId, viewer);
  }

  // ---- Room invites (Bot Social #39): a ticket for an established room, joined by link or QR.

  /** The invite row for a ticket, or null when the string is not even ticket-shaped (same answer as unknown). */
  private faceInviteOf(ticketRaw: unknown) {
    const ticket = String(ticketRaw ?? "").trim();
    if (!isInviteTicket(ticket)) return null;
    return this.get("SELECT * FROM face_room_invites WHERE ticket = ?", ticket) ?? null;
  }

  /** One of the refusals that belong to the invite itself; `room_full` / `already_member` come later, at the join. */
  private faceInviteRefusal(invite: any): { status: number; code: string; message: string } | null {
    if (!invite) return { status: 404, code: "invite_not_found", message: "this invite link is not valid" };
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", invite.room_id);
    if (!room) return { status: 404, code: "invite_not_found", message: "this invite link is not valid" };
    if (room.status === "closed") return { status: 410, code: "ended", message: "this room has ended" };
    if (invite.revoked_at) return { status: 410, code: "revoked", message: "this invite was revoked" };
    if (Date.parse(invite.expires_at) <= this.nowMs()) return { status: 410, code: "expired", message: "this invite has expired" };
    return null;
  }

  private faceInviteUrl(ticket: string) {
    return `${this.publicBaseUrl.replace(/\/$/, "")}/r/${ticket}`;
  }

  /** Only the room lead acts here: the picked lead, else the creator's first Bot still in the room. */
  private faceRequireLead(p: Principal, roomId: string, what: string) {
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    if (!room) throw new ApiError(404, "face_room_not_found", "no such room");
    const lead = this.faceLeadOf(room).effective;
    const isLead = Boolean(lead) && (p.kind === "bot" ? p.botId === lead.bot_id : p.ownerId === lead.owner_id);
    if (!isLead) throw new ApiError(403, "not_lead", `only the room lead may ${what}`);
    return room;
  }

  private faceIpRateLimit(ip: string | null, message: string, scope: string) {
    const since = new Date(this.nowMs() - this.faceRoomLimits.attemptWindowMs).toISOString();
    // Previews have their own per-address budget: a read never spends the join budget, so a client browsing
    // its own links cannot lock itself out of joining. The two sides are isolated both ways: `preview` rows are
    // written with no owner, while a join that fails on a ticket records the same refusal codes against its
    // owner (`invite_not_found`, `expired`, `revoked`, `ended`). Counting only owner-less rows here keeps those
    // failed door checks out of the read budget, exactly as the join budget's per-IP query keeps previews out
    // of its own. A mint is the invite-link budget (#69).
    const marks = FACE_PREVIEW_OUTCOMES.map(() => "?").join(",");
    if (ip && this.get(`SELECT COUNT(*) n FROM face_room_attempts WHERE ip = ? AND owner_id IS NULL AND created_at > ? AND outcome IN (${marks})`, ip, since, ...FACE_PREVIEW_OUTCOMES).n >= this.faceRoomLimits.attemptsPerIp)
      return this.faceRateFail(message, scope, this.faceRoomLimits.attemptWindowMs);
    return null;
  }

  /**
   * Mint a ticket for an existing room. The ticket is a bearer credential: it is returned once, the mint is
   * audited, and the ticket itself is never written to the audit log.
   */
  mintFaceRoomInvite(p: Principal, roomId: string, ctx: { ip?: string } = {}) {
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const viewer = this.faceRequireMember(p, roomId);
    if (viewer.room.status === "closed") throw new ApiError(410, "ended", "this room has ended");
    this.faceRequireLead(p, roomId, "mint an invite");
    const block = this.inviteMintRateLimit(p.ownerId, ip);
    if (block) throw new ApiError(block.status, block.code, block.message, block.extra);
    this.faceRecordAttempt(p.ownerId, ip, "invite", "minted");
    const ticket = newInviteTicket();
    const expiresAt = new Date(this.nowMs() + this.faceRoomLimits.inviteTtlMs).toISOString();
    this.run("INSERT INTO face_room_invites (ticket, room_id, created_by_owner_id, created_by_bot, expires_at, created_at) VALUES (?,?,?,?,?,?)",
      ticket, roomId, p.ownerId, p.kind === "bot" ? p.botId : null, expiresAt, this.ts());
    this.audit.append(`owner:${p.ownerId}`, "face_room.invite_minted", roomId, this.faceOwnerIds(roomId), { expires_at: expiresAt, ttl_seconds: Math.round(this.faceRoomLimits.inviteTtlMs / 1000) });
    return { room_id: roomId, ticket, url: this.faceInviteUrl(ticket), expires_at: expiresAt };
  }

  /**
   * Revoke a ticket now. A join that starts after this commits re-reads the ticket inside its own transaction,
   * sees `revoked` and is refused whole; a join already inside its transaction holds the write lock, so this
   * revoke lands after it and only later uses are affected.
   */
  revokeFaceRoomInvite(p: Principal, roomId: string, ticketRaw: unknown) {
    this.faceRequireMember(p, roomId);
    this.faceRequireLead(p, roomId, "revoke an invite");
    const ticket = String(ticketRaw ?? "").trim();
    const invite = this.get("SELECT * FROM face_room_invites WHERE ticket = ? AND room_id = ?", ticket, roomId);
    if (!invite) throw new ApiError(404, "invite_not_found", "this invite link is not valid");
    const revokedAt = invite.revoked_at ?? this.ts();
    if (!invite.revoked_at) {
      this.run("UPDATE face_room_invites SET revoked_at = ? WHERE ticket = ?", revokedAt, ticket);
      this.audit.append(`owner:${p.ownerId}`, "face_room.invite_revoked", roomId, this.faceOwnerIds(roomId), {});
    }
    return { room_id: roomId, revoked: true, revoked_at: revokedAt };
  }

  /** What a scanned link can show before joining: the room, its lead, how many are in it, when the ticket dies. */
  previewFaceRoomInvite(ticketRaw: unknown, ctx: { ip?: string } = {}) {
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const block = this.faceIpRateLimit(ip, "too many invite previews from this address", "invite_preview");
    if (block) throw new ApiError(block.status, block.code, block.message, block.extra);
    const invite = this.faceInviteOf(ticketRaw);
    const refusal = this.faceInviteRefusal(invite);
    // Every preview counts against the per-IP window, whether it names a real ticket or not.
    this.faceRecordAttempt(null, ip, "invite", refusal ? refusal.code : "preview");
    if (refusal) throw new ApiError(refusal.status, refusal.code, refusal.message);
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", invite!.room_id);
    const leadRow = this.faceLeadOf(room).effective;
    // The preview answers with exactly the three keys it has always returned; only the two labels are cleaned,
    // the same way `publicBot` cleans them. A read-side name fix, not a change to the response shape.
    const lead = leadRow ? { ...leadRow, display_name: peerDisplayName(leadRow.display_name, "Bot"), owner_name: peerDisplayName(leadRow.owner_name, "Owner") } : null;
    const memberCount = this.get("SELECT COUNT(*) n FROM face_room_members WHERE room_id = ? AND left_at IS NULL", room.id).n as number;
    return {
      room_id: room.id,
      // Rooms have no name of their own yet; the lead and the count identify this one.
      name: null,
      status: room.status,
      lead: lead ? { handle: lead.handle, display_name: lead.display_name, owner_name: lead.owner_name } : null,
      member_count: memberCount,
      max_members: this.faceRoomLimits.maxMembers,
      expires_at: invite.expires_at,
    };
  }

  /** Join an established room with a ticket: writes the room grants, then confirms (Bot Social #30/#31). */
  joinFaceRoomByInvite(p: Principal, body: any, ctx: { ip?: string } = {}) {
    const ownerId = p.ownerId;
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const bring = this.faceBotsToBring(p, body);
    const bots = bring.map((x) => x.bot);
    const ticket = String(body?.ticket ?? "").trim();
    type Fail = { ok: false; status: number; code: string; message: string; extra?: Record<string, unknown>; lockout?: boolean };
    type Ok = { ok: true; roomId: string };
    const txn = this.db.transaction((): Ok | Fail => {
      const locked = this.faceLockoutUntil(ownerId, ip);
      if (locked) {
        this.faceRecordAttempt(ownerId, ip, "invite", "locked_out");
        return { ok: false, status: 429, code: "locked_out", message: "too many failed invite attempts; try again later", extra: { retry_after: Math.max(1, Math.ceil((Date.parse(locked) - this.nowMs()) / 1000)) } };
      }
      const attemptBlock = this.faceAttemptRateLimit(ownerId, ip);
      if (attemptBlock) return { ...attemptBlock } as Fail;
      // BEGIN IMMEDIATE: a revoke that commits first is seen here, so the join is refused whole.
      const invite = this.faceInviteOf(ticket);
      const refusal = this.faceInviteRefusal(invite);
      if (refusal) {
        this.faceRecordAttempt(ownerId, ip, "invite", refusal.code);
        return { ok: false, ...refusal, lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      const room = this.get("SELECT * FROM face_rooms WHERE id = ?", invite!.room_id);
      const active = this.all("SELECT bot_id FROM face_room_members WHERE room_id = ? AND left_at IS NULL", room.id);
      const activeSet = new Set(active.map((m: any) => m.bot_id));
      const newcomers = bots.filter((b) => !activeSet.has(b.id));
      if (!newcomers.length) {
        this.faceRecordAttempt(ownerId, ip, "invite", "already_member");
        return { ok: false, status: 409, code: "already_member", message: "every Bot you brought is already in this room" };
      }
      if (active.length + newcomers.length > this.faceRoomLimits.maxMembers) {
        this.faceRecordAttempt(ownerId, ip, "invite", "room_full");
        return { ok: false, status: 409, code: "room_full", message: `this room is full (max ${this.faceRoomLimits.maxMembers} bots)`, lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      if (this.facePairBlocked(newcomers, active)) {
        // #111: the same rule as the code door — a block ends this pair's room doors, so the ticket must not be
        // the way back in. This door refuses a ticket that is not there for the caller with a 404, and the block
        // gets exactly that answer, word for word and counted as the same failure.
        this.faceRecordAttempt(ownerId, ip, "invite", "invite_not_found");
        return { ok: false, status: 404, code: "invite_not_found", message: "this invite link is not valid", lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      this.faceAddMembers(room.id, newcomers, ownerId);
      this.syncFaceRoomAccess(room.id, newcomers, ownerId, bring.filter((x) => newcomers.some((n) => n.id === x.bot.id)));
      this.run("UPDATE face_room_invites SET used_count = used_count + 1, last_used_at = ?, last_used_by_owner_id = ? WHERE ticket = ?", this.ts(), ownerId, ticket);
      this.faceRecordAttempt(ownerId, ip, "invite", "invited");
      return { ok: true, roomId: room.id };
    });
    const out = txn.immediate();
    if (!out.ok) {
      if (out.lockout) this.audit.append(`owner:${ownerId}`, "face_room.lockout", null, [ownerId], { ip, reason: out.code });
      throw new ApiError(out.status, out.code, out.message, out.extra);
    }
    this.audit.append(`owner:${ownerId}`, "face_room.joined", out.roomId, this.faceOwnerIds(out.roomId), { bots: bots.map((b) => b.id), ip, invite: true });
    const viewer = this.faceRequireMember(p, out.roomId);
    return this.faceRoomView(out.roomId, viewer);
  }

  // ---- Local room invites (Bot Social #60): a ticket for a room that lives in one FlyBot home.

  private localInviteOf(ticketRaw: unknown) {
    const ticket = String(ticketRaw ?? "").trim();
    if (!isLocalInviteTicket(ticket)) return null;
    return this.get("SELECT * FROM local_room_invites WHERE ticket = ?", ticket) ?? null;
  }
  /** Every home's live claim on a ticket (a link admits anyone it is given to, until withdrawn). */
  private localInviteClaims(invite: any): { owner_id: string; bots: string[]; claimed_at: string }[] {
    if (!invite) return [];
    return this.all("SELECT * FROM local_room_invite_claims WHERE ticket = ? AND released_at IS NULL ORDER BY claimed_at", invite.ticket)
      .map((c: any) => ({ owner_id: c.owner_id, bots: J(c.bots, []) as string[], claimed_at: c.claimed_at }));
  }
  /** A room member named by handle: exact `@handle` first, else the unique case-insensitive match. */
  private faceMemberByHandle(roomId: string, ref: unknown) {
    const raw = handleRef(ref);
    if (!raw) return undefined;
    const rows = this.all("SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL AND LOWER(handle) = ?", roomId, "@" + raw.toLowerCase());
    if (rows.length > 1) throw ambiguous(raw, rows.length);
    return rows[0];
  }

  private localInviteClaimOf(invite: any, ownerId: string | null) {
    if (!invite || ownerId === null) return null;
    return this.localInviteClaims(invite).find((c) => c.owner_id === ownerId) ?? null;
  }
  private localClaimView(c: { owner_id: string; bots: string[] }) {
    return {
      home: this.homeHandleOf(c.owner_id),
      bots: c.bots.map((id) => "@" + this.bot(id).handle),
      // The names the inviting home shows on each seat; the handles above are the authority.
      members: c.bots.map((id) => { const s = this.faceSnapshot(this.bot(id)); return { handle: s.handle, display_name: s.display_name, owner_name: s.owner_name }; }),
    };
  }
  /** The refusals that belong to the ticket itself, before anyone claims it. */
  private localInviteRefusal(invite: any): { status: number; code: string; message: string } | null {
    if (!invite) return { status: 404, code: "invite_not_found", message: "this invite link is not valid" };
    if (invite.revoked_at) return { status: 410, code: "revoked", message: "this invite was withdrawn" };
    // A link minted since the owner's decision has no deadline (`expires_at` is ''): it lives until it is withdrawn
    // or spent. A ticket minted with a deadline before that keeps it.
    if (invite.expires_at && Date.parse(invite.expires_at) <= this.nowMs()) return { status: 410, code: "expired", message: "this invite has expired" };
    return null;
  }
  private localInviteUrl(handle: string, ticket: string) {
    return `${this.publicBaseUrl.replace(/\/$/, "")}/r/@${String(handle).replace(/^@/, "")}/${ticket}`;
  }
  private homeHandleOf(ownerId: string): string | null {
    const home = this.get("SELECT handle FROM bots WHERE owner_id = ? AND integration_type = 'flybot-home' ORDER BY created_at LIMIT 1", ownerId);
    return home ? "@" + home.handle : null;
  }
  private localInviteView(invite: any, viewerOwnerId: string | null) {
    const inviter = this.bot(invite.inviter_bot);
    const lead = this.faceSnapshot(inviter);
    const minter = viewerOwnerId !== null && viewerOwnerId === invite.created_by_owner_id;
    const own = this.localInviteClaimOf(invite, viewerOwnerId);
    const claims = minter ? this.localInviteClaims(invite) : [];
    return {
      kind: "local_room",
      room_id: invite.room_id,
      name: invite.name || null,
      lead: { handle: lead.handle, display_name: lead.display_name, owner_name: lead.owner_name },
      inviter: { handle: lead.handle, home: this.homeHandleOf(inviter.owner_id) },
      expires_at: invite.expires_at || null,
      // Whether the caller's own home has joined with it. A link admits anyone it is given to, so nobody
      // else's claim closes it; an anonymous caller always reads false.
      claimed: own !== null,
      ...(invite.revoked_at ? { revoked: true } : {}),
      // The minting owner sees every home that joined (`claimers`; `claimer` is the latest, for older readers);
      // a claiming owner sees its own claim; nobody else sees any.
      ...(minter ? { claimers: claims.map((c) => this.localClaimView(c)), claimer: claims.length ? this.localClaimView(claims[claims.length - 1]) : null }
        : own ? { claimer: this.localClaimView(own) } : viewerOwnerId !== null ? { claimer: null } : {}),
    };
  }

  /** Mint a ticket for a room that lives in the caller's FlyBot home. Several may be live for one room at once. */
  mintLocalRoomInvite(p: Principal, body: any, ctx: { ip?: string } = {}) {
    const ownerId = p.ownerId;
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const roomId = String(body?.room_id ?? "").trim();
    assert(isLocalRoomId(roomId), 400, "invalid_request", "room_id: 1-64 chars [A-Za-z0-9._:-]");
    // A face room has its own invitation, and its grants must never be written by someone outside it.
    assert(!this.get("SELECT 1 FROM face_rooms WHERE id = ?", roomId), 409, "face_room", "this room has its own invitation");
    let inviter: any;
    if (p.kind === "bot") inviter = this.bot(p.botId);
    else {
      const ref = String(body?.bot_id ?? body?.bot_handle ?? body?.handle ?? "").trim();
      inviter = ref
        ? this.get("SELECT * FROM bots WHERE id = ? AND owner_id = ?", ref, ownerId) ?? this.botByRef(ref, "owner_id = ?", [ownerId])
        : this.get("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' AND integration_type = 'flybot-member' ORDER BY created_at LIMIT 1", ownerId)
          ?? this.get("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' ORDER BY created_at LIMIT 1", ownerId);
    }
    assert(inviter && inviter.owner_id === ownerId, 404, "bot_not_found", "no such bot on this account");
    this.assertInvitable(inviter);
    const block = this.inviteMintRateLimit(ownerId, ip);
    if (block) throw new ApiError(block.status, block.code, block.message, block.extra);
    this.faceRecordAttempt(ownerId, ip, "local", "minted");
    const ticket = newLocalInviteTicket();
    // No deadline: the owner withdraws the link, or a stranger spends it. The column is NOT NULL, so '' means none.
    const expiresAt = LOCAL_INVITE_NO_DEADLINE;
    // Shown to a stranger before they join: one line, and none of the characters a card or a fence could misread.
    const name = sanitizePeerName(body?.name, "", FACE_ROOM_NAME_MAX).replace(/[[\]"<>`@]/g, "").replace(/\s+/g, " ").trim() || null;
    this.run("INSERT INTO local_room_invites (ticket, room_id, name, created_by_owner_id, inviter_bot, expires_at, created_at) VALUES (?,?,?,?,?,?,?)",
      ticket, roomId, name, ownerId, inviter.id, expiresAt, this.ts());
    // The ticket is a bearer credential: it is returned once and never written to the audit log.
    this.audit.append(`owner:${ownerId}`, "local_room.invite_minted", roomId, [ownerId], { inviter_bot: inviter.id });
    return { kind: "local_room", ticket, url: this.localInviteUrl(inviter.handle, ticket), room_id: roomId, name, expires_at: null, inviter: { handle: "@" + inviter.handle, home: this.homeHandleOf(ownerId) } };
  }

  /** Public preview; the minting or claiming owner also sees the claimer. */
  previewLocalRoomInvite(p: Principal | null, ticketRaw: unknown, ctx: { ip?: string } = {}) {
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const block = this.faceIpRateLimit(ip, "too many invite previews from this address", "invite_preview");
    if (block) throw new ApiError(block.status, block.code, block.message, block.extra);
    const invite = this.localInviteOf(ticketRaw);
    const viewer = p && p.kind === "owner" ? p.ownerId : p && p.kind === "bot" ? p.ownerId : null;
    // The minter, or a home that joined, re-reads a ticket that had a deadline after it passed, to check a claim
    // that landed in time.
    const party = invite && viewer !== null && (viewer === invite.created_by_owner_id || this.localInviteClaimOf(invite, viewer) !== null);
    const refusal = party && !invite.revoked_at && (viewer !== invite.created_by_owner_id || this.localInviteClaims(invite).length) ? null : this.localInviteRefusal(invite);
    this.faceRecordAttempt(null, ip, "local", refusal ? refusal.code : "preview");
    if (refusal) throw new ApiError(refusal.status, refusal.code, refusal.message);
    return this.localInviteView(invite, viewer);
  }

  /**
   * Claim a ticket for the caller's home and the Bots it brings. Any number of homes may claim one ticket
   * (owner decision 2026-10-24: the link admits anyone it is given to, until withdrawn); each home once. The claim writes one room-scoped grant pair
   * per brought Bot with the inviter's Bot (relationship status 'room'): reach for `send_as_member` naming that
   * room id between exactly those two Bots, nothing else.
   */
  claimLocalRoomInvite(p: Principal, ticketRaw: unknown, body: any, ctx: { ip?: string } = {}) {
    const ownerId = p.ownerId;
    const ip = String(ctx.ip ?? "").slice(0, 80) || null;
    const refs = p.kind === "bot" ? [p.botId] : this.normalizeBotRefs(body);
    assert(refs.length >= 1, 400, "invalid_request", "bots: name at least one of your Bots to bring");
    assert(refs.length <= LOCAL_INVITE_MAX_BOTS, 400, "invalid_request", `bots: at most ${LOCAL_INVITE_MAX_BOTS}`);
    const bots: any[] = [];
    for (const ref of refs) {
      const b = this.get("SELECT * FROM bots WHERE id = ? AND owner_id = ?", ref, ownerId) ?? this.botByRef(ref, "owner_id = ?", [ownerId]);
      // A home can only bring Bots it owns: a ticket is not authority over anyone else's identity.
      assert(b, 404, "bot_not_found", `no bot matching ${ref} on this account`);
      this.assertInvitable(b);
      if (!bots.some((x) => x.id === b.id)) bots.push(b);
    }
    const wanted = bots.map((b) => b.id).sort();
    type Fail = { ok: false; status: number; code: string; message: string; extra?: Record<string, unknown>; lockout?: boolean };
    const txn = this.db.transaction((): { ok: true; invite: any; fresh: boolean } | Fail => {
      const locked = this.faceLockoutUntil(ownerId, ip);
      if (locked) {
        this.faceRecordAttempt(ownerId, ip, "local", "locked_out");
        return { ok: false, status: 429, code: "locked_out", message: "too many failed invite attempts; try again later", extra: { retry_after: Math.max(1, Math.ceil((Date.parse(locked) - this.nowMs()) / 1000)) } };
      }
      const attemptBlock = this.faceAttemptRateLimit(ownerId, ip);
      if (attemptBlock) return { ...attemptBlock } as Fail;
      const invite = this.localInviteOf(ticketRaw);
      // #111: a block ends this pair's room doors, so a local-room ticket must not become the way back in — not by
      // claiming it again after a release, and not by re-sending a claim the block already withdrew. Already
      // answered like a link that is not there for this caller; the attempt is counted as that same refusal.
      const inviterBot = invite ? this.get("SELECT * FROM bots WHERE id = ?", invite.inviter_bot) : null;
      if (inviterBot && bots.some((b) => this.pairRelationships(b.id, inviterBot.id).some((r: any) => r.status === "blocked"))) {
        this.faceRecordAttempt(ownerId, ip, "local", "invite_not_found");
        return { ok: false, status: 404, code: "invite_not_found", message: "this invite link is not valid" };
      }
      const mine = this.localInviteClaimOf(invite, ownerId);
      // The same home with the same Bots again is the usual retry (the answer was lost): it succeeds, even past an
      // older ticket's deadline, because the claim landed before it.
      if (invite && !invite.revoked_at && mine && JSON.stringify([...mine.bots].sort()) === JSON.stringify(wanted)) {
        return { ok: true, invite, fresh: false };
      }
      const refusal = this.localInviteRefusal(invite);
      if (refusal) {
        this.faceRecordAttempt(ownerId, ip, "local", refusal.code);
        return { ok: false, ...refusal, lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      // #90: a live ticket whose inviter is no longer active must not write new reach for it. Checked before the
      // claim row, so a ticket minted before the revocation cannot be claimed during or after it. A withdrawn
      // ticket keeps its own answer above (410): the revocation of the link is the more specific fact.
      if (this.bot(invite.inviter_bot).status !== "active") {
        this.faceRecordAttempt(ownerId, ip, "local", "bot_revoked");
        return { ok: false, status: 403, code: "bot_revoked", message: "the Bot that made this invite was revoked" };
      }
      // One claim per home: a home that joined brings its Bots once (another set is a second claim it must release first).
      if (mine) {
        this.faceRecordAttempt(ownerId, ip, "local", "already_claimed");
        return { ok: false, status: 409, code: "already_claimed", message: "this invite was already used for other Bots of yours" };
      }
      if (invite.created_by_owner_id === ownerId) return { ok: false, status: 409, code: "own_invite", message: "this is your own invite link" };
      const now = this.ts();
      // A home that gave its claim back (left) may come back with the same link while it is not withdrawn.
      this.run(`INSERT INTO local_room_invite_claims (ticket, owner_id, bots, claimed_at, released_at) VALUES (?,?,?,?,NULL)
        ON CONFLICT (ticket, owner_id) DO UPDATE SET bots = excluded.bots, claimed_at = excluded.claimed_at, released_at = NULL`, invite.ticket, ownerId, JSON.stringify(wanted), now);
      const inviter = this.bot(invite.inviter_bot);
      for (const b of bots) this.ensureLocalPairGrant(invite.room_id, inviter, b, ownerId);
      this.faceRecordAttempt(ownerId, ip, "local", "claimed");
      return { ok: true, invite: this.localInviteOf(invite.ticket), fresh: true };
    });
    const out = txn.immediate();
    if (!out.ok) {
      if (out.lockout) this.audit.append(`owner:${ownerId}`, "face_room.lockout", null, [ownerId], { ip, reason: out.code });
      throw new ApiError(out.status, out.code, out.message, out.extra);
    }
    const invite = out.invite;
    if (out.fresh) this.audit.append(`owner:${ownerId}`, "local_room.invite_claimed", invite.room_id, [ownerId, invite.created_by_owner_id], { inviter_bot: invite.inviter_bot, bots: wanted });
    const inviter = this.bot(invite.inviter_bot);
    return {
      ...this.localInviteView(invite, ownerId),
      claimed: true,
      claimer: this.localClaimView({ owner_id: ownerId, bots: wanted }),
      inviter: { handle: "@" + inviter.handle, home: this.homeHandleOf(inviter.owner_id) },
      bots: wanted.map((id) => "@" + this.bot(id).handle),
    };
  }

  /**
   * The minting owner withdraws the ticket: nobody new can join with it, and the homes that already joined keep
   * their seats (owner decision 2026-10-24) unless `endClaims` (the room is gone) ends every claim's reach too.
   * A claiming owner releases its own claim, which ends the reach that claim wrote.
   */
  revokeLocalRoomInvite(p: Principal, ticketRaw: unknown, opts: { endClaims?: boolean } = {}) {
    const ownerId = p.ownerId;
    const invite = this.localInviteOf(ticketRaw);
    if (!invite) throw new ApiError(404, "invite_not_found", "this invite link is not valid");
    const minter = invite.created_by_owner_id === ownerId;
    const own = minter ? null : this.localInviteClaimOf(invite, ownerId);
    if (!minter && !own) throw new ApiError(invite.revoked_at ? 404 : 403, invite.revoked_at ? "invite_not_found" : "forbidden", invite.revoked_at ? "this invite link is not valid" : "only the owner who made this link, or one who used it, can end it");
    if (minter && invite.revoked_at && !opts.endClaims) throw new ApiError(404, "invite_not_found", "this invite link is not valid");
    const now = this.ts();
    const ended = minter ? (opts.endClaims ? this.localInviteClaims(invite) : []) : [own!];
    if (minter && !invite.revoked_at) this.run("UPDATE local_room_invites SET revoked_at = ? WHERE ticket = ?", now, invite.ticket);
    for (const c of ended) {
      this.run("UPDATE local_room_invite_claims SET released_at = ? WHERE ticket = ? AND owner_id = ?", now, invite.ticket, c.owner_id);
      this.endLocalPairGrants(invite.room_id, invite.inviter_bot, c.bots);
    }
    this.audit.append(`owner:${ownerId}`, minter ? "local_room.invite_revoked" : "local_room.invite_released", invite.room_id, [invite.created_by_owner_id, ...ended.map((c) => c.owner_id)], minter ? { ended_claims: ended.length } : {});
  }

  /** The minting owner ends one home's claim (it removed that guest): that home's reach in the room ends, the link stays. `home` is the home's handle or one of its claimed Bots' handles. */
  endLocalRoomInviteClaim(p: Principal, ticketRaw: unknown, homeRaw: unknown) {
    const invite = this.localInviteOf(ticketRaw);
    if (!invite) throw new ApiError(404, "invite_not_found", "this invite link is not valid");
    if (invite.created_by_owner_id !== p.ownerId) throw new ApiError(403, "forbidden", "only the owner who made this link can end a claim on it");
    // The home's own handle, or the handle of a Bot that home brought: either names whose claim to end.
    const handle = String(homeRaw ?? "").trim().replace(/^@/, "");
    const home = handle ? this.botByRef(handle) ?? null : null;
    const claim = home ? this.localInviteClaimOf(invite, home.owner_id) : null;
    if (!claim) throw new ApiError(404, "claim_not_found", "no home joined with this link under that handle");
    this.run("UPDATE local_room_invite_claims SET released_at = ? WHERE ticket = ? AND owner_id = ?", this.ts(), invite.ticket, claim.owner_id);
    this.endLocalPairGrants(invite.room_id, invite.inviter_bot, claim.bots);
    this.audit.append(`owner:${p.ownerId}`, "local_room.claim_ended", invite.room_id, [p.ownerId, claim.owner_id], {});
  }

  private ensureLocalPairGrant(roomId: string, inviter: any, guest: any, actorOwnerId: string) {
    // Layer 2 of #111, the local-room twin of `ensurePairRoomGrant`: never rebuild a blocked pair's door.
    if (this.pairRelationships(guest.id, inviter.id).some((r: any) => r.status === "blocked")) return;
    const hit = this.get(`SELECT g.id FROM grants g JOIN relationships r ON r.id = g.relationship_id
      WHERE g.room_id = ? AND g.status = 'active' AND r.status = 'room'
      AND ((r.requester_bot = ? AND r.target_bot = ?) OR (r.requester_bot = ? AND r.target_bot = ?))`, roomId, inviter.id, guest.id, guest.id, inviter.id);
    if (hit) return;
    const id = newId("rel");
    const now = nowIso();
    this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, message, requested_caps, offered_caps, created_at, updated_at, requester_scope, target_scope)
      VALUES (?,?,?,?,?,'room',?,?,?,?,?,'bot','bot')`, id, guest.id, inviter.id, guest.owner_id, inviter.owner_id, "local room", "[]", "[]", now, now);
    const actor = `owner:${actorOwnerId}`;
    for (const cap of DEFAULT_CAPABILITIES) {
      this.insertGrant(id, inviter.owner_id, guest.id, cap, { kind: "room", room_id: roomId }, undefined, actor, { roomId });
      this.insertGrant(id, guest.owner_id, inviter.id, cap, { kind: "room", room_id: roomId }, undefined, actor, { roomId });
    }
  }
  private endLocalPairGrants(roomId: string, inviterBot: string, guests: string[]) {
    const now = nowIso();
    for (const guest of guests) {
      const rels = this.all(`SELECT id FROM relationships WHERE status = 'room' AND ((requester_bot = ? AND target_bot = ?) OR (requester_bot = ? AND target_bot = ?))
        AND id IN (SELECT relationship_id FROM grants WHERE room_id = ?)`, guest, inviterBot, inviterBot, guest, roomId);
      for (const r of rels) {
        // Another live claim on the same room may still seat this pair (a second link for the same Bot): keep it.
        if (this.localPairClaim(roomId, inviterBot, guest, r.id)) continue;
        for (const g of this.all("SELECT * FROM grants WHERE relationship_id = ? AND room_id = ? AND status = 'active'", r.id, roomId)) {
          this.run("UPDATE grants SET status = 'revoked', revoked_at = ? WHERE id = ?", now, g.id);
          this.audit.append("platform", "grant.revoked", g.id, [], { reason: "local_invite_ended", room_id: roomId });
        }
        this.run("UPDATE relationships SET status = 'revoked', updated_at = ? WHERE id = ?", now, r.id);
      }
    }
  }
  /**
   * A live claim (not released) that seats this pair in this local room. A withdrawn link keeps the seats it
   * already made (owner decision 2026-10-24); ending a claim, or the room, is what ends one.
   */
  private localPairClaim(roomId: string, a: string, b: string, _relId?: string) {
    const rows = this.all(`SELECT i.inviter_bot, c.bots FROM local_room_invites i JOIN local_room_invite_claims c ON c.ticket = i.ticket
      WHERE i.room_id = ? AND c.released_at IS NULL AND i.inviter_bot IN (?, ?)`, roomId, a, b);
    return rows.find((row: any) => {
      const guests = J(row.bots, []) as string[];
      return (row.inviter_bot === a && guests.includes(b)) || (row.inviter_bot === b && guests.includes(a));
    }) ?? null;
  }

  getFaceRoom(p: Principal, roomId: string, opts: { after?: number; as_bot?: string } = {}) {
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId, opts.as_bot);
    const floor = viewer.joinSeq - 1;
    const after = Math.max(Number(opts.after ?? 0) || 0, floor);
    return this.faceRoomView(roomId, viewer, { after });
  }

  listFaceRooms(p: Principal) {
    this.advanceFaceRooms();
    const ownerId = p.ownerId;
    const extra = p.kind === "bot" ? "AND m.bot_id = ?" : "";
    const args: unknown[] = p.kind === "bot" ? [ownerId, ownerId, p.botId] : [ownerId, ownerId];
    const rows = this.all(`SELECT r.id, r.status, r.expires_at, r.started_at, COUNT(DISTINCT m2.bot_id) member_count
      FROM face_rooms r
      JOIN face_room_members m ON m.room_id = r.id AND (m.owner_id = ? OR m.added_by_owner_id = ?) AND m.left_at IS NULL ${extra}
      LEFT JOIN face_room_members m2 ON m2.room_id = r.id AND m2.left_at IS NULL
      WHERE r.status != 'closed'
      GROUP BY r.id ORDER BY r.created_at DESC`, ...args);
    return {
      rooms: rows.map((r: any) => ({
        room_id: r.id, status: r.status, expires_at: r.expires_at, started_at: r.started_at, member_count: r.member_count,
        my_bots: this.all("SELECT m.handle, m.display_name, b.avatar, b.color, b.avatar_updated_at FROM face_room_members m JOIN bots b ON b.id = m.bot_id WHERE m.room_id = ? AND (m.owner_id = ? OR m.added_by_owner_id = ?) AND m.left_at IS NULL", r.id, ownerId, ownerId)
          .map((m: any) => ({ handle: m.handle, display_name: peerDisplayName(m.display_name, "Bot"), ...lookOf(m) })),
      })),
    };
  }

  startFaceRoom(p: Principal, roomId: string) {
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId);
    this.db.transaction(() => {
      const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
      if (room.status === "closed") throw new ApiError(409, "room_closed", "this room is closed");
      if (room.status === "candidate") this.faceStartRoom(room, "start", { ownerId: viewer.ownerId, botId: viewer.botIds[0] });
    }).immediate();
    return this.faceRoomView(roomId, viewer);
  }

  leaveFaceRoom(p: Principal, roomId: string, body: any = {}) {
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId);
    // Only the caller's own Bots leave. A brought guest is the other owner's seat even though this owner
    // added it, and the other owner ends it by revoking the grant (or leaving with their own token).
    let leaving = viewer.members.filter((m: any) => m.owner_id === p.ownerId);
    const refs = this.normalizeBotRefs(body);
    if (refs.length) {
      for (const r of refs) {
        const raw = handleRef(r);
        if (leaving.some((m: any) => m.bot_id === r)) continue;
        if (leaving.some((m: any) => String(m.handle ?? "").replace(/^@/, "") === raw)) continue;
        const ci = leaving.filter((m: any) => handleKey(m.handle) === raw.toLowerCase());
        if (ci.length > 1) throw ambiguous(raw, ci.length);
      }
      leaving = leaving.filter((m: any) => refs.some((r) => m.bot_id === r || handleKey(m.handle) === handleKey(r)));
      assert(leaving.length, 404, "bot_not_found", "none of your Bots are in this room");
    }
    this.db.transaction(() => {
      for (const m of leaving) this.removeFaceMember(roomId, m);
      this.endRoomGrantsForBots(roomId, leaving.map((m: any) => m.bot_id));
    }).immediate();
    this.audit.append(`owner:${viewer.ownerId}`, "face_room.left", roomId, this.faceOwnerIds(roomId, true), { bots: leaving.map((m: any) => m.bot_id) });
    const still = this.get("SELECT 1 FROM face_room_members WHERE room_id = ? AND owner_id = ? AND left_at IS NULL", roomId, viewer.ownerId);
    if (!still) return { room_id: roomId, status: this.get("SELECT status FROM face_rooms WHERE id = ?", roomId).status, left: leaving.map((m: any) => m.handle) };
    return this.faceRoomView(roomId, this.faceRequireMember(p, roomId));
  }

  /**
   * Pick the room lead (FlyBot #476). Only the room creator, with an owner token (a person's UI action, never a
   * Bot token); `bot` must be a Bot in the room now; null / "" goes back to the default lead.
   */
  setFaceRoomLead(p: Principal, roomId: string, body: any = {}) {
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId);
    assert(p.kind === "owner", 403, "forbidden", "only the room creator picks the lead, from their own app; a Bot token cannot");
    assert(this.faceCreatorOf(viewer.room) === viewer.ownerId, 403, "not_room_creator", "only the person who created this room picks its lead");
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    if (room.status === "closed") throw new ApiError(409, "room_closed", "this room is closed");
    const raw = body?.bot ?? body?.bot_handle ?? body?.handle ?? body?.bot_id ?? null;
    let botId: string | null = null;
    if (raw !== null && raw !== undefined && String(raw).trim() !== "") {
      const ref = String(raw).trim();
      const m = this.get("SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL AND (bot_id = ? OR handle = ?)", roomId, ref, "@" + handleRef(ref))
        ?? this.faceMemberByHandle(roomId, ref);
      assert(m, 400, "bot_not_in_room", "that Bot is not in this room now");
      botId = m.bot_id;
    }
    if ((room.lead_bot_id ?? null) !== botId) {
      this.db.transaction(() => this.faceSetLead(roomId, botId, botId ? "set" : "cleared", viewer.botIds[0] ?? null)).immediate();
      this.audit.append(`owner:${viewer.ownerId}`, "face_room.lead_changed", roomId, this.faceOwnerIds(roomId), { lead_bot: botId });
    }
    return this.faceRoomView(roomId, viewer);
  }

  /**
   * Role labels of your own Bots in a room (FlyBot #476 roster): `{ roles: { "<handle or bot id>": "Writer" | null } }`.
   * Plain text, sanitized like a name and capped at 80; shown to every member as untrusted data. No room event.
   */
  setFaceRoomRoles(p: Principal, roomId: string, body: any = {}) {
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId);
    const roles = body?.roles;
    assert(roles && typeof roles === "object" && !Array.isArray(roles) && Object.keys(roles).length > 0 && Object.keys(roles).length <= this.faceRoomLimits.maxMembers,
      400, "invalid_request", "roles must be an object of your Bots in this room: { \"@handle\": \"role\" | null }");
    const changes: [string, string | null][] = [];
    // Role labels belong to the Bot's owner, even when someone else brought the Bot into the room.
    const ownMembers = viewer.members.filter((m: any) => m.owner_id === p.ownerId);
    for (const [ref, value] of Object.entries(roles)) {
      const m = ownMembers.find((x: any) => x.bot_id === ref) ?? pickByHandle(ownMembers, ref);
      assert(m, 404, "bot_not_found", `${ref} is not one of your Bots in this room`);
      assert(value === null || typeof value === "string", 400, "invalid_request", "a role is a string or null");
      changes.push([m.bot_id, value === null ? null : sanitizePeerName(value, "", FACE_ROOM_ROLE_MAX) || null]);
    }
    this.db.transaction(() => { for (const [botId, role] of changes) this.run("UPDATE face_room_members SET role = ? WHERE room_id = ? AND bot_id = ?", role, roomId, botId); }).immediate();
    return this.faceRoomView(roomId, viewer);
  }

  draftFaceRoomMessage(p: Principal, roomId: string, body: { text?: string; bot_id?: string; bot?: string; typed_by_owner?: boolean; mentions?: string[] | null } = {}) {
    const typed = this.typedByOwner(p, body);
    const mentions = this.mentionList(body?.mentions);
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId, body.bot_id ?? body.bot);
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    if (room.status === "closed") throw new ApiError(409, "room_closed", "this room is closed");
    const text = String(body?.text ?? "");
    assert(text.length > 0 && text.length <= 4000, 400, "invalid_request", "text (1-4000 chars) required");
    // A room can contain a Bot another owner brought with a grant (added_by_owner_id = this owner). That
    // lets the bringer see and manage the seat, never speak as that Bot: only its own owner may send.
    const own = viewer.members.filter((m: any) => m.owner_id === p.ownerId);
    assert(own.length, 403, "forbidden", "you can only send as your own Bot");
    const sender = this.bot(own[0].bot_id);
    // The kill switch stops this Bot's outbound side here too: a stopped Bot's owner typing in its name is the
    // same act as the home page's send-as-member (#196), and it must name the stop, not queue a card that the
    // approval door will later kill as "revoked".
    this.assertInvitable(sender);
    const flags = this.dlp(sender.owner_id, { text });
    const blocked = flags.filter((f) => f.action === "block");
    if (blocked.length) throw new ApiError(422, "dlp_blocked", "outbound DLP blocked this draft", { categories: blocked.map((b) => b.category) });
    const minuteAgo = this.nowMs() - 60e3, hourAgo = this.nowMs() - 3600e3;
    if (this.get("SELECT COUNT(*) n FROM face_room_drafts WHERE room_id = ? AND sender_bot = ? AND created_ms > ?", roomId, sender.id, minuteAgo).n >= LIMITS.ratePerConversationPerMin)
      throw new ApiError(429, "rate_limited", "per-room rate limit (6/min)", { retry_after: 60 });
    if (this.get("SELECT COUNT(*) n FROM face_room_drafts WHERE sender_bot = ? AND created_ms > ?", sender.id, hourAgo).n >= LIMITS.ratePerBotPerHour)
      throw new ApiError(429, "rate_limited", "global bot rate limit (60/h)", { retry_after: 3600 });
    const id = newId("fmd");
    // Only people in the room can be mentioned in it; handles that are not (or no longer) members are dropped.
    // Checked again when the line is delivered, since a member can leave while it waits for approval.
    const kept = this.roomMentions(roomId, mentions);
    const reasons = ["mvp.all_outbound_requires_approval", ...flags.map((f) => `dlp.${f.category}`)];
    // #49: face-room drafts carry no attachments, so the field is risk, policy or the room's own switch.
    // Nothing else holding the line means `auto_approve_face_rooms` is off, and that card is the owner's:
    // name it apart from the blanket hold a connector may decide.
    const injectionSuspected = detectInjection(text).suspected;
    const found = holdReasonOf({ riskFlags: flags, injectionSuspected });
    const holdReason: HoldReason = found === "blanket_outbound" ? "face_room_auto_send_off" : found;
    const snap = this.faceSnapshot(sender);
    const aprId = this.createApproval(sender.owner_id, "face_room_message", id, sender.id, null, `To face room: ${text.slice(0, 80)}`, reasons, flags, LIMITS.approvalTtlMs, { room_id: roomId }, holdReason);
    this.run("INSERT INTO face_room_drafts (id, room_id, sender_bot, payload, status, approval_id, created_at, created_ms, typed_by_owner, mentions) VALUES (?,?,?,?,?,?,?,?,?,?)",
      id, roomId, sender.id, JSON.stringify({ text }), "pending_approval", aprId, this.ts(), this.nowMs(), typed ? 1 : 0, kept.length ? JSON.stringify(kept) : null);
    this.audit.append(`bot:${sender.id}`, "face_room.message_drafted", id, this.faceOwnerIds(roomId), { room_id: roomId, approval_id: aprId });
    const o = this.owner(sender.owner_id);
    if (o.auto_approve_face_rooms && flags.length === 0 && !injectionSuspected) {
      this.decideApproval({ kind: "owner", ownerId: sender.owner_id }, aprId, { decision: "approved" }, "policy:auto_approve");
      const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", id);
      return { message_id: id, status: "delivered", approval_id: aprId, event_cursor: d.event_seq, auto_approved: true, ...(typed ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), from: snap };
    }
    return { message_id: id, status: "pending_approval", approval_id: aprId, hold_reason: holdReason, ...(typed ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), from: snap };
  }

  /** What an owner's edit may set on a held face-room line: its text, parsed and bounded before anything is written. */
  private static faceRoomEdit(ep: any): { text: string } {
    assert(ep && typeof ep === "object" && !Array.isArray(ep), 400, "invalid_request", "edited_payload must be an object");
    assert(typeof ep.text === "string" && ep.text.length >= 1 && ep.text.length <= 4000, 400, "invalid_request", "edited_payload.text (1-4000 chars) required");
    return { text: ep.text };
  }

  private deliverFaceRoomMessage(a: any, body: any) {
    const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", a.subject_id);
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", d.room_id);
    assert(room && room.status !== "closed", 409, "room_closed", "this room is closed");
    let payload = J(d.payload);
    if (body.decision === "approved_with_edits" && body.edited_payload) {
      // A draft's payload is `{ text }`: an edit replaces it, it is never folded in. Spreading the request let a
      // non-string or a 5000-character line reach `untrusted_content.text`, and a bare string spread into "0","1",…
      // The draft door already holds this window (1-4000); the edit door must not widen it.
      payload = Platform.faceRoomEdit(body.edited_payload);
      const blocked = this.dlp(this.bot(d.sender_bot).owner_id, payload).filter((f) => f.action === "block");
      assert(!blocked.length, 422, "dlp_blocked", "edited payload blocked by DLP", { categories: blocked.map((b) => b.category) });
    }
    const edited = body.decision === "approved_with_edits" && !!body.edited_payload; // the list described the typed text; an edited line carries none
    // Membership is re-checked now: a mentioned Bot that left while the line waited is dropped. What is stored is what is delivered.
    const listed = edited ? [] : this.roomMentions(d.room_id, mentionsOf(d.mentions));
    if (d.mentions) this.run("UPDATE face_room_drafts SET mentions = ? WHERE id = ?", listed.length ? JSON.stringify(listed) : null, d.id);
    const still = this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", d.room_id, d.sender_bot);
    assert(still, 409, "not_a_member", "sender is no longer in the room");
    const snap = this.faceMemberPublic(still);
    const inj = detectInjection(String(payload.text ?? ""));
    const ev = this.faceInsertEvent(d.room_id, "room.message", d.sender_bot, {
      from: snap, trust: "peer_untrusted", untrusted_content: { text: payload.text },
      security: { injection_suspected: inj.suspected }, edited_by_owner: body.decision === "approved_with_edits",
      ...(d.typed_by_owner ? { typed_by_owner: true } : {}),
      ...(listed.length ? { mentions: listed } : {}),
    });
    this.run("UPDATE face_room_drafts SET status = 'delivered', event_seq = ? WHERE id = ?", ev.seq, d.id);
    this.faceEmitMembers(d.room_id, "face_room.message", {
      room_id: d.room_id, event_id: ev.id, event_cursor: ev.seq, message_id: d.id,
      from: snap, trust: "peer_untrusted", untrusted_content: { text: payload.text },
      security: { injection_suspected: inj.suspected },
      ...(d.typed_by_owner ? { typed_by_owner: true } : {}),
      ...(listed.length ? { mentions: listed } : {}),
    });
    this.emit(d.sender_bot, "approval.decided", { approval_id: a.id, kind: "face_room_message", message_id: d.id, room_id: d.room_id, decision: body.decision, note_to_bot: body.note_to_bot ?? null });
    this.audit.append("platform", "face_room.message_delivered", d.id, this.faceOwnerIds(d.room_id), { room_id: d.room_id, event_seq: ev.seq });
    return { message_id: d.id, status: "delivered", event_cursor: ev.seq };
  }
  private rejectFaceRoomMessage(a: any, note?: string) {
    const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", a.subject_id);
    this.run("UPDATE face_room_drafts SET status = 'rejected' WHERE id = ?", d.id);
    this.emit(d.sender_bot, "approval.decided", { approval_id: a.id, kind: "face_room_message", message_id: d.id, room_id: d.room_id, decision: "rejected", note_to_bot: note ?? null });
    return { message_id: d.id, status: "rejected" };
  }

  // ================================================================ presence ("thinking")
  /** The Bot a presence call acts as: an owner names one of theirs (or has one), a Bot token is only itself. */
  private presenceBot(p: Principal, ref?: unknown) {
    const want = String(ref ?? "").replace(/^@/, "");
    let b: any;
    if (p.kind === "bot") {
      b = this.bot(p.botId);
      assert(!want || want === b.id || want.toLowerCase() === String(b.handle).replace(/^@/, "").toLowerCase(), 403, "forbidden", "a bot token can only act as itself");
    } else {
      const ownerId = this.requireOwner(p);
      b = want
        ? this.get("SELECT * FROM bots WHERE id = ?", want) ?? this.botByRef(want)
        : this.get("SELECT * FROM bots WHERE owner_id = ? AND status = 'active' ORDER BY created_at LIMIT 1", ownerId);
      assert(b, 404, "bot_not_found", "no such bot");
      assert(b.owner_id === ownerId, 403, "forbidden", "not your bot");
    }
    assert(b.status === "active", 403, b.status === "frozen" ? "bot_frozen" : "bot_revoked",
      b.status === "frozen" ? "bot is frozen (emergency stop)" : "this bot identity was revoked");
    return b;
  }

  /**
   * Say that one of my Bots is thinking toward a peer Bot (`to`) or a face room (`room_id`), or that it stopped.
   * Ephemeral and content-free. Allowed only where the Bot could already send: an active relationship, or an open room it is in.
   */
  setPresence(p: Principal, body: { bot_id?: string; state?: string; to?: string; room_id?: string; ttl_seconds?: number } = {}) {
    const state = body?.state;
    assert(state === "thinking" || state === "idle", 400, "invalid_request", "state must be \"thinking\" or \"idle\"");
    const to = body?.to === undefined || body?.to === null ? "" : String(body.to);
    const roomId = body?.room_id === undefined || body?.room_id === null ? "" : String(body.room_id);
    assert(!!to !== !!roomId, 400, "invalid_request", "exactly one of to (a Bot handle) or room_id is required");
    let ttl = PRESENCE_DEFAULT_TTL_S;
    if (body?.ttl_seconds !== undefined && body?.ttl_seconds !== null) {
      assert(typeof body.ttl_seconds === "number" && Number.isFinite(body.ttl_seconds), 400, "invalid_request", "ttl_seconds must be a number");
      ttl = Math.min(PRESENCE_MAX_TTL_S, Math.max(PRESENCE_MIN_TTL_S, Math.round(body.ttl_seconds)));
    }
    const me = this.presenceBot(p, body?.bot_id);
    let target: { toBot?: string; roomId?: string };
    if (to) {
      const peer = this.get("SELECT * FROM bots WHERE id = ? AND status = 'active'", to) ?? this.botByRef(to, "status = 'active'");
      assert(peer, 404, "bot_not_found", "no such remote bot");
      // Same gate as sending, but a refused signal is not an audit event: it is not content and can repeat.
      assert(this.findActiveRelationship(me.id, peer.id), 403, "no_relationship", "no active relationship between these bots");
      target = { toBot: peer.id };
    } else {
      this.advanceFaceRooms();
      const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
      const member = room && this.get("SELECT 1 FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", roomId, me.id);
      assert(room && member, 404, "face_room_not_found", "no such room");
      assert(room.status === "open", 409, room.status === "closed" ? "room_closed" : "room_not_started", `room is ${room.status}`);
      target = { roomId };
    }
    assert(this.presence.allow(me.id, this.nowMs()), 429, "rate_limited", `presence rate limit (${PRESENCE_WRITES_PER_MIN}/min per bot)`, { retry_after: 10 });
    if (state === "idle") { this.presence.clear({ botId: me.id, ...target }); return { ok: true, state: "idle" }; }
    const expires = this.presence.set({ botId: me.id, ...target, state: "thinking" }, ttl * 1000, this.nowMs());
    return { ok: true, state: "thinking", expires_at: new Date(expires).toISOString() };
  }

  /**
   * Who is thinking toward me: other people's Bots that are thinking toward one of my Bots (direct) or in a face room I am in.
   * Never my own Bots, never anyone I could not already hear from; relationship and membership are checked now, not when it was set.
   */
  listPresence(p: Principal, opts: { bot_id?: string; room_id?: string } = {}) {
    const viewerOwner = p.ownerId;
    const mine: any[] = p.kind === "bot"
      ? [this.presenceBot(p, opts?.bot_id)]
      : opts?.bot_id ? [this.presenceBot(p, opts.bot_id)] : this.all("SELECT * FROM bots WHERE owner_id = ? AND status = 'active'", viewerOwner);
    const mineIds = new Set(mine.map((b) => b.id as string));
    const handle = (h: string) => "@" + String(h).replace(/^@/, "");
    const out: any[] = [];
    const now = this.nowMs();
    this.advanceFaceRooms();
    for (const e of this.presence.live(now)) {
      const writer = this.get("SELECT * FROM bots WHERE id = ?", e.botId);
      if (!writer || writer.status !== "active" || writer.owner_id === viewerOwner) continue;
      if (e.toBot) {
        if (opts?.room_id || !mineIds.has(e.toBot) || !this.findActiveRelationship(e.botId, e.toBot)) continue;
        const peer = this.bot(e.toBot);
        out.push({ scope: "direct", bot: { handle: handle(writer.handle), display_name: sanitizePeerName(writer.display_name, "Bot") }, to: handle(peer.handle), state: e.state, expires_at: new Date(e.expiresMs).toISOString() });
      } else if (e.roomId) {
        if (opts?.room_id && opts.room_id !== e.roomId) continue;
        const room = this.get("SELECT status FROM face_rooms WHERE id = ?", e.roomId);
        const member = room?.status === "open" && this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", e.roomId, e.botId);
        if (!member) continue;
        const sees = this.all("SELECT bot_id FROM face_room_members WHERE room_id = ? AND left_at IS NULL AND (owner_id = ? OR added_by_owner_id = ?)", e.roomId, viewerOwner, viewerOwner)
          .some((m: any) => p.kind !== "bot" || m.bot_id === p.botId);
        if (!sees) continue;
        out.push({ scope: "face_room", room_id: e.roomId, bot: { handle: handle(member.handle), display_name: sanitizePeerName(member.display_name, "Bot") }, state: e.state, expires_at: new Date(e.expiresMs).toISOString() });
      }
    }
    return { presence: out, server_time: this.ts() };
  }

  platformInfo() {
    return { name: "Bot Social", version: "0.1.0", policy_version: POLICY_VERSION, platform_key: { alg: "Ed25519", kid: this.platformKid, public_key: this.platformKey.publicKey }, capabilities: CAPABILITIES, intents: INTENTS, features: ["typed_by_owner", "mentions", "presence", "reply_only_grants", "grants_before_join", "report_not_delivered", "room_lead", "member_roles", "face_room_invites", "local_room_invites"] };
  }
}
