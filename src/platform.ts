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
import { isoInTz, localMinutes, localWeekday, overlaps, parseHours } from "./time.js";
import {
  FaceRoomLimits, isFaceCode, joinSystemText, leaveSystemText, loadFaceRoomLimits, memberLabel, sanitizePeerName,
} from "./face-rooms.js";

export type Principal = { kind: "owner"; ownerId: string; scope?: "connector"; tokenId?: string; attestTyped?: boolean } | { kind: "bot"; botId: string; ownerId: string };

export interface PlatformOptions { kmsKey?: Buffer; dbPath?: string; auditPath?: string; publicBaseUrl?: string; fetchImpl?: typeof fetch; webhooks?: WebhookOptions; attachments?: Partial<AttachmentLimits>; now?: () => number; faceRooms?: Partial<FaceRoomLimits> }

const nowIso = () => new Date().toISOString();
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
    const b = this.get("SELECT * FROM bots WHERE handle = ?", handle.replace(/^@/, ""));
    assert(b, 404, "bot_not_found", `bot ${handle} not found`);
    return b;
  }
  owner(id: string) {
    const o = this.get("SELECT * FROM owners WHERE id = ?", id);
    assert(o, 404, "owner_not_found");
    return o;
  }
  /** `look` adds avatar/color. Opt-in per call site: only places where the viewer may already see the Bot
   *  (own bots, active friends, grants, profile.read); never events, messages, invites or pending requests. */
  private publicBot(b: any, look = false) {
    const o = this.owner(b.owner_id);
    return { bot_id: b.id, handle: "@" + b.handle, display_name: b.display_name, owner_display_name: o.display_name, owner_verified: true, ...(look ? lookOf(b) : {}) };
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
    const id = newId("own");
    this.run("INSERT INTO owners (id, username, display_name, password_hash, timezone, created_at) VALUES (?,?,?,?,?,?)",
      id, body.username, body.display_name || body.username, hashPassword(body.password), body.timezone || "Asia/Shanghai", nowIso());
    this.audit.append(`owner:${id}`, "owner.registered", id, [id], { username: body.username });
    return { owner_id: id, owner_token: this.issueToken("owner", id) };
  }

  login(body: { username: string; password: string }) {
    const o = this.get("SELECT * FROM owners WHERE username = ?", body?.username);
    if (!o || !checkPassword(String(body.password ?? ""), o.password_hash)) throw new ApiError(401, "invalid_credentials");
    this.audit.append(`owner:${o.id}`, "owner.login", o.id, [o.id]);
    return { owner_id: o.id, owner_token: this.issueToken("owner", o.id) };
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
    const handle = String(body.bot_handle || `${body.username}.bot`).replace(/^@/, "");
    assert(/^[a-z0-9._-]{2,40}$/i.test(handle), 400, "invalid_request", "bot handle: 2-40 chars [a-z0-9._-]");
    assert(!this.get("SELECT 1 FROM bots WHERE handle = ?", handle), 409, "handle_taken");
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
    const home = this.get("SELECT * FROM bots WHERE (id = ? OR handle = ?) AND owner_id = ?", homeId, String(homeId).replace(/^@/, ""), ownerId);
    assert(home && home.integration_type === "flybot-home", 404, "home_not_found", "no FlyBot home with that id for this owner");
    return home;
  }

  /** Registers (or reactivates) a local FlyBot Bot as @<name>.<home>, its key custodied with the home. */
  addHomeMember(p: Principal, homeId: string, body: { name?: string; display_name?: string; local_id?: string; avatar?: string | null; color?: string | null }) {
    const ownerId = this.requireOwner(p);
    const home = this.ownHome(ownerId, homeId);
    const look = { avatar: body?.avatar !== undefined ? validateAvatar(body.avatar) : undefined, color: body?.color !== undefined ? validateColor(body.color) : undefined };
    const room = 40 - home.handle.length - 1;
    assert(room >= 2, 400, "invalid_request", "home handle too long for members");
    const name = String(body?.name ?? "").toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, room);
    assert(name.length >= 1, 400, "invalid_request", "member name required");
    const handle = `${name}.${home.handle}`;
    const existing = this.get("SELECT * FROM bots WHERE handle = ?", handle);
    if (existing) {
      assert(existing.home_bot_id === home.id, 409, "handle_taken");
      this.run("UPDATE bots SET status = 'active', display_name = ? WHERE id = ?", body?.display_name || existing.display_name, existing.id);
      this.applyLook(existing.id, look);
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
    const m = this.get("SELECT * FROM bots WHERE (id = ? OR handle = ?) AND home_bot_id = ?", memberId, String(memberId).replace(/^@/, ""), home.id);
    assert(m, 404, "member_not_found");
    this.run("UPDATE bots SET status = 'revoked' WHERE id = ?", m.id);
    this.run("UPDATE tokens SET revoked_at = ? WHERE kind = 'bot' AND subject_id = ? AND revoked_at IS NULL", nowIso(), m.id);
    this.audit.append(`owner:${ownerId}`, "home.member_revoked", m.id, [ownerId], { home: home.id });
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

  /** A signed message from one of my home's members to any bot of a friend home; reuses the pair's active conversation. */
  sendAsMember(p: Principal, body: { from_bot_id: string; to: string; text: string; attachments?: AttachmentRef[]; typed_by_owner?: boolean; mentions?: string[] | null }) {
    const ownerId = this.requireOwner(p);
    const typed = this.typedByOwner(p, body);
    const mentions = this.mentionList(body?.mentions);
    const cb = this.custodialBot(p, body?.from_bot_id);
    const to = this.get("SELECT * FROM bots WHERE handle = ? OR id = ?", String(body?.to ?? "").replace(/^@/, ""), body?.to);
    assert(to && to.status === "active", 404, "bot_not_found", "no such remote bot");
    void ownerId;
    this.activeRelationship(cb.botId, to.id);
    // Conversation statuses are open / awaiting_approval / closed; 'active' never matches,
    // so every send opened a new conversation and hit newConversationsPerPairPerDay (then 5).
    const conv = this.get("SELECT id FROM conversations WHERE status IN ('open', 'awaiting_approval') AND (expires_at IS NULL OR expires_at > ?) AND ((initiator_bot = ? AND peer_bot = ?) OR (initiator_bot = ? AND peer_bot = ?)) ORDER BY updated_at DESC LIMIT 1", nowIso(), cb.botId, to.id, to.id, cb.botId);
    const conversationId = conv?.id ?? (this.createConversation(cb.bp, cb.sign("conversation.create", { type: "direct", peer_bot_id: to.id, intent: { type: "general_chat", summary: "chat" } }, { to: to.id })) as any).conversation_id;
    const message = this.draftMessage(cb.bp, conversationId, cb.sign("message.draft", { text: body.text, ...(body.attachments?.length ? { attachments: body.attachments } : {}) }, { conversation_id: conversationId }), typed, mentions);
    return { conversation_id: conversationId, message, typed_by_owner: typed };
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
    assert(this.bot(c.bot_id).status === "active", 403, "bot_revoked", "this bot identity was revoked");
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
      name = String(body.display_name).trim();
      assert(name.length >= 1 && name.length <= 60, 400, "invalid_request", "display_name: 1-60 chars");
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
      return { kind: "owner", owner_id: o.id, username: o.username, display_name: o.display_name, timezone: o.timezone, sensitive_terms: J(o.sensitive_terms, []), auto_approve_face_rooms: !!o.auto_approve_face_rooms, bots: this.listBots(p) };
    }
    const b = this.bot(p.botId);
    return { kind: "bot", ...this.publicBot(b, true), status: b.status };
  }

  updateSettings(p: Principal, body: { sensitive_terms?: string[]; timezone?: string; display_name?: string; auto_approve_face_rooms?: boolean }) {
    const ownerId = this.requireOwner(p);
    if (Array.isArray(body.sensitive_terms)) this.run("UPDATE owners SET sensitive_terms = ? WHERE id = ?", JSON.stringify(body.sensitive_terms.map(String)), ownerId);
    if (body.timezone) this.run("UPDATE owners SET timezone = ? WHERE id = ?", body.timezone, ownerId);
    if (body.display_name) this.run("UPDATE owners SET display_name = ? WHERE id = ?", body.display_name, ownerId);
    if (typeof body.auto_approve_face_rooms === "boolean") this.run("UPDATE owners SET auto_approve_face_rooms = ? WHERE id = ?", body.auto_approve_face_rooms ? 1 : 0, ownerId);
    this.audit.append(`owner:${ownerId}`, "owner.settings_updated", ownerId, [ownerId], { fields: Object.keys(body) });
    return this.me(p);
  }

  // ================================================================ bots & keys
  registerBot(p: Principal, body: { handle: string; display_name?: string; avatar?: string | null; color?: string | null; integration_type?: string; webhook_url?: string; public_key?: { alg?: string; kid: string; value: string } }) {
    const ownerId = this.requireOwner(p);
    const handle = String(body?.handle ?? "").replace(/^@/, "");
    assert(/^[a-z0-9._-]{2,40}$/i.test(handle), 400, "invalid_request", "handle: 2-40 chars [a-z0-9._-]");
    assert(!this.get("SELECT 1 FROM bots WHERE handle = ?", handle), 409, "handle_taken");
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
        id, ownerId, handle, body.display_name || handle, body.integration_type || "rest", body.webhook_url ? validateUrl(body.webhook_url) : null, webhookSecret, nowIso());
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
    return this.all("SELECT id, handle, display_name, avatar, color, avatar_updated_at, integration_type, webhook_url, status, created_at FROM bots WHERE owner_id = ?", ownerId).map((b) => ({
      ...b, ...lookOf(b), webhook_url: redactUrl(b.webhook_url), webhook: { configured: !!b.webhook_url }, keys: this.all("SELECT kid, alg, public_key, status, created_at, expires_at FROM bot_keys WHERE bot_id = ?", b.id),
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
    this.run("UPDATE bots SET status = 'active' WHERE id = ?", b.id);
    const token = this.issueToken("bot", b.id);
    this.audit.append(`owner:${ownerId}`, "bot.resumed", b.id, [ownerId], {});
    return { bot_id: b.id, status: "active", bot_token: token };
  }

  rotateBotToken(p: Principal, botId: string) {
    const ownerId = this.requireOwner(p);
    const b = this.ownBot(ownerId, botId);
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
    if (b.status !== "active") throw new ApiError(403, "bot_frozen", "bot is frozen (emergency stop)");
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
      this.run("UPDATE approvals SET status = 'expired' WHERE subject_id = ? AND status = 'pending'", r.id);
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
    return rel;
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
    assert(target.id !== fromBot.id && target.owner_id !== fromBot.owner_id, 400, "invalid_request", "cannot befriend your own bot");
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
      this.audit.append(`owner:${ownerId}`, "relationship.declined", relId, [r.requester_owner, r.target_owner], {});
      this.emit(r.requester_bot, "relationship.changed", { relationship_id: relId, status: "declined" });
      return { relationship_id: relId, status: "declined" };
    }
    const specs = (body.grant_capabilities ?? []).map((g) => (typeof g === "string" ? { capability: g } : g));
    this.validCaps(specs.map((s) => s.capability));
    this.activateRelationship(r, specs, `owner:${ownerId}`);
    return { relationship_id: relId, status: "active", grants: this.grantsFor(relId) };
  }

  /** Activate a relationship: minimal defaults both ways + target owner's choices + requester's offered caps. */
  private activateRelationship(r: any, targetSpecs: { capability: string; scope?: any; expires_in_days?: number }[], actor: string) {
    const fbScope = { window_days: 14, hours: "09:00-18:00" };
    this.db.transaction(() => {
      this.run("UPDATE relationships SET status = 'active', updated_at = ?, expires_at = NULL WHERE id = ?", nowIso(), r.id);
      const targetToRequester = new Map<string, any>(DEFAULT_CAPABILITIES.map((c) => [c, { capability: c }]));
      for (const s of targetSpecs) targetToRequester.set(s.capability, { scope: s.capability === "calendar.freebusy.read" ? fbScope : {}, ...s });
      for (const s of targetToRequester.values()) this.insertGrant(r.id, r.target_owner, r.requester_bot, s.capability, s.scope, s.expires_in_days, actor);
      const requesterToTarget = new Set<string>([...DEFAULT_CAPABILITIES, ...J(r.offered_caps, [])]);
      for (const c of requesterToTarget) this.insertGrant(r.id, r.requester_owner, r.target_bot, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, `owner:${r.requester_owner}`);
    })();
    this.audit.append(actor, "relationship.accepted", r.id, [r.requester_owner, r.target_owner], { granted_to_requester: targetSpecs.map((s) => s.capability) });
    for (const b of [r.requester_bot, r.target_bot]) this.emit(b, "relationship.changed", { relationship_id: r.id, status: "active" });
  }

  private insertGrant(relId: string, grantorOwner: string, granteeBot: string, cap: string, scope: any, expiresInDays: number | undefined, actor: string, extra: { roomId?: string } = {}) {
    this.run("UPDATE grants SET status = 'superseded' WHERE relationship_id = ? AND grantor_owner = ? AND capability = ? AND status = 'active' AND IFNULL(room_id,'') = ?", relId, grantorOwner, cap, extra.roomId ?? "");
    const id = newId("grt");
    const exp = extra.roomId ? null : new Date(Date.now() + (expiresInDays ?? LIMITS.grantDefaultDays) * 86400e3).toISOString();
    const sc = extra.roomId ? { ...(scope ?? {}), kind: "room", room_id: extra.roomId } : { ...(scope ?? {}) };
    this.run("INSERT INTO grants (id, relationship_id, grantor_owner, grantee_bot, capability, scope, created_at, expires_at, room_id) VALUES (?,?,?,?,?,?,?,?,?)",
      id, relId, grantorOwner, granteeBot, cap, JSON.stringify(sc), nowIso(), exp, extra.roomId ?? null);
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    this.audit.append(actor, "grant.created", id, [r.requester_owner, r.target_owner], { relationship_id: relId, grantor_owner: grantorOwner, grantee_bot: granteeBot, capability: cap, scope: sc, expires_at: exp, room_id: extra.roomId ?? null });
    return id;
  }

  grantsFor(relId: string) {
    return this.all("SELECT * FROM grants WHERE relationship_id = ? AND status = 'active'", relId).map((g) => ({ ...g, scope: J(g.scope, {}) }));
  }

  findGrant(grantorOwner: string, granteeBot: string, cap: string, grantedBot?: string): any {
    const rows = this.all("SELECT g.*, r.requester_bot, r.target_bot, r.requester_owner, r.target_owner FROM grants g JOIN relationships r ON r.id = g.relationship_id WHERE g.grantor_owner = ? AND g.grantee_bot = ? AND g.capability = ? AND g.status = 'active' AND r.status = 'active' AND g.room_id IS NULL", grantorOwner, granteeBot, cap);
    for (const g of rows) {
      if (g.expires_at && Date.parse(g.expires_at) < Date.now()) { this.run("UPDATE grants SET status = 'expired' WHERE id = ?", g.id); continue; }
      if (grantedBot && this.grantedBotOf(g, g) !== grantedBot) continue;
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
    const grantee = ownerId === r.requester_owner ? r.target_bot : r.requester_bot;
    const id = this.insertGrant(relId, ownerId, grantee, body.capability, body.scope, body.expires_in_days, `owner:${ownerId}`);
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
   * The whole bundle (every capability of that grant to that bot) ends as 'declined'; it disappears from
   * the granting owner's list_bot_grants and from the grantee's list_remote_bots. Only this direction ends:
   * the friendship and any grants the other way stay. The Bot leaves rooms where the grant was used (same
   * as a revoke). The granting owner may share the Bot again with a fresh invite (see joinInvite).
   * Needs no confirm code: it only reduces the caller's own access, like leaving a room.
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
      const ref = this.get("SELECT id FROM bots WHERE id = ? OR handle = ?", botId, String(botId).replace(/^@/, ""));
      assert(ref && ref.id === granted, 404, "grant_not_found", "that grant is not for this bot");
    }
    const bundle = this.all("SELECT id FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND IFNULL(room_id,'') = ?",
      g.relationship_id, g.grantor_owner, g.grantee_bot, g.room_id ?? "");
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
        relationship_id: g.rel_status === "room" ? null : g.relationship_id,
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
        bot_id: granted.id, handle: "@" + granted.handle, display_name: granted.display_name, ...lookOf(granted),
        owner_display_name: this.owner(granted.owner_id).display_name,
        grant_id: g.id, scope, room: g.room_id ? this.grantRoomPublic(g.room_id) : rooms[0] ?? null, rooms,
        via: "@" + this.bot(g.grantee_bot).handle, created_at: g.created_at, expires_at: g.expires_at,
        relationship_id: g.rel_status === "room" ? null : g.relationship_id,
      };
      bots.push(item);
      const peerHome = this.bot(this.homeOf(granted.id));
      const entry = byHome.get(peerHome.id) ?? {
        relationship_id: item.relationship_id, relationship_ids: [] as string[],
        home: { bot_id: peerHome.id, handle: "@" + peerHome.handle, display_name: peerHome.display_name, ...lookOf(peerHome), owner_display_name: this.owner(peerHome.owner_id).display_name },
        bots: [] as any[], scope: "member", via: [] as string[],
      };
      if (item.relationship_id && !entry.relationship_ids.includes(item.relationship_id)) entry.relationship_ids.push(item.relationship_id);
      if (!entry.bots.some((x: any) => x.bot_id === granted.id)) {
        entry.bots.push({ bot_id: granted.id, handle: "@" + granted.handle, display_name: granted.display_name, ...lookOf(granted), grant_id: g.id, scope, room: item.room, rooms, created_at: g.created_at, expires_at: g.expires_at });
      }
      if (!entry.via.includes(item.via)) entry.via.push(item.via);
      byHome.set(peerHome.id, entry);
    }
    return { bots, homes: [...byHome.values()] };
  }

  private resolveOwnBot(ownerId: string, ref: string) {
    const b = this.get("SELECT * FROM bots WHERE owner_id = ? AND (id = ? OR handle = ?)", ownerId, ref, String(ref).replace(/^@/, ""));
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
      ...myBotIds, ownerId);
    return rows.find((g: any) => this.grantedBotOf(g, g) === targetBotId) ?? null;
  }

  requestGrant(p: Principal, env: Envelope) {
    this.verifyEnvelope(p, env, "grant.request");
    const { botId, ownerId } = this.requireBot(p);
    const pl: any = env.payload ?? {};
    const r = this.get("SELECT * FROM relationships WHERE id = ? AND status = 'active'", pl.relationship_id);
    assert(r && (r.requester_bot === botId || r.target_bot === botId), 403, "no_relationship");
    this.validCaps([pl.capability]);
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
      this.cancelPendingFor("(conversation_id IN (SELECT id FROM conversations WHERE relationship_id = ?) OR subject_id = ?)", [r.id, r.id], status);
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
      r = this.pairRelationships(mine.id, other.id)[0];
      if (!r) {
        const id = newId("rel");
        this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, requested_caps, offered_caps, created_at, updated_at) VALUES (?,?,?,?,?,'none','[]','[]',?,?)`,
          id, mine.id, other.id, ownerId, other.owner_id, nowIso(), nowIso());
        r = this.get("SELECT * FROM relationships WHERE id = ?", id);
      }
    }
    this.endRelationship(ownerId, r, "blocked");
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
      const fmt = (g: any) => ({ grant_id: g.id, capability: g.capability, scope: g.scope, expires_at: g.expires_at });
      return {
        relationship_id: r.id, status: r.status, direction: meIsRequester ? "outgoing" : "incoming", my_bot_id: myBot,
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
    if (i.status !== "active") return i.status;
    if (Date.parse(i.expires_at) < Date.now()) return "expired";
    if (i.uses >= i.max_uses) return "used";
    return "active";
  }

  /** Create an invite link. Owner-created invites are active at once (creating it is the owner's consent);
   *  bot-created invites (signed invite.create) need the owner's approval first. */
  createInvite(p: Principal, body: any) {
    let bot: any, payload: any, viaBot = false;
    if (p.kind === "bot") { const env = this.verifyEnvelope(p, body, "invite.create"); payload = env.payload ?? {}; bot = this.bot(p.botId); viaBot = true; }
    else {
      payload = body ?? {};
      bot = payload.bot_id ? this.ownBot(p.ownerId, payload.bot_id) : this.get("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at LIMIT 1", p.ownerId);
      assert(bot, 400, "invalid_request", "you have no bot");
    }
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
      payload = body ?? {};
      joiner = payload.from_bot_id ? this.ownBot(p.ownerId, payload.from_bot_id) : this.get("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at LIMIT 1", p.ownerId);
      assert(joiner, 400, "invalid_request", "you have no bot");
    }
    code = payload.code ?? code;
    const i = this.get("SELECT * FROM invites WHERE code = ?", code);
    assert(i, 404, "invite_not_found");
    const st = this.inviteStatus(i);
    assert(st === "active", 410, "invite_unavailable", `invite is ${st}`, { invite_status: st });
    const inviter = this.bot(i.bot_id);
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
    this.run(`INSERT INTO relationships (id, requester_bot, target_bot, requester_owner, target_owner, status, message, requested_caps, offered_caps, created_at, updated_at, expires_at, requester_scope, target_scope)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, joiner.id, inviter.id, joiner.owner_id, inviter.owner_id, status, payload.message ?? `Joined via invite link`, i.offered_caps, JSON.stringify(offered), nowIso(), nowIso(), new Date(Date.now() + LIMITS.relationshipRequestTtlMs).toISOString(), requesterScope, targetScope);
    this.run("INSERT INTO relationship_invites (relationship_id, invite_id) VALUES (?,?)", id, i.id);
    this.run("UPDATE invites SET uses = uses + 1 WHERE id = ?", i.id);
    this.audit.append(viaBot ? `bot:${joiner.id}` : `owner:${joiner.owner_id}`, "invite.joined", i.id, [joiner.owner_id, inviter.owner_id], { relationship_id: id, offered });
    let approval_id: string | undefined;
    if (viaBot) approval_id = this.createApproval(joiner.owner_id, "relationship_request", id, joiner.id, null, `Your bot wants to befriend @${inviter.handle} via invite (you grant: ${offered.join(", ")})`, ["relationship.requires_owner", "invite"], [], LIMITS.relationshipRequestTtlMs);
    else if (!this.maybeAutoAcceptInvite(id)) this.notifyTarget(id);
    const r = this.get("SELECT status FROM relationships WHERE id = ?", id);
    return { relationship_id: id, status: r.status, approval_id, inviter: this.publicBot(inviter), awaiting: r.status === "active" ? null : r.status === "pending_requester_owner" ? "your_owner_approval" : "inviter_owner_consent" };
  }

  /** Does `grantorOwner` still hold an unexpired, active relationship-level grant to `granteeBot` on this relationship? */
  private hasLiveGrant(grantorOwner: string, granteeBot: string, relId: string): boolean {
    return this.all("SELECT * FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND room_id IS NULL", relId, grantorOwner, granteeBot)
      .some((g: any) => !g.expires_at || Date.parse(g.expires_at) >= Date.now());
  }

  private regrantViaInvite(i: any, rel: any, inviter: any, joiner: any, payload: any) {
    const offered = this.validCaps(payload.offered_capabilities ?? J(i.requested_caps, DEFAULT_CAPABILITIES));
    const actor = `owner:${i.owner_id}(invite:${i.id})`;
    this.db.transaction(() => {
      this.run("UPDATE invites SET uses = uses + 1 WHERE id = ?", i.id);
      this.run("INSERT OR IGNORE INTO relationship_invites (relationship_id, invite_id) VALUES (?,?)", rel.id, i.id);
      const fbScope = { window_days: 14, hours: "09:00-18:00" };
      // inviter owner -> joiner bot: the same bundle a fresh friendship would give
      for (const c of new Set<string>([...DEFAULT_CAPABILITIES, ...J(i.offered_caps, [])])) this.insertGrant(rel.id, inviter.owner_id, joiner.id, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, actor);
      // joiner owner -> inviter bot: add only what is missing; never replaces grants the joiner already holds
      for (const c of new Set<string>([...DEFAULT_CAPABILITIES, ...offered])) {
        if (!this.findGrant(joiner.owner_id, inviter.id, c, joiner.id)) this.insertGrant(rel.id, joiner.owner_id, inviter.id, c, c === "calendar.freebusy.read" ? fbScope : {}, undefined, `owner:${joiner.owner_id}`);
      }
    })();
    this.audit.append(`owner:${joiner.owner_id}`, "invite.joined", i.id, [joiner.owner_id, inviter.owner_id], { relationship_id: rel.id, regrant: true, offered });
    for (const b of [inviter.id, joiner.id]) this.emit(b, "grant.changed", { relationship_id: rel.id, status: "granted", granted_bot: inviter.id, grantee_bot: joiner.id });
    return { relationship_id: rel.id, status: "active", approval_id: undefined, inviter: this.publicBot(inviter), awaiting: null, regranted: true };
  }

  /** A join that never became a friendship (requester owner rejected / request expired) must give its
   *  invite slot back; otherwise a 1-use invite reads "used" while no relationship exists. */
  private releaseInviteUse(relId: string) {
    const link = this.get("SELECT invite_id FROM relationship_invites WHERE relationship_id = ?", relId);
    if (link) this.run("UPDATE invites SET uses = MAX(uses - 1, 0) WHERE id = ?", link.invite_id);
  }

  /** If the relationship came from an auto-accept invite, the inviter owner already consented: activate it. */
  private maybeAutoAcceptInvite(relId: string): boolean {
    const link = this.get("SELECT i.* FROM relationship_invites ri JOIN invites i ON i.id = ri.invite_id WHERE ri.relationship_id = ?", relId);
    if (!link || !link.auto_accept || link.status === "revoked" || link.status === "pending_owner") return false;
    const r = this.get("SELECT * FROM relationships WHERE id = ?", relId);
    if (r.status !== "pending_target") return false;
    this.activateRelationship(r, J(link.offered_caps, []).map((c: string) => ({ capability: c })), `owner:${link.owner_id}(invite:${link.id})`);
    return true;
  }

  /** Per-bot friend overview for the /friends page. Owners may view any of their own bots; a bot only itself. */
  friendsOverview(p: Principal, botId?: string) {
    let bots: any[];
    if (p.kind === "bot") bots = [this.bot(p.botId)];
    else bots = this.all("SELECT * FROM bots WHERE owner_id = ? ORDER BY created_at", p.ownerId);
    const selected = botId ? bots.find((b) => b.id === botId || "@" + b.handle === botId || b.handle === botId) : bots[0];
    if (botId && !selected) throw new ApiError(403, "forbidden", "not your bot");
    const list = bots.map((b) => ({ bot_id: b.id, handle: "@" + b.handle, display_name: b.display_name, ...lookOf(b), status: b.status }));
    if (!selected) return { bots: list, bot: null, friends: [], pending_incoming: [], pending_outgoing: [], others: [] };
    this.expireStale();
    const rows = this.all("SELECT * FROM relationships WHERE (requester_bot = ? OR target_bot = ?) AND status != 'room' ORDER BY updated_at DESC", selected.id, selected.id);
    const items = rows.map((r) => {
      const outgoing = r.requester_bot === selected.id;
      const peerId = outgoing ? r.target_bot : r.requester_bot;
      const grants = this.grantsFor(r.id);
      const convs = this.all("SELECT id, status, outcome, intent, turn_count, max_turns, created_at, updated_at FROM conversations WHERE relationship_id = ? ORDER BY updated_at DESC", r.id);
      const lastMsg = this.get("SELECT MAX(COALESCE(delivered_at, created_at)) t FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE relationship_id = ?)", r.id)?.t ?? null;
      const last = convs[0];
      const times = [r.updated_at, last?.updated_at, lastMsg].filter(Boolean).sort();
      return {
        relationship_id: r.id, status: r.status, direction: outgoing ? "outgoing" : "incoming",
        peer: this.publicBot(this.bot(peerId), r.status === "active"),
        connected_at: r.status === "active" || r.status === "revoked" || r.status === "blocked" ? r.updated_at : null,
        requested_at: r.created_at, expires_at: r.expires_at, message: r.message, settings: this.settingsFor(r.id, selected.owner_id), blocked_by_me: !!r.blocked_by && r.blocked_by === selected.owner_id,
        capabilities: {
          granted_to_peer: grants.filter((g) => g.grantee_bot === peerId).map((g) => ({ capability: g.capability, scope: g.scope, expires_at: g.expires_at })),
          granted_to_me: grants.filter((g) => g.grantee_bot === selected.id).map((g) => ({ capability: g.capability, scope: g.scope, expires_at: g.expires_at })),
        },
        conversation_count: convs.length,
        last_conversation: last ? { conversation_id: last.id, status: last.status, outcome: last.outcome, intent: J(last.intent).type, summary: J(last.intent).summary, turn: { count: last.turn_count, max: last.max_turns }, updated_at: last.updated_at } : null,
        last_activity_at: times[times.length - 1] ?? null,
      };
    });
    return {
      bots: list, bot: { bot_id: selected.id, handle: "@" + selected.handle, display_name: selected.display_name, ...lookOf(selected), status: selected.status, owner_display_name: this.owner(selected.owner_id).display_name },
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
  private createApproval(ownerId: string, kind: string, subjectId: string, botId: string | null, convId: string | null, summary: string, reasons: string[], riskFlags: unknown[], ttlMs: number, extra?: unknown) {
    const id = newId("apr");
    this.run("INSERT INTO approvals (id, owner_id, kind, subject_id, bot_id, conversation_id, summary, reasons, risk_flags, created_at, expires_at, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
      id, ownerId, kind, subjectId, botId, convId, summary, JSON.stringify(reasons), JSON.stringify(riskFlags), nowIso(), new Date(Date.now() + ttlMs).toISOString(), extra ? JSON.stringify(extra) : null);
    return id;
  }

  private cancelPendingFor(where: string, args: unknown[], reason: string) {
    for (const a of this.all(`SELECT * FROM approvals WHERE status = 'pending' AND ${where}`, ...args)) {
      this.run("UPDATE approvals SET status = 'cancelled', decision = ?, decided_at = ? WHERE id = ?", reason, nowIso(), a.id);
      if (a.kind === "outbound_message") this.run("UPDATE messages SET status = 'cancelled' WHERE id = ?", a.subject_id);
      if (a.kind === "action") this.run("UPDATE actions SET status = 'cancelled' WHERE id = ?", a.subject_id);
      if (a.kind === "face_room_message") this.run("UPDATE face_room_drafts SET status = 'cancelled' WHERE id = ?", a.subject_id);
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
    if (a.kind === "action") this.run("UPDATE actions SET status = 'expired' WHERE id = ?", a.subject_id);
    if (a.kind === "face_room_message") {
      this.run("UPDATE face_room_drafts SET status = 'expired' WHERE id = ?", a.subject_id);
      const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", a.subject_id);
      if (d) this.emit(d.sender_bot, "approval.decided", { approval_id: a.id, kind: a.kind, message_id: d.id, room_id: d.room_id, decision: "expired" });
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
    const card: any = { approval_id: a.id, kind: a.kind, status: a.status, decision: a.decision, summary: a.summary, reasons: J(a.reasons, []), risk_flags: J(a.risk_flags, []), bot_id: a.bot_id, conversation_id: a.conversation_id, created_at: a.created_at, expires_at: a.expires_at };
    if (a.kind === "outbound_message") {
      const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
      const pl = J(m.payload);
      card.message = { message_id: m.id, to: this.publicBot(this.bot(m.recipient_bot)), payload: pl, status: m.status, ...(pl.attachments ? { attachments: pl.attachments.map((r: AttachmentRef) => ({ ...r, size_label: humanSize(r.size) })) } : {}) };
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
      if (d) card.face_room = { room_id: d.room_id, message_id: d.id, payload: J(d.payload), status: d.status };
    }
    if (a.conversation_id) {
      const c = this.get("SELECT * FROM conversations WHERE id = ?", a.conversation_id);
      if (c) card.conversation = { conversation_id: c.id, intent: J(c.intent), status: c.status, turn: { count: c.turn_count, max: c.max_turns } };
    }
    return card;
  }

  decideApproval(p: Principal, aprId: string, body: { decision: "approved" | "approved_with_edits" | "rejected"; edited_payload?: any; edited_params?: any; note_to_bot?: string }, actorOverride?: string) {
    const ownerId = this.requireOwner(p);
    this.expireStale();
    const a = this.get("SELECT * FROM approvals WHERE id = ?", aprId);
    assert(a, 404, "approval_not_found");
    assert(a.owner_id === ownerId, 403, "forbidden", "not your approval");
    assert(a.status === "pending", 409, "invalid_state", `approval is ${a.status}`);
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
      if (approve) result.grant_id = this.insertGrant(a.subject_id, ownerId, req.grantee_bot, req.capability, body.edited_params?.scope ?? req.scope, body.edited_params?.expires_in_days, `owner:${ownerId}`);
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

  private assertConvActive(c: any) {
    if (c.expires_at && Date.parse(c.expires_at) < Date.now() && c.status !== "closed") {
      this.run("UPDATE conversations SET status = 'closed', outcome = 'expired', updated_at = ? WHERE id = ?", nowIso(), c.id);
      throw new ApiError(409, "conversation_closed", "conversation expired");
    }
    assert(c.status !== "closed", 409, "conversation_closed", `conversation is closed (${c.outcome})`);
    assert(["open", "awaiting_approval"].includes(c.status), 409, "conversation_paused", `conversation is ${c.status}`);
  }

  private policyDecision(actor: string, convId: string | null, owners: string[], action: string, decision: string, reasons: string[], extra: Record<string, unknown> = {}) {
    this.audit.append(`bot:${actor}`, "policy.decision", convId, owners, { action, decision, reasons, policy_version: POLICY_VERSION, ...extra });
  }

  createConversation(p: Principal, env: Envelope) {
    this.verifyEnvelope(p, env, "conversation.create");
    const { botId, ownerId } = this.requireBot(p);
    const pl: any = env.payload ?? {};
    assert((pl.type ?? "direct") === "direct", 400, "invalid_request", "MVP supports only direct (1:1) conversations");
    assert(pl.peer_bot_id, 400, "invalid_request", "peer_bot_id required");
    const peer = this.bot(pl.peer_bot_id);
    const rel = this.activeRelationship(botId, peer.id);
    const intentDef = INTENTS[pl.intent?.type];
    if (!intentDef) {
      this.policyDecision(botId, null, [ownerId], "conversation.create", "deny", ["intent.unsupported"]);
      throw new ApiError(403, "intent_scope_violation", "MVP intents: schedule_meeting, general_chat");
    }
    if (!this.findGrant(peer.owner_id, botId, "chat.public", peer.id)) {
      this.policyDecision(botId, null, [ownerId, peer.owner_id], "conversation.create", "deny", ["capability_not_granted:chat.public"]);
      throw new ApiError(403, "capability_not_granted", "peer has not granted chat.public", { suggestion: "request_grant" });
    }
    const since = new Date(Date.now() - 86400e3).toISOString();
    const today = this.get("SELECT COUNT(*) n FROM conversations WHERE relationship_id = ? AND created_at > ?", rel.id, since).n;
    if (today >= LIMITS.newConversationsPerPairPerDay) throw new ApiError(429, "rate_limited", "too many new conversations for this relationship today", { retry_after: 3600 });
    const maxTurns = Math.min(Number(pl.intent.max_turns) || intentDef.maxTurns, intentDef.maxTurns);
    const allowed = (pl.intent.allowed_capabilities ?? intentDef.allowed).filter((c: string) => intentDef.allowed.includes(c));
    const intent = { type: intentDef.type, summary: String(pl.intent.summary ?? ""), params: pl.intent.params ?? {}, allowed_capabilities: allowed, success_criteria: pl.intent.success_criteria ?? null, max_turns: maxTurns };
    const id = newId("cnv");
    const expires = pl.intent.expires_at ? new Date(ms(pl.intent.expires_at)).toISOString() : new Date(Date.now() + 72 * 3600e3).toISOString();
    this.run("INSERT INTO conversations (id, type, relationship_id, initiator_bot, peer_bot, intent, status, max_turns, created_at, updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
      id, "direct", rel.id, botId, peer.id, JSON.stringify(intent), "open", maxTurns, nowIso(), nowIso(), expires);
    this.policyDecision(botId, id, [ownerId, peer.owner_id], "conversation.create", "allow", ["relationship.active", "intent.allowed", "turn_budget.ok"]);
    this.audit.append(`bot:${botId}`, "conversation.created", id, [ownerId, peer.owner_id], { peer: peer.id, intent, envelope_id: env.id, sig: env.sig });
    this.emit(peer.id, "conversation.started", { conversation_id: id, from: this.publicBot(this.bot(botId)), trust: "peer_untrusted", untrusted_content: { intent } });
    return {
      conversation_id: id, status: "open", intent,
      limits: { max_turns: maxTurns, rate_per_min: LIMITS.ratePerConversationPerMin, expires_at: expires },
      effective_capabilities: this.effectiveCaps(botId, peer.id, allowed),
    };
  }

  private effectiveCaps(me: string, peer: string, allowed: string[]) {
    const meB = this.bot(me), peerB = this.bot(peer);
    return {
      me_on_peer: allowed.filter((c) => this.findGrant(peerB.owner_id, me, c, peer)),
      peer_on_me: allowed.filter((c) => this.findGrant(meB.owner_id, peer, c, me)),
    };
  }

  /** `typedByOwner` is internal: set only by sendAsMember after typedByOwner() authorised it, never from the envelope or text. */
  draftMessage(p: Principal, convId: string, env: Envelope, typedByOwner = false, mentions: string[] = []) {
    this.verifyEnvelope(p, env, "message.draft");
    const { botId, ownerId } = this.requireBot(p);
    assert(!env.conversation_id || env.conversation_id === convId, 400, "invalid_envelope", "conversation_id mismatch");
    const { peer } = this.memberConv(botId, convId);
    const peerB = this.bot(peer);
    const owners = [ownerId, peerB.owner_id];
    this.activeRelationship(botId, peer);
    this.expireStale();
    const c = this.conv(convId);
    this.assertConvActive(c);
    const pl: any = env.payload ?? {};
    assert(typeof pl.text === "string" && pl.text.length > 0 && pl.text.length <= 4000, 400, "invalid_request", "payload.text (1-4000 chars) required");
    // Refs live in the signed payload, so the sender's signature covers them.
    const refs = this.checkRefs(botId, pl.attachments);
    if (!this.findGrant(peerB.owner_id, botId, "chat.public", peerB.id)) {
      this.policyDecision(botId, convId, owners, "message.draft", "deny", ["capability_not_granted:chat.public"]);
      throw new ApiError(403, "capability_not_granted", "peer has not granted chat.public", { suggestion: "request_grant" });
    }
    // rate limits
    const minuteAgo = Date.now() - 60e3, hourAgo = Date.now() - 3600e3;
    if (this.get("SELECT COUNT(*) n FROM messages WHERE conversation_id = ? AND sender_bot = ? AND created_ms > ?", convId, botId, minuteAgo).n >= LIMITS.ratePerConversationPerMin)
      throw new ApiError(429, "rate_limited", "per-conversation rate limit (6/min)", { retry_after: 60 });
    if (this.get("SELECT COUNT(*) n FROM messages WHERE sender_bot = ? AND created_ms > ?", botId, hourAgo).n >= LIMITS.ratePerBotPerHour)
      throw new ApiError(429, "rate_limited", "global bot rate limit (60/h)", { retry_after: 3600 });
    // turn budget (delivered + pending)
    const pendingCount = this.get("SELECT COUNT(*) n FROM messages WHERE conversation_id = ? AND status = 'pending_approval'", convId).n;
    if (c.turn_count + pendingCount >= c.max_turns) {
      this.pauseConversation(c, "paused_limit", "max_turns reached");
      throw new ApiError(409, "conversation_paused", "turn budget exhausted; owners can extend the conversation");
    }
    // loop detection
    const recent = this.all("SELECT payload FROM messages WHERE conversation_id = ? AND status IN ('delivered','pending_approval') ORDER BY created_ms DESC LIMIT 3", convId)
      .reverse().map((m) => { const x = J(m.payload); return { text: x.text ?? "", structured: !!x.structured }; });
    if (detectLoop(recent, { text: pl.text, structured: !!pl.structured })) {
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
    const files = refs.length ? ` [${refs.length} file${refs.length > 1 ? "s" : ""}: ${refs.map((r) => `${r.name} (${humanSize(r.size)})`).join(", ")}]` : "";
    // Only the two ends of this conversation can be mentioned in it.
    const ends = ["@" + String(this.bot(botId).handle).replace(/^@/, "").toLowerCase(), "@" + String(peerB.handle).replace(/^@/, "").toLowerCase()];
    const kept = mentions.filter((h) => ends.includes(h));
    const aprId = this.createApproval(ownerId, "outbound_message", id, botId, convId, `To @${peerB.handle}: ${pl.text.slice(0, 80)}${files}`, reasons, flags, J(c.intent).type === "schedule_meeting" ? LIMITS.meetingApprovalTtlMs : LIMITS.approvalTtlMs);
    this.run("INSERT INTO messages (id, conversation_id, sender_bot, recipient_bot, envelope, payload, status, risk_flags, expects_reply, approval_id, created_at, created_ms, typed_by_owner, mentions) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      id, convId, botId, peer, JSON.stringify(env), JSON.stringify({ kind: pl.kind ?? (pl.structured ? "structured" : "text"), text: pl.text, structured: pl.structured ?? null, expects_reply: pl.expects_reply !== false, ...(refs.length ? { attachments: refs } : {}) }),
      "pending_approval", JSON.stringify(flags), pl.expects_reply === false ? 0 : 1, aprId, nowIso(), Date.now(), typedByOwner ? 1 : 0, kept.length ? JSON.stringify(kept) : null);
    for (const r of refs) this.run("UPDATE attachments SET message_id = ? WHERE id = ? AND message_id IS NULL", id, r.id);
    this.policyDecision(botId, convId, owners, "message.draft", "require_approval", reasons, { message_id: id });
    this.audit.append(`bot:${botId}`, "message.drafted", id, owners, { conversation_id: convId, envelope_id: env.id, payload_sha256: env.payload_sha256, sig: env.sig, risk_flags: flags, approval_id: aprId, ...(typedByOwner ? { typed_by_owner: true } : {}) });
    this.refreshConversationStatus(convId);
    const rel = this.activeRelationship(botId, peer);
    if (this.settingsFor(rel.id, ownerId).auto_approve_chat && flags.length === 0 && !detectInjection(pl.text).suspected) {
      this.decideApproval({ kind: "owner", ownerId }, aprId, { decision: "approved" }, "policy:auto_approve");
      return { message_id: id, status: "delivered", approval_id: aprId, auto_approved: true, ...(typedByOwner ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), policy: { decision: "allow", reasons: ["owner.auto_approve_chat", "dlp.clean"], risk_flags: [], policy_version: POLICY_VERSION } };
    }
    return { message_id: id, status: "pending_approval", approval_id: aprId, ...(typedByOwner ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), policy: { decision: "require_approval", reasons, risk_flags: flags, policy_version: POLICY_VERSION } };
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
    this.audit.append("platform", "conversation.paused", c.id, owners, { status, reason, turn_count: c.turn_count, max_turns: c.max_turns });
    for (const b of [c.initiator_bot, c.peer_bot]) this.emit(b, "conversation.paused", { conversation_id: c.id, status, reason, trust: "platform" });
  }

  private deliverMessage(a: any, body: any) {
    const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
    const c = this.conv(m.conversation_id);
    const sender = this.bot(m.sender_bot);
    const recipient = this.bot(m.recipient_bot);
    this.activeRelationship(sender.id, recipient.id);
    let payload = J(m.payload);
    const edited = body.decision === "approved_with_edits" && body.edited_payload;
    if (edited) {
      payload = { ...payload, ...body.edited_payload, ...(payload.attachments ? { attachments: payload.attachments } : {}) };
      if (!payload.attachments) delete payload.attachments;
      const blocked = this.dlp(sender.owner_id, payload).filter((f) => f.action === "block");
      assert(!blocked.length, 422, "dlp_blocked", "edited payload blocked by DLP", { categories: blocked.map((b) => b.category) });
    }
    const inj = detectInjection([payload.text, payload.structured ? JSON.stringify(payload.structured) : ""].join("\n"));
    const turn = c.turn_count + 1;
    const env = J(m.envelope);
    const intent = J(c.intent);
    const delivered: Record<string, unknown> = {
      message_id: m.id, conversation_id: c.id, intent: { type: intent.type, summary: intent.summary },
      from: this.publicBot(sender), trust: "peer_untrusted",
      untrusted_content: { text: payload.text, structured: payload.structured ?? null },
      ...(Array.isArray(payload.attachments) && payload.attachments.length ? { attachments: payload.attachments } : {}),
      expects_reply: payload.expects_reply !== false, approved_by_owner: true, edited_by_owner: !!edited,
      ...(m.typed_by_owner ? { typed_by_owner: true } : {}),
      ...(mentionsOf(m.mentions).length && !edited ? { mentions: mentionsOf(m.mentions) } : {}),
      security: { injection_suspected: inj.suspected }, turn: { count: turn, max: c.max_turns },
      sender_envelope: { id: env.id, ts: env.ts, nonce: env.nonce, payload_sha256: env.payload_sha256, sig: env.sig },
      platform_kid: this.platformKid, delivered_at: nowIso(),
    };
    delivered.platform_countersig = this.countersign(delivered);
    this.run("UPDATE messages SET status = 'delivered', delivered_payload = ?, injection = ?, delivered_at = ? WHERE id = ?", JSON.stringify(payload), JSON.stringify(inj), nowIso(), m.id);
    this.run("UPDATE conversations SET turn_count = ?, updated_at = ? WHERE id = ?", turn, nowIso(), c.id);
    this.emit(recipient.id, "message.received", delivered);
    this.emit(sender.id, "approval.decided", { approval_id: a.id, kind: "outbound_message", message_id: m.id, decision: body.decision, note_to_bot: body.note_to_bot ?? null, delivered_payload: payload });
    this.audit.append("platform", "message.delivered", m.id, [sender.owner_id, recipient.owner_id], { conversation_id: c.id, turn, edited: !!edited, injection_suspected: inj.suspected, delivered_sha256: payloadDigest(payload), platform_countersig: delivered.platform_countersig });
    if (turn >= c.max_turns) this.pauseConversation({ ...c, turn_count: turn }, "paused_limit", "max_turns reached");
    return { message_id: m.id, status: "delivered" };
  }

  private rejectMessage(a: any, note?: string) {
    const m = this.get("SELECT * FROM messages WHERE id = ?", a.subject_id);
    this.run("UPDATE messages SET status = 'rejected' WHERE id = ?", m.id);
    // the peer never sees rejected drafts; only the sender bot is informed
    this.emit(m.sender_bot, "approval.decided", { approval_id: a.id, kind: "outbound_message", message_id: m.id, decision: "rejected", note_to_bot: note ?? null });
    return { message_id: m.id, status: "rejected" };
  }

  extendConversation(p: Principal, convId: string, body: { extra_turns?: number }) {
    const ownerId = this.requireOwner(p);
    const c = this.conv(convId);
    const owners = [this.bot(c.initiator_bot).owner_id, this.bot(c.peer_bot).owner_id];
    assert(owners.includes(ownerId), 403, "forbidden");
    assert(["paused_limit", "paused_loop", "paused_stop", "open", "awaiting_approval"].includes(c.status), 409, "invalid_state", `conversation is ${c.status}`);
    const extra = Math.max(1, Math.min(Number(body?.extra_turns) || 4, 20));
    this.run("UPDATE conversations SET max_turns = max_turns + ?, status = 'open', updated_at = ? WHERE id = ?", extra, nowIso(), convId);
    this.refreshConversationStatus(convId);
    this.audit.append(`owner:${ownerId}`, "conversation.extended", convId, owners, { extra_turns: extra });
    for (const b of [c.initiator_bot, c.peer_bot]) this.emit(b, "conversation.resumed", { conversation_id: convId, max_turns: c.max_turns + extra, trust: "platform" });
    return { conversation_id: convId, status: this.conv(convId).status, max_turns: c.max_turns + extra };
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
    this.cancelPendingFor("conversation_id = ?", [convId], "conversation_closed");
    this.audit.append(actor, "conversation.closed", convId, owners, { outcome, summary });
    for (const b of [c.initiator_bot, c.peer_bot]) this.emit(b, "conversation.closed", { conversation_id: convId, outcome, trust: "platform", summary });
    return { conversation_id: convId, status: "closed", outcome };
  }

  listConversations(p: Principal) {
    const rows = p.kind === "owner"
      ? this.all("SELECT c.* FROM conversations c WHERE c.initiator_bot IN (SELECT id FROM bots WHERE owner_id = ?) OR c.peer_bot IN (SELECT id FROM bots WHERE owner_id = ?) ORDER BY c.created_at DESC", p.ownerId, p.ownerId)
      : this.all("SELECT * FROM conversations WHERE initiator_bot = ? OR peer_bot = ? ORDER BY created_at DESC", p.botId, p.botId);
    return rows.map((c) => ({ conversation_id: c.id, status: c.status, outcome: c.outcome, intent: J(c.intent), initiator: this.publicBot(this.bot(c.initiator_bot)), peer: this.publicBot(this.bot(c.peer_bot)), turn: { count: c.turn_count, max: c.max_turns }, created_at: c.created_at, updated_at: c.updated_at }));
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
    return {
      conversation_id: c.id, status: c.status, outcome: c.outcome, summary: c.summary, intent: J(c.intent), turn: { count: c.turn_count, max: c.max_turns },
      initiator: this.publicBot(this.bot(c.initiator_bot)), peer: this.publicBot(this.bot(c.peer_bot)), messages: msgs, actions,
      effective_capabilities: this.effectiveCaps(viewerBot, viewerBot === c.initiator_bot ? c.peer_bot : c.initiator_bot, J(c.intent).allowed_capabilities),
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
    this.assertConvActive(c);
    const pl: any = env.payload ?? {};
    const def = ACTIONS[pl.action_type];
    const intent = J(c.intent);
    if (!def || !intent.allowed_capabilities.includes(def.capability)) {
      this.policyDecision(botId, convId, owners, "action.draft", "deny", ["intent_scope_violation"], { action_type: pl.action_type });
      throw new ApiError(403, "intent_scope_violation", `action ${pl.action_type} not allowed in ${intent.type} conversation`);
    }
    const params = pl.params ?? {};
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
      const inv = this.get("SELECT * FROM calendar_entries WHERE booking_id = ? AND owner_id = ? AND status = 'invited'", params.booking_id, ownerId);
      assert(inv, 404, "invite_not_found", "no pending invite with that booking_id for your owner");
      summary = `Accept @${peerB.handle}'s meeting invite at ${isoInTz(Date.parse(inv.start), tz).slice(0, 16).replace("T", " ")} (${tz})?`;
    }
    const dlpFlags = this.dlp(ownerId, { text: [params.title, pl.justification].filter(Boolean).join(" ") }).filter((f) => f.category !== "commitment");
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
      this.emit(actor.id, "event.meeting_booked", { conversation_id: c.id, action_id: x.id, trust: "platform", ...result });
      this.emit(peer.id, "event.meeting_booked", { conversation_id: c.id, action_id: x.id, trust: "platform", ...result, note: "Invite pending. Accepting is a commitment requiring your owner's approval: draft action calendar.accept_invite." });
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
    this.expireStale();
    const rows = this.all("SELECT * FROM events WHERE bot_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?", botId, since, limit);
    return { events: rows.map((r) => ({ cursor: r.seq, event_id: r.id, event_type: r.type, created_at: r.created_at, ...J(r.data) })), next_cursor: rows.length ? rows[rows.length - 1].seq : since };
  }

  auditEvents(p: Principal, opts: { subject?: string; limit?: number } = {}) {
    const ownerId = this.requireOwner(p);
    return { events: this.audit.list({ owner: ownerId, subject: opts.subject, limit: opts.limit }), chain: this.audit.verify() };
  }

  // ================================================================ face-to-face rooms
  /** `look` adds the Bot's current avatar/color. Only used for the member list of a room the viewer belongs to;
   *  events (persisted, replayed and delivered as inbox items) never carry the avatar. */
  private faceMemberPublic(m: any, look = false) {
    const display_name = sanitizePeerName(m.display_name, "Bot");
    const owner_name = sanitizePeerName(m.owner_name, "Owner");
    return {
      handle: m.handle, display_name, owner_name,
      label: memberLabel(display_name, owner_name), bot_id: m.bot_id,
      ...(look ? lookOf(this.get("SELECT avatar, color, avatar_updated_at FROM bots WHERE id = ?", m.bot_id) ?? {}) : {}),
    };
  }
  private faceSnapshot(b: any) {
    const o = this.owner(b.owner_id);
    const display_name = sanitizePeerName(b.display_name, sanitizePeerName(String(b.handle).replace(/^@/, ""), "Bot"));
    const owner_name = sanitizePeerName(o.display_name, sanitizePeerName(o.username, "Owner"));
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
  private faceRecordAttempt(ownerId: string, ip: string | null, code: string, outcome: string) {
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
  private faceAttemptRateLimit(ownerId: string, ip: string | null) {
    const since = new Date(this.nowMs() - this.faceRoomLimits.attemptWindowMs).toISOString();
    if (this.get("SELECT COUNT(*) n FROM face_room_attempts WHERE owner_id = ? AND created_at > ?", ownerId, since).n >= this.faceRoomLimits.attemptsPerAccount)
      return this.faceRateFail("too many code attempts from this account", "account", this.faceRoomLimits.attemptWindowMs);
    if (ip && this.get("SELECT COUNT(*) n FROM face_room_attempts WHERE ip = ? AND created_at > ?", ip, since).n >= this.faceRoomLimits.attemptsPerIp)
      return this.faceRateFail("too many code attempts from this address", "ip", this.faceRoomLimits.attemptWindowMs);
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
      if (extra.some((r) => r !== p.botId && r.replace(/^@/, "") !== this.bot(p.botId).handle)) throw new ApiError(403, "forbidden", "a bot token may only bring itself");
      const b = this.bot(p.botId);
      assert(b.status === "active", 403, "bot_revoked", "this bot identity was revoked");
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
      const own = this.get("SELECT * FROM bots WHERE (id = ? OR handle = ?) AND owner_id = ?", ref, String(ref).replace(/^@/, ""), p.ownerId);
      if (own) {
        assert(own.status === "active", 403, "bot_revoked", "this bot identity was revoked");
        if (!out.some((x) => x.bot.id === own.id)) out.push(wrap(own));
        continue;
      }
      const other = this.get("SELECT * FROM bots WHERE id = ? OR handle = ?", ref, String(ref).replace(/^@/, ""));
      assert(other && other.status === "active", 404, "bot_not_found", `no bot matching ${ref} on this account`);
      const grant = this.accessGrantTo(p.ownerId, mine, other.id);
      assert(grant, 404, "bot_not_found", `no bot matching ${ref} on this account`);
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
    if (asBot) { sql += " AND (bot_id = ? OR handle = ?)"; args.push(asBot, asBot.startsWith("@") ? asBot : "@" + String(asBot).replace(/^@/, "")); }
    const members = this.all(sql, ...args);
    if (!members.length) throw new ApiError(404, "face_room_not_found", "no such room");
    return { ownerId, botIds: members.map((m: any) => m.bot_id as string), members, joinSeq: Math.min(...members.map((m: any) => m.join_seq as number)), room };
  }
  private faceRoomView(roomId: string, viewer: { joinSeq?: number }, opts: { after?: number } = {}) {
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    const members = this.all("SELECT * FROM face_room_members WHERE room_id = ? AND left_at IS NULL ORDER BY joined_at", roomId).map((m: any) => this.faceMemberPublic(m, true));
    const floor = (viewer.joinSeq ?? 1) - 1;
    const after = opts.after !== undefined ? opts.after : floor;
    const events = this.all("SELECT * FROM face_room_events WHERE room_id = ? AND seq > ? ORDER BY seq ASC", roomId, after).map((e: any) => this.faceEventPublic(e));
    return {
      room_id: room.id, status: room.status, expires_at: room.expires_at, started_at: room.started_at, closed_at: room.closed_at,
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
      if (attemptBlock) { this.faceRecordAttempt(ownerId, ip, code || String(rawCode ?? ""), "rate_limited"); return { ...attemptBlock }; }
      if (!codeOk) {
        this.faceRecordAttempt(ownerId, ip, String(rawCode ?? ""), "invalid_code");
        return { ok: false, status: 400, code: "invalid_code", message: "code must be exactly 6 digits", lockout: this.faceMaybeLockout(ownerId, ip) };
      }
      const mapping = this.get("SELECT * FROM face_room_codes WHERE code = ?", code);
      if (!mapping) {
        const createBlock = this.faceCreateRateLimit(ownerId, ip);
        if (createBlock) { this.faceRecordAttempt(ownerId, ip, code, "rate_limited"); return { ...createBlock }; }
        if (bots.length > this.faceRoomLimits.maxMembers) {
          this.faceRecordAttempt(ownerId, ip, code, "room_full");
          return { ok: false, status: 409, code: "room_full", message: `this room is full (max ${this.faceRoomLimits.maxMembers} bots); no second room is opened`, lockout: this.faceMaybeLockout(ownerId, ip) };
        }
        const id = newId("frm");
        const now = this.ts();
        const expires = new Date(this.nowMs() + this.faceRoomLimits.ttlMs).toISOString();
        this.run("INSERT INTO face_rooms (id, code, status, created_at, expires_at) VALUES (?,?,?,?,?)", id, code, "candidate", now, expires);
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
          .map((m: any) => ({ handle: m.handle, display_name: m.display_name, ...lookOf(m) })),
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
    let leaving = viewer.members;
    const refs = this.normalizeBotRefs(body);
    if (refs.length) {
      leaving = leaving.filter((m: any) => refs.some((r) => m.bot_id === r || m.handle === r || m.handle === "@" + String(r).replace(/^@/, "")));
      assert(leaving.length, 404, "bot_not_found", "none of those bots are in this room");
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

  draftFaceRoomMessage(p: Principal, roomId: string, body: { text?: string; bot_id?: string; bot?: string; typed_by_owner?: boolean; mentions?: string[] | null } = {}) {
    const typed = this.typedByOwner(p, body);
    const mentions = this.mentionList(body?.mentions);
    this.advanceFaceRooms();
    const viewer = this.faceRequireMember(p, roomId, body.bot_id ?? body.bot);
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", roomId);
    if (room.status === "closed") throw new ApiError(409, "room_closed", "this room is closed");
    const text = String(body?.text ?? "");
    assert(text.length > 0 && text.length <= 4000, 400, "invalid_request", "text (1-4000 chars) required");
    const sender = this.bot(viewer.botIds[0]);
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
    const inRoom = new Set(this.all("SELECT handle FROM face_room_members WHERE room_id = ? AND left_at IS NULL", roomId).map((r) => "@" + String(r.handle).replace(/^@/, "").toLowerCase()));
    const kept = mentions.filter((h) => inRoom.has(h));
    const reasons = ["mvp.all_outbound_requires_approval", ...flags.map((f) => `dlp.${f.category}`)];
    const snap = this.faceSnapshot(sender);
    const aprId = this.createApproval(sender.owner_id, "face_room_message", id, sender.id, null, `To face room: ${text.slice(0, 80)}`, reasons, flags, LIMITS.approvalTtlMs, { room_id: roomId });
    this.run("INSERT INTO face_room_drafts (id, room_id, sender_bot, payload, status, approval_id, created_at, created_ms, typed_by_owner, mentions) VALUES (?,?,?,?,?,?,?,?,?,?)",
      id, roomId, sender.id, JSON.stringify({ text }), "pending_approval", aprId, this.ts(), this.nowMs(), typed ? 1 : 0, kept.length ? JSON.stringify(kept) : null);
    this.audit.append(`bot:${sender.id}`, "face_room.message_drafted", id, this.faceOwnerIds(roomId), { room_id: roomId, approval_id: aprId });
    const o = this.owner(sender.owner_id);
    if (o.auto_approve_face_rooms && flags.length === 0 && !detectInjection(text).suspected) {
      this.decideApproval({ kind: "owner", ownerId: sender.owner_id }, aprId, { decision: "approved" }, "policy:auto_approve");
      const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", id);
      return { message_id: id, status: "delivered", approval_id: aprId, event_cursor: d.event_seq, auto_approved: true, ...(typed ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), from: snap };
    }
    return { message_id: id, status: "pending_approval", approval_id: aprId, ...(typed ? { typed_by_owner: true } : {}), ...(kept.length ? { mentions: kept } : {}), from: snap };
  }

  private deliverFaceRoomMessage(a: any, body: any) {
    const d = this.get("SELECT * FROM face_room_drafts WHERE id = ?", a.subject_id);
    const room = this.get("SELECT * FROM face_rooms WHERE id = ?", d.room_id);
    assert(room && room.status !== "closed", 409, "room_closed", "this room is closed");
    let payload = J(d.payload);
    if (body.decision === "approved_with_edits" && body.edited_payload) {
      payload = { ...payload, ...body.edited_payload };
      const blocked = this.dlp(this.bot(d.sender_bot).owner_id, payload).filter((f) => f.action === "block");
      assert(!blocked.length, 422, "dlp_blocked", "edited payload blocked by DLP", { categories: blocked.map((b) => b.category) });
    }
    const edited = body.decision === "approved_with_edits" && !!body.edited_payload; // the list described the typed text; an edited line carries none
    const still = this.get("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ? AND left_at IS NULL", d.room_id, d.sender_bot);
    assert(still, 409, "not_a_member", "sender is no longer in the room");
    const snap = this.faceMemberPublic(still);
    const inj = detectInjection(String(payload.text ?? ""));
    const ev = this.faceInsertEvent(d.room_id, "room.message", d.sender_bot, {
      from: snap, trust: "peer_untrusted", untrusted_content: { text: payload.text },
      security: { injection_suspected: inj.suspected }, edited_by_owner: body.decision === "approved_with_edits",
      ...(d.typed_by_owner ? { typed_by_owner: true } : {}),
      ...(mentionsOf(d.mentions).length && !edited ? { mentions: mentionsOf(d.mentions) } : {}),
    });
    this.run("UPDATE face_room_drafts SET status = 'delivered', event_seq = ? WHERE id = ?", ev.seq, d.id);
    this.faceEmitMembers(d.room_id, "face_room.message", {
      room_id: d.room_id, event_id: ev.id, event_cursor: ev.seq, message_id: d.id,
      from: snap, trust: "peer_untrusted", untrusted_content: { text: payload.text },
      security: { injection_suspected: inj.suspected },
      ...(d.typed_by_owner ? { typed_by_owner: true } : {}),
      ...(mentionsOf(d.mentions).length && !edited ? { mentions: mentionsOf(d.mentions) } : {}),
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

  platformInfo() {
    return { name: "Bot Social", version: "0.1.0", policy_version: POLICY_VERSION, platform_key: { alg: "Ed25519", kid: this.platformKid, public_key: this.platformKey.publicKey }, capabilities: CAPABILITIES, intents: INTENTS, features: ["typed_by_owner", "mentions"] };
  }
}
