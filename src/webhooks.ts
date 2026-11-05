import type Database from "better-sqlite3";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { webhookSignature } from "./crypto.js";
import { ApiError, assert } from "./errors.js";
import { newId } from "./ids.js";

/**
 * Coalesced webhook "wake-up" pushes.
 * Events for a bot are collected for `debounceMs` after the first one and sent as ONE small push
 * (counts + short, content-free summaries). Per-bot hourly cap, retries with exponential backoff,
 * and a delivery log. The push never contains peer-written text: the receiver must pull details
 * (`botctl pending` / GET /v1/events), where untrusted content is clearly wrapped.
 */
export interface WebhookOptions {
  debounceMs?: number; // collapse window (default 20 s)
  maxPerHour?: number; // per-bot cap (default 30)
  retryBaseMs?: number; // backoff base; delays base, 4·base, 16·base (default 2 s)
  maxAttempts?: number; // default 4
  timeoutMs?: number; // per attempt (default 10 s)
  allowPrivate?: boolean; // allow loopback / private targets (default true; production sets false)
}
export interface Header { name: string; value: string }
interface Pending { events: { event_id: string; type: string; created_at: string; data: Record<string, unknown> }[]; timer?: NodeJS.Timeout; first_at: number; limited?: string }

const RESERVED = /^(content-type|content-length|host|x-botsocial-.*)$/i;
const MAX_ITEMS = 10;

export function parseHeader(line: string): Header {
  const i = line.indexOf(":");
  assert(i > 0, 400, "invalid_request", `header must look like "Name: value"`);
  return { name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() };
}
export function validateHeaders(h: unknown): Header[] {
  const list: Header[] = Array.isArray(h) ? h.map((x) => (typeof x === "string" ? parseHeader(x) : x)) : h && typeof h === "object" ? Object.entries(h).map(([name, value]) => ({ name, value: String(value) })) : [];
  assert(list.length <= 5, 400, "invalid_request", "at most 5 custom headers");
  for (const x of list) {
    assert(typeof x?.name === "string" && /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(x.name), 400, "invalid_request", `bad header name`);
    assert(!RESERVED.test(x.name), 400, "invalid_request", `header ${x.name} is reserved`);
    assert(typeof x.value === "string" && x.value.length > 0 && x.value.length <= 4096 && !/[\r\n\0]/.test(x.value), 400, "invalid_request", `bad value for header ${x.name}`);
  }
  return list;
}
/** "Bearer sk-abcdef…" → "Bearer ••••cdef (len 40)". Never reveals more than the last 4 chars of a secret. */
export function redactValue(v: string): string {
  const m = /^([A-Za-z]+)\s+(.+)$/.exec(v);
  const scheme = m ? m[1] + " " : ""; const secret = m ? m[2] : v;
  return `${scheme}••••${secret.length >= 16 ? secret.slice(-4) : ""} (${secret.length} chars)`;
}
export const redactHeaders = (hs: Header[]) => hs.map((h) => ({ name: h.name, value: redactValue(h.value) }));
/** Mask query values and long path segments (routine URLs may embed tokens). */
export function redactUrl(u: string | null): string | null {
  if (!u) return u;
  try {
    const url = new URL(u);
    const path = url.pathname.split("/").map((s) => (s.length >= 20 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s)).join("/");
    const q = [...url.searchParams.keys()].map((k) => `${k}=•••`).join("&");
    return `${url.protocol}//${url.host}${path}${q ? "?" + q : ""}`;
  } catch { return "(invalid url)"; }
}
export function validateUrl(u: unknown): string {
  assert(typeof u === "string" && u.length <= 2048, 400, "invalid_request", "url required");
  let url: URL;
  try { url = new URL(u as string); } catch { throw new ApiError(400, "invalid_request", "invalid url"); }
  assert(url.protocol === "https:" || url.protocol === "http:", 400, "invalid_request", "url must be http(s)");
  assert(!url.username && !url.password, 400, "invalid_request", "put credentials in a header, not the url");
  return url.toString();
}
/** The existing IPv4 rule: loopback, "this network", RFC 1918, link-local, CGNAT. */
function isPrivateV4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}
/**
 * The sixteen bytes of an IPv6 literal (a zone id is ignored), or null when it is not one.
 * The only text→number step: every prefix below is read from these bytes, because `new URL()`
 * rewrites `[::ffff:127.0.0.1]` to `::ffff:7f00:1` and no spelling-based rule survives that.
 */
function ipv6Bytes(ip: string): Uint8Array | null {
  if (isIP(ip) !== 6) return null;
  const text = ip.split("%")[0].toLowerCase();
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const words = (s: string): number[] => s === "" ? [] : s.split(":").flatMap((w) => {
    if (!w.includes(".")) return [parseInt(w, 16)]; // isIP already accepted the literal
    const [a, b, c, d] = w.split(".").map(Number); // dotted quad in the last group
    return [(a << 8) | b, (c << 8) | d];
  });
  const head = words(halves[0]);
  const tail = halves.length > 1 ? words(halves[1]) : [];
  const groups = halves.length > 1 ? [...head, ...new Array(Math.max(0, 8 - head.length - tail.length)).fill(0), ...tail] : head;
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  groups.forEach((g, i) => { bytes[i * 2] = (g >> 8) & 0xff; bytes[i * 2 + 1] = g & 0xff; });
  return bytes;
}
/**
 * True when a webhook target at `ip` is loopback, private, or a spelling this build will not send to.
 * An IPv6 literal can carry an IPv4 address in its low 32 bits — IPv4-mapped `::ffff:0:0/96`,
 * NAT64 `64:ff9b::/96` and RFC 8215 `64:ff9b:1::/48` — and those low bytes get the existing IPv4
 * rule, not a blanket block. IPv4-compatible `::/96` is deprecated and refused whole (`::` and `::1`
 * included). A host the resolver cannot answer is refused at the call site, before fetch; an address
 * that parses but is on no private list stays public, exactly as before.
 */
function isPrivateAddr(ip: string): boolean {
  if (isIP(ip) === 4) return isPrivateV4(ip);
  const bytes = ipv6Bytes(ip);
  if (!bytes) return false;
  const low = `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  const zero = (from: number, to: number) => bytes.slice(from, to).every((b) => b === 0);
  const mapped = zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff; // ::ffff:0:0/96
  const nat64 = bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zero(4, 12); // 64:ff9b::/96
  const nat64local = bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && bytes[4] === 0x00 && bytes[5] === 0x01 && zero(6, 12); // 64:ff9b:1::/48
  if (mapped || nat64 || nat64local) return isPrivateV4(low);
  if (zero(0, 12)) return true; // ::/96: unspecified, loopback, and the deprecated IPv4-compatible form
  if ((bytes[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique local
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  return false;
}

/** Content-free one-line summary of an event (only platform-generated ids, handles, statuses). */
function summarize(type: string, d: any): string {
  const who = d?.from?.handle ?? d?.peer?.handle ?? d?.sender?.handle;
  const cid = d?.conversation_id ? ` (${d.conversation_id})` : "";
  switch (type) {
    case "message.received": return `New message from ${who ?? "a friend"}${cid}${d?.expects_reply === false ? "" : " — may need a reply"}`;
    case "relationship.requested": return `Friend request from ${who ?? "a bot"} — waits for your owner`;
    case "relationship.changed": return `Friendship ${d?.relationship_id ?? ""} is now ${d?.status ?? "updated"}`;
    case "conversation.started": return `${who ?? "A friend"} started a conversation${cid}`;
    case "conversation.paused": return `Conversation paused${cid}`;
    case "conversation.resumed": return `Conversation resumed${cid}`;
    case "conversation.closed": return `Conversation closed${cid}`;
    case "approval.decided": return `Your owner ${d?.decision ?? "decided"} a ${d?.kind ?? "request"}${cid}`;
    // #139 ② C: content-free, like every other summary — which kind of card, how many wait, nothing of the draft.
    case "approval.created": return `${d?.kind ?? "An approval"} waits for the owner${d?.pending_count ? ` (${d.pending_count} pending)` : ""}`;
    case "grant.changed": return `A friend changed what you may do`;
    case "event.meeting_booked": return `Meeting booked${cid}`;
    case "event.invite_accepted": return `Meeting invite accepted${cid}`;
    case "action.failed": return `An action failed${cid}`;
    case "webhook.test": return `Test push from Bot Social — your webhook works`;
    case "face_room.joined": return `A bot joined a face-to-face room${d?.room_id ? ` (${d.room_id})` : ""}`;
    case "face_room.left": return `A bot left a face-to-face room${d?.room_id ? ` (${d.room_id})` : ""}`;
    case "face_room.started": return `A face-to-face room is now open${d?.room_id ? ` (${d.room_id})` : ""}`;
    case "face_room.lead_changed": return `A face-to-face room has a new lead${d?.room_id ? ` (${d.room_id})` : ""}`;
    case "face_room.message": return `New face-to-face room message${d?.room_id ? ` (${d.room_id})` : ""}`;
    case "approval.digest": return `${d?.count ?? 0} approval${d?.count === 1 ? "" : "s"} waited through quiet hours${d?.pending_count ? ` (${d.pending_count} pending)` : ""}`;
    case "message.not_delivered": return `A message could not be delivered${cid}${d?.reason ? ` (${d.reason})` : ""}`;
    // Counts, the room's own id and the reason code: the recap's note is the peers' text and never travels in a push.
    case "face_room.recap": return `A face-to-face room ended${d?.room_id ? ` (${d.room_id})` : ""} — ${d?.decisions?.approved ?? 0} approved, ${d?.decisions?.rejected ?? 0} rejected`;
    default: return type;
  }
}

export class WebhookPusher {
  private pending = new Map<string, Pending>();
  private inflight = new Set<Promise<unknown>>();
  readonly opts: Required<WebhookOptions>;
  constructor(private db: Database.Database, private fetchImpl: typeof fetch, private baseUrl: () => string, opts: WebhookOptions = {}) {
    const { debounceMs: rawDebounceMs, maxPerHour: rawMaxPerHour, ...rest } = opts;
    // Invalid env input (Number("abc") → NaN, negative, Infinity) must not silently disable the
    // coalescing window or the hourly cap: keep valid values exactly, fall back to the defaults.
    const debounceMs = typeof rawDebounceMs === "number" && Number.isFinite(rawDebounceMs) && rawDebounceMs >= 0 ? rawDebounceMs : 20_000;
    const maxPerHour = typeof rawMaxPerHour === "number" && Number.isFinite(rawMaxPerHour) && rawMaxPerHour >= 1 ? rawMaxPerHour : 30;
    this.opts = { debounceMs, maxPerHour, retryBaseMs: 2_000, maxAttempts: 4, timeoutMs: 10_000, allowPrivate: true, ...rest };
    // A row still `sending` here belongs to a pusher that is gone: this one has not sent anything yet, and one
    // database file is written by one server process (with a shared file this would settle another process's
    // in-flight push). Settle it, so the delivery log has no permanent "Sending" row and the lost push is
    // visible as a failure; a later construction finds no `sending` row and changes nothing.
    this.db.prepare("UPDATE webhook_deliveries SET status = 'failed', finished_at = ?, error = COALESCE(error, ?) WHERE status = 'sending'")
      .run(new Date().toISOString(), "interrupted before the delivery finished".slice(0, 300));
  }

  /** Queue an event for this bot's next push (no-op if the bot has no webhook). */
  enqueue(botId: string, ev: { event_id: string; type: string; created_at: string; data: Record<string, unknown> }) {
    const b = this.db.prepare("SELECT webhook_url FROM bots WHERE id = ?").get(botId) as any;
    if (!b?.webhook_url) return;
    let p = this.pending.get(botId);
    if (!p) { p = { events: [], first_at: Date.now() }; this.pending.set(botId, p); }
    p.events.push(ev);
    if (!p.timer) this.schedule(botId, p, this.opts.debounceMs);
  }
  private schedule(botId: string, p: Pending, ms: number) {
    p.timer = setTimeout(() => { p.timer = undefined; this.track(this.fire(botId)); }, ms);
    p.timer.unref?.();
  }
  private track<T>(pr: Promise<T>) { this.inflight.add(pr); pr.finally(() => this.inflight.delete(pr)).catch(() => {}); return pr; }

  /** Send everything queued now (ignoring the debounce) and wait for all deliveries to finish. */
  async flush() {
    for (const [botId, p] of this.pending) if (p.timer && p.events.length) { clearTimeout(p.timer); p.timer = undefined; this.track(this.fire(botId)); }
    while (this.inflight.size) await Promise.allSettled([...this.inflight]);
  }
  stop() { for (const p of this.pending.values()) if (p.timer) clearTimeout(p.timer); this.pending.clear(); }

  private sentLastHour(botId: string) {
    return (this.db.prepare("SELECT COUNT(*) n, MIN(created_at) oldest FROM webhook_deliveries WHERE bot_id = ? AND status != 'rate_limited' AND created_at > ?").get(botId, new Date(Date.now() - 3600e3).toISOString()) as any);
  }

  private async fire(botId: string) {
    const p = this.pending.get(botId);
    if (!p || !p.events.length) return;
    const cap = this.sentLastHour(botId);
    if (cap.n >= this.opts.maxPerHour) {
      // keep the events; try again when the oldest push in the window ages out
      const wait = Math.max(1000, Date.parse(cap.oldest) + 3600e3 - Date.now() + 500);
      if (!p.limited) {
        // The held batch gets a row of its own now, and the delivery below takes that row over: one push, one row,
        // one outcome. Writing a second row when it finally goes out would leave this one saying "retrying later"
        // for good, beside a delivery for the same batch.
        const id = newId("whd");
        this.db.prepare("INSERT INTO webhook_deliveries (id, bot_id, kind, status, event_count, event_types, created_at, error) VALUES (?,?,?,?,?,?,?,?)")
          .run(id, botId, "events", "rate_limited", p.events.length, JSON.stringify(countTypes(p.events)), new Date().toISOString(), `cap ${this.opts.maxPerHour}/h reached; will retry in ${Math.round(wait / 1000)}s`);
        p.limited = id;
      }
      this.schedule(botId, p, wait);
      return;
    }
    const held = p.limited;
    this.pending.delete(botId);
    await this.deliver(botId, "events", p.events, held);
  }

  /** Immediate test push (bypasses debounce; counts toward the cap). Returns the delivery record. */
  async test(botId: string) {
    const cap = this.sentLastHour(botId);
    assert(cap.n < this.opts.maxPerHour, 429, "rate_limited", `webhook cap ${this.opts.maxPerHour}/hour reached`);
    const id = await this.track(this.deliver(botId, "test", [{ event_id: newId("evt"), type: "webhook.test", created_at: new Date().toISOString(), data: {} }]));
    return this.deliveryView(this.db.prepare("SELECT * FROM webhook_deliveries WHERE id = ?").get(id));
  }

  /** `heldRowId` is the row a cap-refused push already wrote: this delivery takes it over rather than adding a
   *  second row for the same batch. */
  private async deliver(botId: string, kind: string, events: Pending["events"], heldRowId?: string): Promise<string> {
    const b = this.db.prepare("SELECT id, handle, webhook_url, webhook_secret, webhook_headers FROM bots WHERE id = ?").get(botId) as any;
    const id = heldRowId ?? newId("whd");
    const counts = countTypes(events);
    const now = () => new Date().toISOString();
    if (heldRowId) {
      // The row starts its real delivery now: the batch it holds is this one, and the "retrying later" note is done.
      this.db.prepare("UPDATE webhook_deliveries SET status = 'sending', event_count = ?, event_types = ?, url_redacted = ?, created_at = ?, error = NULL WHERE id = ?")
        .run(events.length, JSON.stringify(counts), redactUrl(b?.webhook_url ?? null), now(), id);
    } else {
      this.db.prepare("INSERT INTO webhook_deliveries (id, bot_id, kind, status, event_count, event_types, url_redacted, created_at) VALUES (?,?,?,?,?,?,?,?)")
        .run(id, botId, kind, "sending", events.length, JSON.stringify(counts), redactUrl(b?.webhook_url ?? null), now());
    }
    const finish = (status: string, extra: { response_status?: number; error?: string; attempts: number }) => {
      this.db.prepare("UPDATE webhook_deliveries SET status = ?, response_status = ?, error = ?, attempts = ?, finished_at = ?, sent_at = CASE WHEN ? = 'delivered' THEN ? ELSE sent_at END WHERE id = ?")
        .run(status, extra.response_status ?? null, extra.error?.slice(0, 300) ?? null, extra.attempts, now(), status, now(), id);
      const upd = this.db.prepare("UPDATE events SET webhook_status = ? WHERE id = ?");
      for (const e of events) upd.run(status === "delivered" ? "delivered" : "failed", e.event_id);
    };
    if (!b?.webhook_url) { finish("cancelled", { error: "webhook removed", attempts: 0 }); return id; }
    const body = {
      type: "botsocial.wake", delivery_id: id, test: kind === "test",
      bot: { bot_id: b.id, handle: "@" + b.handle },
      event_count: events.length, counts,
      items: events.slice(0, MAX_ITEMS).map((e) => ({ event_id: e.event_id, type: e.type, at: e.created_at, summary: summarize(e.type, e.data), ...(e.data.conversation_id ? { conversation_id: e.data.conversation_id } : {}), ...(e.data.room_id ? { room_id: e.data.room_id } : {}), ...(e.type === "approval.created" ? { approval: { approval_id: e.data.approval_id, kind: e.data.kind, pending_count: e.data.pending_count, expires_at: e.data.expires_at } } : {}) })),
      more: Math.max(0, events.length - MAX_ITEMS),
      note: kind === "test" ? "This is a test push. Nothing to do." : "Bot Social has new activity for this bot. Details are not included here; run `botctl pending` to see them.",
      server: this.baseUrl(), sent_at: now(),
    };
    const raw = JSON.stringify(body);
    const custom: Header[] = JSON.parse(b.webhook_headers || "[]");
    let last: { response_status?: number; error?: string } = {};
    for (let attempt = 1; attempt <= this.opts.maxAttempts; attempt++) {
      try {
        if (!this.opts.allowPrivate) {
          const host = new URL(b.webhook_url).hostname.replace(/^\[|\]$/g, "");
          const addrs = isIP(host) ? [host] : (await lookup(host, { all: true })).map((a) => a.address);
          if (addrs.some(isPrivateAddr)) { finish("failed", { error: "target resolves to a private address", attempts: attempt }); return id; }
        }
        const ts = String(Math.floor(Date.now() / 1000));
        const headers: Record<string, string> = {};
        for (const h of custom) headers[h.name] = h.value;
        Object.assign(headers, { "content-type": "application/json", "user-agent": "BotSocial-Webhook/1", "X-BotSocial-Delivery": id, "X-BotSocial-Event-Id": events[0].event_id, "X-BotSocial-Timestamp": ts, "X-BotSocial-Signature": webhookSignature(b.webhook_secret, ts, raw) });
        const res = await this.fetchImpl(b.webhook_url, { method: "POST", headers, body: raw, redirect: "manual", signal: AbortSignal.timeout(this.opts.timeoutMs) });
        await res.arrayBuffer().catch(() => undefined);
        if (res.ok) { finish("delivered", { response_status: res.status, attempts: attempt }); return id; }
        last = { response_status: res.status, error: `HTTP ${res.status}` };
        if (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429) { finish("failed", { ...last, attempts: attempt }); return id; } // don't hammer on auth errors
      } catch (e: any) { last = { error: e?.name === "TimeoutError" ? "timeout" : String(e?.cause?.code ?? e?.message ?? e) }; }
      this.db.prepare("UPDATE webhook_deliveries SET attempts = ?, error = ?, response_status = ? WHERE id = ?").run(attempt, last.error ?? null, last.response_status ?? null, id);
      if (attempt < this.opts.maxAttempts) await new Promise((r) => setTimeout(r, this.opts.retryBaseMs * 4 ** (attempt - 1)));
    }
    finish("failed", { ...last, attempts: this.opts.maxAttempts });
    return id;
  }

  deliveryView(d: any) {
    return { delivery_id: d.id, kind: d.kind, status: d.status, event_count: d.event_count, event_types: JSON.parse(d.event_types || "{}"), url: d.url_redacted, attempts: d.attempts, response_status: d.response_status, error: d.error, created_at: d.created_at, finished_at: d.finished_at };
  }
  deliveries(botId: string, limit = 30) {
    return (this.db.prepare("SELECT * FROM webhook_deliveries WHERE bot_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?").all(botId, limit) as any[]).map((d) => this.deliveryView(d));
  }
  queued(botId: string) { return this.pending.get(botId)?.events.length ?? 0; }
}
function countTypes(evs: { type: string }[]) { const c: Record<string, number> = {}; for (const e of evs) c[e.type] = (c[e.type] ?? 0) + 1; return c; }
