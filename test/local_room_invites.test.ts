import assert from "node:assert/strict";
import { test } from "node:test";
import { generateEd25519 } from "../src/crypto.js";
import { isLocalInviteTicket, newLocalInviteTicket } from "../src/local-room-invites.js";
import { ownerWithBot, startServer } from "./helpers.js";

// Bot Social #60: a ticket for a room that lives in one FlyBot home. The server keeps the ticket, never the room.

async function req(base: string, method: string, path: string, token?: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(base + path, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const json = text ? JSON.parse(text) : {};
  return { status: r.status, body: json.error ? json.error : json };
}
const tok = (o: any) => o.owner.token;
const owner = (o: any) => ({ kind: "owner" as const, ownerId: o.owner_id });
const ROOM = "session-3f2a9c1e-6b7d-4e1a-9f0c-2d4b6a8c0e12";
const mint = (base: string, o: any, body: Record<string, unknown> = {}) =>
  req(base, "POST", "/v1/local-room-invites", tok(o), { room_id: ROOM, name: "Launch plan", bot_id: o.bot.id, ...body });
const preview = (base: string, ticket: string, token?: string, ip?: string) =>
  req(base, "GET", `/v1/local-room-invites/${encodeURIComponent(ticket)}`, token, undefined, ip ? { "x-forwarded-for": ip } : {});
const claim = (base: string, o: any, ticket: string, bots: string[]) =>
  req(base, "POST", `/v1/local-room-invites/${encodeURIComponent(ticket)}/claim`, tok(o), { bots });
const revoke = (base: string, o: any, ticket: string) => req(base, "DELETE", `/v1/local-room-invites/${encodeURIComponent(ticket)}`, tok(o));
async function secondBot(base: string, o: any, suffix: string) {
  const kp = generateEd25519();
  const handle = `${o.handle.slice(1).replace(/\.bot$/, "")}${suffix}.bot`;
  const r = await o.owner.req("POST", "/v1/bots", { handle, public_key: { alg: "Ed25519", kid: "k1", value: kp.publicKey } });
  return { id: r.bot_id as string, handle: `@${handle}`, kp };
}

test("#60: the ticket helpers — 22 characters of base64url, the shape a local link carries", () => {
  const t = newLocalInviteTicket();
  assert.match(t, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(t, newLocalInviteTicket());
  assert.equal(isLocalInviteTicket(t), true);
  assert.equal(isLocalInviteTicket("a".repeat(15)), false);
  assert.equal(isLocalInviteTicket("a".repeat(65)), false);
  assert.equal(isLocalInviteTicket("has.dot.in.it.abcdefgh"), false);
});

test("#60: mint answers the two-segment link, the preview is public, and the platform lists the feature", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const m = await mint(s.base, A);
  assert.equal(m.status, 201, JSON.stringify(m.body));
  assert.equal(m.body.kind, "local_room");
  assert.match(m.body.ticket, /^[A-Za-z0-9_-]{16,64}$/);
  assert.equal(m.body.url, `${s.base}/r/${A.handle}/${m.body.ticket}`);
  assert.equal(m.body.room_id, ROOM);
  const left = Date.parse(m.body.expires_at) - Date.now();
  assert.ok(left > 9 * 60e3 && left <= 10 * 60e3, `ten minutes, got ${left}`);
  assert.equal(m.body.inviter.handle, A.handle);

  const p = await preview(s.base, m.body.ticket);
  assert.equal(p.status, 200);
  assert.equal(p.body.kind, "local_room");
  assert.equal(p.body.name, "Launch plan");
  assert.equal(p.body.lead.handle, A.handle);
  assert.equal(typeof p.body.lead.owner_name, "string");
  assert.equal(p.body.expires_at, m.body.expires_at);
  assert.equal(p.body.claimed, false);
  assert.equal("claimer" in p.body, false, "an anonymous caller never sees a claimer field");
  const mine = await preview(s.base, m.body.ticket, tok(A));
  assert.equal(mine.body.claimer, null);

  const info = await req(s.base, "GET", "/v1/platform");
  assert.ok(info.body.features.includes("local_room_invites"));
  assert.ok(info.body.features.includes("face_room_invites"), "the face-room feature is still listed");
});

test("#60: a room name is cleaned, a bad room id is refused, and a face room keeps its own invitation", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const named = await mint(s.base, A, { name: "<b>War\nroom</b> @all" });
  assert.equal(named.status, 201);
  assert.doesNotMatch(String(named.body.name), /[<>@\n]/);
  assert.equal((await mint(s.base, A, { room_id: "has space" })).status, 400);
  assert.equal((await mint(s.base, A, { room_id: "x".repeat(65) })).status, 400);
  const face = await req(s.base, "POST", "/v1/face-rooms/join", tok(A), { code: "616161", bots: [A.bot.id] });
  assert.equal(face.status, 200);
  const clash = await mint(s.base, A, { room_id: face.body.room_id });
  assert.equal(clash.status, 409);
  assert.equal(clash.body.code, "face_room");
  const B = await ownerWithBot(s.base, "ben");
  const theirs = await mint(s.base, A, { bot_id: B.bot.id });
  assert.equal(theirs.status, 404, "a link can only knock on one of your own Bots");
});

test("#60: one claim binds a home and its Bots, once; every other claim has its own refusal", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const C = await ownerWithBot(s.base, "cat");
  const B2 = await secondBot(s.base, B, "two");
  const m = await mint(s.base, A);
  const ticket = m.body.ticket as string;

  const own = await claim(s.base, A, ticket, [A.bot.id]);
  assert.equal(own.status, 409);
  assert.equal(own.body.code, "own_invite");
  const foreign = await claim(s.base, B, ticket, [C.bot.id]);
  assert.equal(foreign.status, 404, "a home cannot bring a Bot it does not own");
  assert.equal(foreign.body.code, "bot_not_found");

  const first = await claim(s.base, B, ticket, [B.bot.id, B2.handle]);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.claimed, true);
  assert.equal(first.body.room_id, ROOM);
  assert.equal(first.body.inviter.handle, A.handle);
  assert.deepEqual([...first.body.bots].sort(), [B.handle, B2.handle].sort());

  const retry = await claim(s.base, B, ticket, [B2.id, B.handle]);
  assert.equal(retry.status, 200, "the same home with the same Bots is the idempotent retry");
  const otherSet = await claim(s.base, B, ticket, [B.bot.id]);
  assert.equal(otherSet.status, 409);
  assert.equal(otherSet.body.code, "already_claimed");
  const otherHome = await claim(s.base, C, ticket, [C.bot.id]);
  assert.equal(otherHome.status, 409);
  assert.equal(otherHome.body.code, "already_claimed");

  // The inviter re-reads the claimer; an anonymous caller only learns that it is claimed.
  const seen = await preview(s.base, ticket, tok(A));
  assert.deepEqual([...seen.body.claimer.bots].sort(), [B.handle, B2.handle].sort());
  assert.deepEqual(seen.body.claimer.members.map((m: any) => m.handle).sort(), [B.handle, B2.handle].sort(), "each seat carries a name to show");
  assert.ok(seen.body.claimer.members.every((m: any) => typeof m.display_name === "string" && m.display_name), "names are cleaned strings");
  const anon = await preview(s.base, ticket);
  assert.equal(anon.body.claimed, true);
  assert.equal("claimer" in anon.body, false);
  const stranger = await preview(s.base, ticket, tok(C));
  assert.equal("claimer" in stranger.body, false, "a third owner is as anonymous as no token");

  const unknown = await claim(s.base, B, newLocalInviteTicket(), [B.bot.id]);
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.code, "invite_not_found");
  assert.equal((await preview(s.base, newLocalInviteTicket())).body.code, "invite_not_found");
});

test("#60: an expired or withdrawn ticket refuses a claim and writes nothing", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const count = () => (s.platform.db.prepare("SELECT COUNT(*) n FROM grants").get() as any).n as number;
  const late = await mint(s.base, A);
  const gone = await mint(s.base, A);
  assert.equal((await revoke(s.base, A, gone.body.ticket)).status, 204);
  const before = count();
  const real = s.platform.nowMs;
  s.platform.nowMs = () => real() + 11 * 60e3;
  const expired = await claim(s.base, B, late.body.ticket, [B.bot.id]);
  s.platform.nowMs = real;
  assert.equal(expired.status, 410);
  assert.equal(expired.body.code, "expired");
  const revoked = await claim(s.base, B, gone.body.ticket, [B.bot.id]);
  assert.equal(revoked.status, 410);
  assert.equal(revoked.body.code, "revoked");
  assert.equal(count(), before, "no grant for a refused claim");
  assert.equal((await preview(s.base, gone.body.ticket)).body.code, "revoked");
});

test("#60: several live tickets for one room; revoking one leaves the other", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const C = await ownerWithBot(s.base, "cat");
  const one = await mint(s.base, A);
  const two = await mint(s.base, A);
  assert.notEqual(one.body.ticket, two.body.ticket);
  assert.equal((await revoke(s.base, A, one.body.ticket)).status, 204);
  assert.equal((await claim(s.base, B, one.body.ticket, [B.bot.id])).status, 410);
  assert.equal((await claim(s.base, C, two.body.ticket, [C.bot.id])).status, 200);
  assert.equal((await revoke(s.base, B, two.body.ticket)).status, 403, "a third owner cannot end it");
  assert.equal((await revoke(s.base, A, one.body.ticket)).status, 404, "a second revoke finds nothing");
});

test("#60: the claim is the room door — the pair talks naming that room, and nowhere else", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben"); // a stranger: no friendship, no shared Bot
  const C = await ownerWithBot(s.base, "cat");
  s.platform.enableCustody(owner(A), A.bot.id, { private_key_pem: A.kp.privateKeyPem });
  s.platform.enableCustody(owner(B), B.bot.id, { private_key_pem: B.kp.privateKeyPem });
  const m = await mint(s.base, A);
  // Before the claim the stranger cannot reach the inviter at all, with or without the room.
  assert.throws(() => s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "knock", room_id: ROOM }), (e: any) => e.code === "room_not_shared");
  assert.equal((await claim(s.base, B, m.body.ticket, [B.bot.id])).status, 200);

  const ask = s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "FLYBOT-ROOM-SHARE ask", room_id: ROOM });
  assert.equal(ask.message.status, "delivered");
  assert.deepEqual((ask.message as any).policy.reasons, ["room.context", "dlp.clean"]);
  const back = s.platform.sendAsMember(owner(A), { from_bot_id: A.bot.id, to: B.handle, text: "welcome to the group", room_id: ROOM });
  assert.equal(back.message.status, "delivered", "the inviter answers on the same door");
  const arrived = await B.bot.events(0);
  assert.ok(arrived.events.some((e: any) => e.event_type === "message.received" && e.from.handle === A.handle));

  // The claim is not a friendship: a 1:1 send, another room, or a third Bot are all still refused.
  assert.throws(() => s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "plain" }), (e: any) => e.code === "no_relationship");
  assert.throws(() => s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "x", room_id: "session-other" }), (e: any) => e.code === "room_not_shared");
  assert.throws(() => s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: C.handle, text: "x", room_id: ROOM }), (e: any) => e.code === "room_not_shared");
  const rels = s.platform.db.prepare("SELECT status FROM relationships WHERE (requester_bot = ? AND target_bot = ?) OR (requester_bot = ? AND target_bot = ?)").all(A.bot.id, B.bot.id, B.bot.id, A.bot.id) as any[];
  assert.deepEqual(rels.map((r) => r.status), ["room"], "no friendship row is written");

  // The seat outlives the ten minutes it took to claim it.
  const real = s.platform.nowMs;
  s.platform.nowMs = () => real() + 60 * 60e3;
  assert.equal(s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "an hour later", room_id: ROOM }).message.status, "delivered");
  s.platform.nowMs = real;

  // Withdrawn by the inviter: the door is gone.
  assert.equal((await revoke(s.base, A, m.body.ticket)).status, 204);
  assert.throws(() => s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "after", room_id: ROOM }), (e: any) => e.code === "room_not_shared");
  assert.throws(() => s.platform.sendAsMember(owner(A), { from_bot_id: A.bot.id, to: B.handle, text: "after", room_id: ROOM }), (e: any) => e.code === "room_not_shared");
});

test("#60: the guest's own release ends its reach, and the inviter's other guest keeps theirs", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const C = await ownerWithBot(s.base, "cat");
  s.platform.enableCustody(owner(B), B.bot.id, { private_key_pem: B.kp.privateKeyPem });
  s.platform.enableCustody(owner(C), C.bot.id, { private_key_pem: C.kp.privateKeyPem });
  const forB = await mint(s.base, A);
  const forC = await mint(s.base, A);
  assert.equal((await claim(s.base, B, forB.body.ticket, [B.bot.id])).status, 200);
  assert.equal((await claim(s.base, C, forC.body.ticket, [C.bot.id])).status, 200);
  assert.equal((await revoke(s.base, B, forB.body.ticket)).status, 204, "the claimer may release its own claim");
  assert.throws(() => s.platform.sendAsMember(owner(B), { from_bot_id: B.bot.id, to: A.handle, text: "x", room_id: ROOM }), (e: any) => e.code === "room_not_shared");
  assert.equal(s.platform.sendAsMember(owner(C), { from_bot_id: C.bot.id, to: A.handle, text: "still here", room_id: ROOM }).message.status, "delivered");
  // A released ticket is spent: it reopens neither for the same home nor for another one.
  const again = await claim(s.base, B, forB.body.ticket, [B.bot.id]);
  assert.equal(again.status, 409);
  assert.equal(again.body.code, "already_claimed");
  const D = await ownerWithBot(s.base, "dan");
  assert.equal((await claim(s.base, D, forB.body.ticket, [D.bot.id])).body.code, "already_claimed");
});

test("#60: the public preview has its own per-address limit", async (t) => {
  const s = await startServer({ faceRooms: { attemptsPerIp: 3 } });
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const m = await mint(s.base, A);
  for (let i = 0; i < 3; i += 1) assert.equal((await preview(s.base, m.body.ticket, undefined, "203.0.113.9")).status, 200);
  const blocked = await preview(s.base, m.body.ticket, undefined, "203.0.113.9");
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.code, "rate_limited");
  assert.equal((await preview(s.base, m.body.ticket, undefined, "203.0.113.10")).status, 200, "another address is not blocked");
});
