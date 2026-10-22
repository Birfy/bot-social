import assert from "node:assert/strict";
import { test } from "node:test";
import { loadFaceRoomLimits, newInviteTicket, isInviteTicket } from "../src/face-rooms.js";
import { ownerWithBot, startServer } from "./helpers.js";

async function req(base: string, method: string, path: string, token?: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(base + path, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const json = text ? JSON.parse(text) : {};
  return { status: r.status, body: json };
}
const tok = (o: { owner: { token: string } }) => o.owner.token;
const newRoom = (base: string, o: { owner: { token: string }; bot: { id: string } }, code: string) =>
  req(base, "POST", "/v1/face-rooms/join", tok(o), { code, bots: [o.bot.id] });
const mint = (base: string, o: { owner: { token: string } }, roomId: string) =>
  req(base, "POST", `/v1/face-rooms/${roomId}/invites`, tok(o));
const joinInvite = (base: string, o: { owner: { token: string }; bot: { id: string } }, ticket: string, extra: Record<string, unknown> = {}) =>
  req(base, "POST", "/v1/face-rooms/join-invite", tok(o), { ticket, bots: [o.bot.id], ...extra });
const preview = (base: string, ticket: string, ip?: string) =>
  req(base, "GET", `/v1/face-rooms/invites/${encodeURIComponent(ticket)}`, undefined, undefined, ip ? { "x-forwarded-for": ip } : {});

test("the ticket helpers: 256 random bits, base64url, nothing else accepted", () => {
  const t = newInviteTicket();
  assert.equal(t.length, 43);
  assert.match(t, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(t, newInviteTicket());
  assert.equal(isInviteTicket(t), true);
  assert.equal(isInviteTicket("short"), false);
  assert.equal(isInviteTicket(""), false);
  assert.equal(isInviteTicket(null), false);
  assert.equal(loadFaceRoomLimits().inviteTtlMs, 600_000);
  assert.equal(loadFaceRoomLimits({ inviteTtlMs: 1000 }).inviteTtlMs, 1000);
});

test("the lead mints a ticket and a second owner joins that same room with it", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const room = await newRoom(s.base, A, "313131");
  assert.equal(room.status, 200);
  const m = await mint(s.base, A, room.body.room_id);
  assert.equal(m.status, 201);
  assert.equal(m.body.room_id, room.body.room_id);
  assert.match(m.body.ticket, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(m.body.url, `${s.base}/r/${m.body.ticket}`);
  assert.ok(Date.parse(m.body.expires_at) > Date.now());

  const p = await preview(s.base, m.body.ticket);
  assert.equal(p.status, 200);
  assert.equal(p.body.room_id, room.body.room_id);
  assert.equal(p.body.member_count, 1);
  assert.equal(p.body.max_members, 8);
  assert.equal(p.body.lead.handle, A.handle);
  assert.equal(p.body.expires_at, m.body.expires_at);
  assert.equal(p.body.name, null);

  const b = await joinInvite(s.base, B, m.body.ticket);
  assert.equal(b.status, 200);
  assert.equal(b.body.room_id, room.body.room_id);
  assert.equal(b.body.members.length, 2);
  assert.ok(b.body.members.some((x: any) => x.handle === B.handle));
  const mine = await req(s.base, "GET", "/v1/face-rooms", tok(B));
  assert.ok(mine.body.rooms.some((r: any) => r.room_id === room.body.room_id));
  // The room grant is written: B's Bot sees the room members it now shares.
  const again = await joinInvite(s.base, B, m.body.ticket);
  assert.equal(again.status, 409);
  assert.equal(again.body.error.code, "already_member");
});

test("only the room lead may mint or revoke a ticket", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const room = await newRoom(s.base, A, "323232");
  await joinInvite(s.base, B, (await mint(s.base, A, room.body.room_id)).body.ticket);
  const denied = await mint(s.base, B, room.body.room_id);
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error.code, "not_lead");
  const ticket = (await mint(s.base, A, room.body.room_id)).body.ticket;
  const revokeByB = await req(s.base, "DELETE", `/v1/face-rooms/${room.body.room_id}/invites/${ticket}`, tok(B));
  assert.equal(revokeByB.status, 403);
  assert.equal(revokeByB.body.error.code, "not_lead");
});

test("a revoked ticket answers revoked; an unknown or malformed one is the same shape", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const room = await newRoom(s.base, A, "333333");
  const ticket = (await mint(s.base, A, room.body.room_id)).body.ticket;
  const del = await req(s.base, "DELETE", `/v1/face-rooms/${room.body.room_id}/invites/${ticket}`, tok(A));
  assert.equal(del.status, 200);
  assert.equal(del.body.revoked, true);
  const join = await joinInvite(s.base, B, ticket);
  assert.equal(join.status, 410);
  assert.equal(join.body.error.code, "revoked");
  const p = await preview(s.base, ticket);
  assert.equal(p.status, 410);
  assert.equal(p.body.error.code, "revoked");
  const unknown = await joinInvite(s.base, B, newInviteTicket());
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.error.code, "invite_not_found");
  const malformed = await joinInvite(s.base, B, "not-a-ticket");
  assert.equal(malformed.status, 404);
  assert.equal(malformed.body.error.code, "invite_not_found");
});

test("expiry is enforced server-side, on the join and on the preview", async (t) => {
  let now = Date.now();
  const s = await startServer({ now: () => now, faceRooms: { inviteTtlMs: 60_000 } });
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const room = await newRoom(s.base, A, "343434");
  const m = await mint(s.base, A, room.body.room_id);
  now += 60_001;
  const join = await joinInvite(s.base, B, m.body.ticket);
  assert.equal(join.status, 410);
  assert.equal(join.body.error.code, "expired");
  const p = await preview(s.base, m.body.ticket);
  assert.equal(p.status, 410);
  assert.equal(p.body.error.code, "expired");
});

test("a full room answers room_full even with a valid ticket", async (t) => {
  const s = await startServer({ faceRooms: { maxMembers: 2 } });
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const C = await ownerWithBot(s.base, "cid");
  const room = await newRoom(s.base, A, "353535");
  const ticket = (await mint(s.base, A, room.body.room_id)).body.ticket;
  await joinInvite(s.base, B, ticket);
  const third = await joinInvite(s.base, C, ticket);
  assert.equal(third.status, 409);
  assert.equal(third.body.error.code, "room_full");
  // the ticket is still usable for a Bot that is already inside? no: it is already a member
  const full = await preview(s.base, ticket);
  assert.equal(full.body.member_count, 2);
  assert.equal(full.body.max_members, 2);
});

test("a room that ended answers ended instead of half-applying the join", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const room = await newRoom(s.base, A, "363636");
  await joinInvite(s.base, B, (await mint(s.base, A, room.body.room_id)).body.ticket);
  const ticket = (await mint(s.base, A, room.body.room_id)).body.ticket;
  const C = await ownerWithBot(s.base, "cid");
  await req(s.base, "POST", `/v1/face-rooms/${room.body.room_id}/leave`, tok(A), {});
  await req(s.base, "POST", `/v1/face-rooms/${room.body.room_id}/leave`, tok(B), {});
  const join = await joinInvite(s.base, C, ticket);
  assert.equal(join.status, 410);
  assert.equal(join.body.error.code, "ended");
  const listed = await req(s.base, "GET", "/v1/face-rooms", tok(C));
  assert.equal(listed.body.rooms.length, 0);
});

test("previews are rate-limited per address, so a leaked ticket cannot be brute-forced", async (t) => {
  const s = await startServer({ faceRooms: { attemptsPerIp: 3, attemptWindowMs: 60_000 } });
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const room = await newRoom(s.base, A, "373737");
  const ticket = (await mint(s.base, A, room.body.room_id)).body.ticket;
  const ip = "203.0.113.7";
  assert.equal((await preview(s.base, ticket, ip)).status, 200);
  assert.equal((await preview(s.base, newInviteTicket(), ip)).status, 404);
  assert.equal((await preview(s.base, ticket, ip)).status, 200);
  const blocked = await preview(s.base, ticket, ip);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.error.code, "rate_limited");
});
