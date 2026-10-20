import assert from "node:assert/strict";
import { test } from "node:test";
import { CAPS, flybotHomes, req } from "./flybot_helpers.js";

/** Alice (Writer) and Bob (Coder) are already friends via an invite. */
async function friends(t: any) {
  const h = await flybotHomes(t);
  const inv = await h.A("create_invite", { bot_id: h.writer.bot_id, ...CAPS });
  const joined = await h.B("join_invite", { code: inv.code, from_bot_id: h.coder.bot_id });
  assert.equal(joined.status, "active");
  return { ...h, joined };
}

test("#34: grant_bot_to_friend shares another Bot with an existing friend (MCP + lists)", async (t) => {
  const { s, a, b, A, B, writer, chief, coder, joined } = await friends(t);
  // Writer is already shared; share Chief with Bob (no invite).
  const out = await A("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: b.owner_id });
  assert.equal(out.error, undefined, JSON.stringify(out));
  assert.equal(out.status, "active");
  assert.equal(out.bot_id, chief.bot_id);
  assert.equal(out.friend_owner_id, b.owner_id);
  assert.equal(out.grantee_bot, coder.bot_id);
  assert.equal(out.reply_only, false);
  assert.equal(out.idempotent, false);
  assert.ok(out.grant_id);
  assert.ok(out.relationship_id);
  assert.notEqual(out.relationship_id, joined.relationship_id, "Chief gets its own relationship endpoint");

  const aliceGrants = await A("list_bot_grants", { bot_id: chief.bot_id });
  assert.ok(aliceGrants.grants.some((g: any) => g.grantee.handle === coder.handle && g.reply_only === false));

  const remote = await B("list_remote_bots");
  const item = remote.bots.find((x: any) => x.handle === chief.handle);
  assert.ok(item, "Chief appears for Bob");
  assert.equal(item.reply_only, false);
  assert.equal(item.relationship_id, out.relationship_id);
  // grant_id is one row of the capability bundle; list_remote_bots may surface another row of the same share
  assert.ok(item.grant_id);
  const aliceListed = (await A("list_bot_grants", { bot_id: chief.bot_id })).grants.find((g: any) => g.grantee.handle === coder.handle);
  assert.equal(aliceListed.grant_id, item.grant_id);

  // Reciprocal reply-only: Alice can reply to Coder via Chief's relationship, not start from Bob's side wrongly.
  const replyOnly = s.platform.db.prepare(
    "SELECT COUNT(*) n FROM grants WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ? AND status = 'active' AND reply_only = 1"
  ).get(out.relationship_id, b.owner_id, chief.bot_id) as any;
  assert.ok(replyOnly.n >= 1, "reply-only back to Chief exists");

  // Chat works: Bob's Coder → Alice's Chief.
  const sent = await B("send_as_member", { from_bot_id: coder.bot_id, to: chief.handle, text: "hi chief" });
  assert.match(sent.conversation_id, /.+/);

  // Friend notified.
  const ev = s.platform.listEvents({ kind: "bot", botId: coder.bot_id, ownerId: b.owner_id } as any, 0) as any;
  assert.ok(ev.events.some((e: any) => e.event_type === "grant.changed" && e.status === "granted"), JSON.stringify(ev.events.slice(0, 5)));
});

test("#34: idempotent when a live grant already exists", async (t) => {
  const { b, A, writer } = await friends(t);
  const first = await A("grant_bot_to_friend", { bot_id: writer.bot_id, friend_owner_id: b.owner_id });
  assert.equal(first.idempotent, true, "Writer was already shared via the invite join");
  assert.equal(first.status, "active");
  const second = await A("grant_bot_to_friend", { bot_id: writer.bot_id, friend_owner_id: b.owner_id });
  assert.equal(second.idempotent, true);
  assert.equal(second.grant_id, first.grant_id);
  assert.equal(second.relationship_id, first.relationship_id);
});

test("#34: owner-only, friend-only; strangers and self refused", async (t) => {
  const { s, a, b, c, A, B, C, chief } = await friends(t);
  assert.equal((await A("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: a.owner_id })).error.code, "invalid_request");
  assert.equal((await A("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: c.owner_id })).error.code, "friend_not_found");
  assert.equal((await A("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: "own_nope" })).error.code, "friend_not_found");
  assert.equal((await B("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: a.owner_id })).error.code, "bot_not_found");
  assert.equal((await C("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: a.owner_id })).error.code, "bot_not_found");
  // REST with connector token
  const ok = await req(s.base, "POST", `/v1/bots/${chief.bot_id}/grants`, a.connector.token, { friend_owner_id: b.owner_id });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  assert.equal(ok.body.status, "active");
  const again = await req(s.base, "POST", `/v1/bots/${chief.bot_id}/grants`, a.connector.token, { friend_owner_id: b.owner_id });
  assert.equal(again.status, 201);
  assert.equal(again.body.idempotent, true);
  assert.equal((await req(s.base, "POST", `/v1/bots/${chief.bot_id}/grants`, c.connector.token, { friend_owner_id: b.owner_id })).status, 404);
  assert.equal((await req(s.base, "POST", `/v1/bots/${chief.bot_id}/grants`, undefined, { friend_owner_id: b.owner_id })).status, 401);
});

test("#34: friend can decline; owner can revoke; re-grant works", async (t) => {
  const { a, b, A, B, chief, coder } = await friends(t);
  const out = await A("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: b.owner_id });
  assert.equal(out.status, "active");

  const declined = await B("decline_bot_grant", { grant_id: out.grant_id, bot_id: chief.handle });
  assert.equal(declined.status, "declined");
  assert.ok(!(await B("list_remote_bots")).bots.some((x: any) => x.handle === chief.handle));
  assert.deepEqual((await A("list_bot_grants", { bot_id: chief.bot_id })).grants.filter((g: any) => g.grantee.handle === coder.handle), []);

  const again = await A("grant_bot_to_friend", { bot_id: chief.bot_id, friend_owner_id: b.owner_id });
  assert.equal(again.status, "active");
  assert.equal(again.idempotent, false);
  assert.notEqual(again.grant_id, out.grant_id);
  assert.ok((await B("list_remote_bots")).bots.some((x: any) => x.handle === chief.handle && x.reply_only === false));

  const rev = await A("revoke_bot_grant", { grant_id: again.grant_id, bot_id: chief.bot_id });
  assert.equal(rev.status, "revoked");
  assert.ok(!(await B("list_remote_bots")).bots.some((x: any) => x.handle === chief.handle));
});
