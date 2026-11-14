/**
 * Unfriending (or blocking) one row ends several others: every active share of the relationship is revoked, every
 * chat it made is closed, and the cards hanging off them are cancelled. The door writes one `relationship.revoked`
 * for the pair and tells both Bots `relationship.changed`; the shares and the chats it ended were named nowhere, so
 * the chain could not say which capability a Bot lost when, and a Bot whose chat was closed never heard about it —
 * while every other revoke door and both other close doors write exactly one row per row they end.
 *
 * These readings are per row: one `grant.revoked` per share that goes active -> revoked (carrying the reason, as the
 * room doors carry `room_left`/`room_closed`), one `conversation.closed` with `outcome: "revoked"` per chat that goes
 * open -> closed, and both Bots told about the chat. The pair's own row stays a single entry, and a row that was not
 * active is not named again on a second call.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { friends, startServer } from "./helpers.js";

const audit = (s: any) => s.platform.audit.db.prepare("SELECT seq, actor, action, subject, data FROM audit_events ORDER BY seq").all() as any[];
const since = (s: any, mark: number) => audit(s).filter((r) => r.seq > mark);
const head = (s: any) => (audit(s).at(-1)?.seq ?? 0);
const data = (r: any) => JSON.parse(r.data);
const events = (s: any, botId: string) =>
  (s.platform.db.prepare("SELECT type, data FROM events WHERE bot_id = ? ORDER BY seq").all(botId) as any[]).map((e) => ({ type: e.type, data: JSON.parse(e.data) }));

/** The rows this door is about to end, read before it runs: every active share, and every chat still standing. */
function ended(s: any, relId: string) {
  return {
    shares: (s.platform.db.prepare("SELECT id, capability, status FROM grants WHERE relationship_id = ? AND status = 'active'").all(relId) as any[]),
    chats: (s.platform.db.prepare("SELECT id, status FROM conversations WHERE relationship_id = ? AND status != 'closed'").all(relId) as any[]),
  };
}

async function twoFriends(t: any) {
  const s = await startServer();
  t.after(s.stop);
  const { A, B, relId } = await friends(s.base, { freebusy: true });
  const conv = (await A.bot.startConversation(B.bot.id, { type: "general_chat", summary: "the chat this door closes" })).conversation_id as string;
  return { s, A, B, relId, conv };
}

test("unfriending names every share it takes back and every chat it closes", async (t) => {
  const { s, A, B, relId, conv } = await twoFriends(t);
  const about = ended(s, relId);
  assert.ok(about.shares.length >= 2, `the fixture holds shares to end: ${JSON.stringify(about.shares)}`);
  assert.ok(about.chats.some((c) => c.id === conv), "the fixture holds a chat to close");

  const mark = head(s);
  await A.owner.req("DELETE", `/v1/relationships/${relId}`);
  const rows = since(s, mark);

  for (const g of about.shares) {
    const named = rows.filter((r) => r.action === "grant.revoked" && r.subject === g.id);
    assert.equal(named.length, 1, `one grant.revoked for the ${g.capability} share this door took back, got ${named.length}`);
    assert.equal(data(named[0]).capability, g.capability, "the row names the capability that ended");
    assert.equal(data(named[0]).relationship_id, relId, "and the relationship it belonged to");
    assert.equal(data(named[0]).reason, "revoked", "with the reason this door settles cards by");
    assert.equal(named[0].actor, `owner:${A.owner_id}`, "attributed to the owner who removed the friendship");
  }
  assert.equal(rows.filter((r) => r.action === "grant.revoked").length, about.shares.length, "one row per share, none twice");

  for (const c of about.chats) {
    const named = rows.filter((r) => r.action === "conversation.closed" && r.subject === c.id);
    assert.equal(named.length, 1, `one conversation.closed for the chat this door closed, got ${named.length}`);
    assert.equal(data(named[0]).outcome, "revoked", "the chat was not closed by agreement");
  }
  assert.equal(rows.filter((r) => r.action === "conversation.closed").length, about.chats.length, "one row per chat, none twice");

  assert.equal(rows.filter((r) => r.action === "relationship.revoked").length, 1, "the pair's own row is still one entry");

  for (const bot of [A.bot.id, B.bot.id]) {
    const told = events(s, bot).filter((e) => e.type === "conversation.closed" && e.data.conversation_id === conv);
    assert.equal(told.length, 1, "each side hears the chat closed, and only once");
    assert.equal(told[0].data.outcome, "revoked", "with the outcome the row carries");
  }
});

test("a block names them with its own reason, and a second call names nothing twice", async (t) => {
  const { s, A, relId } = await twoFriends(t);
  const about = ended(s, relId);

  const mark = head(s);
  await A.owner.req("POST", "/v1/blocks", { relationship_id: relId });
  const rows = since(s, mark);

  for (const g of about.shares) {
    const named = rows.filter((r) => r.action === "grant.revoked" && r.subject === g.id);
    assert.equal(named.length, 1, `one grant.revoked per share on a block too, got ${named.length}`);
    assert.equal(data(named[0]).reason, "blocked", "a block says so, as the card decision it settles says so");
  }
  assert.equal(rows.filter((r) => r.action === "conversation.closed").length, about.chats.length, "one row per chat on a block too");

  // The pair's rows are already revoked: a second door over the same relationship finds nothing active and names
  // nothing again. Unblocking writes its own row and restores nothing, so this is where the count must stay.
  const again = head(s);
  await A.owner.req("POST", `/v1/blocks/${relId}/undo`);
  const undoRows = since(s, again);
  assert.equal(undoRows.filter((r) => r.action === "grant.revoked").length, 0, "an undo revokes nothing, so it names no share");
  assert.equal(undoRows.filter((r) => r.action === "conversation.closed").length, 0, "and no chat");
});
