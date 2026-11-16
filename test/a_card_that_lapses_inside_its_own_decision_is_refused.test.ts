/**
 * #792: a row that lapses inside its own deciding call is settled by the sweep, not decided by that call.
 *
 * Two doors read the row they judge, take every refusal, and only then run the platform-wide sweep `expireStale()`
 * before they write the decision: `consent` accepts a friend request, and `decideApproval` writes `approved` for a
 * card. The sweep is a clock: if the row's own `expires_at` crossed now in the window between the read and the sweep,
 * `expireStale` settles that very row (`expired`, its audit line, the invite use it spent, the Bot's decision), and
 * the call that was about to decide it writes a second, opposite outcome on top: `active` on the same relationship,
 * `approved` on the same card and a second `approval.decided` event. One row ends with two outcomes, and a Bot hears
 * two opposite decisions about one card.
 *
 * What must happen instead: the call loses. After the sweep, before any covering write or emit, the row is read again;
 * a row the sweep settled is answered with the door's existing `409 invalid_state` and nothing else is written, emitted
 * or audited. The sweep's settlement is the only decision the call leaves behind, and the sweep keeps its meaning for
 * every other row. `consent` must not exempt its own row from the clock either — that would let a request that really
 * lapsed be accepted later.
 *
 * The window is opened deterministically, with no clock or hook in `src`: a method the door reaches after its own
 * state check and before the sweep is wrapped in the test and pushes that row's expiry into the past once. On the base
 * both cases end with the double settlement; the assertions below pin the one-outcome answer.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { bulkAuth, friends, inDays, ownerWithBot, startServer } from "./helpers.js";

type S = Awaited<ReturnType<typeof startServer>>;

const past = () => new Date(Date.now() - 3600e3).toISOString();
const count = (db: any, sql: string, ...args: unknown[]) => (db.prepare(sql).get(...args) as any).n as number;
const meeting = () => ({
  type: "schedule_meeting", summary: "sync",
  params: { duration_minutes: 30, window: { start: inDays(1, 0), end: inDays(8, 23) } },
});

/** The call's answer: the result it returned, or the error it threw. */
async function answered(call: Promise<any>): Promise<{ out?: any; error?: any }> {
  try { return { out: await call }; } catch (error) { return { error }; }
}

test("an acceptance whose own request lapses during the call is not accepted", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "lapsedaccepta");
  const B = await ownerWithBot(s.base, "lapsedacceptb");
  // A one-use link whose join waits for A: the request is `pending_target` and the link has spent its only use.
  const inv = (s.platform as any).createInvite({ kind: "owner", ownerId: A.owner_id }, { bot_id: A.bot.id, auto_accept: false, max_uses: 1 });
  const joined: any = await B.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: B.bot.id });
  assert.equal(joined.status, "pending_target", JSON.stringify(joined));
  const relId = joined.relationship_id as string;

  // The window: `consent` has read and judged the row (`pending_target`), and the next thing it reaches is the
  // invitee check -- the row's own clock crosses now there, before the sweep.
  const platform: any = s.platform;
  const realInvitable = platform.assertInvitable.bind(platform);
  let armed = true;
  platform.assertInvitable = (bot: any) => {
    if (armed) {
      armed = false;
      platform.db.prepare("UPDATE relationships SET expires_at = ? WHERE id = ?").run(past(), relId);
    }
    return realInvitable(bot);
  };
  t.after(() => { platform.assertInvitable = realInvitable; });

  const eventsBefore = count(platform.db, "SELECT COUNT(*) n FROM events WHERE bot_id IN (?,?)", A.bot.id, B.bot.id);
  const { out, error } = await answered(A.owner.req("POST", `/v1/relationships/${relId}/consent`, { decision: "accept" }));

  const row: any = platform.db.prepare("SELECT status FROM relationships WHERE id = ?").get(relId);
  const grants = count(platform.db, "SELECT COUNT(*) n FROM grants WHERE relationship_id = ?", relId);
  const accepted = count(platform.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.accepted' AND subject = ?", relId);
  const expired = count(platform.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.expired' AND subject = ?", relId);
  const eventsAfter = count(platform.db, "SELECT COUNT(*) n FROM events WHERE bot_id IN (?,?)", A.bot.id, B.bot.id);
  const uses = (platform.db.prepare("SELECT uses FROM invites WHERE code = ?").get(inv.code) as any).uses;

  // The failure message carries the base's two outcomes, not only the missing 409.
  assert.ok(error, `a call whose own request lapsed before its sweep must refuse, not accept: it answered ${JSON.stringify(out)}; the row reads ${row.status}, audits expired=${expired} accepted=${accepted}, grants=${grants}, events added=${eventsAfter - eventsBefore}, invite uses=${uses}`);
  assert.equal(error.status, 409);
  assert.equal(error.code, "invalid_state");
  assert.equal(row.status, "expired", "the sweep's settlement is the only outcome on the row");
  assert.equal(grants, 0, "an accepted friendship would have written grants");
  assert.equal(accepted, 0, "no acceptance was recorded on the audit chain");
  assert.equal(expired, 1, "the sweep's expiry is the one settlement the call leaves");
  assert.equal(eventsAfter, eventsBefore, "neither Bot was told the friendship became active");
  assert.equal(uses, 0, "the one-use link stays spent: the join never became a friendship");
});

test("an approval whose own card lapses during the call is not decided", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B } = await friends(s.base);
  const conv: any = await A.bot.startConversation(B.bot.id, meeting());
  const drafted: any = await A.bot.draftMessage(conv.conversation_id, { text: "a line whose card lapses inside its own decision" });
  assert.ok(drafted.approval_id, `a drafted line waits on a card: ${JSON.stringify(drafted)}`);
  const card = drafted.approval_id as string;
  const subject = (s.platform.db.prepare("SELECT subject_id FROM approvals WHERE id = ?").get(card) as any).subject_id as string;

  // The window: every refusal the door makes about this card is behind it, and the next step is the delivery
  // moment -- the card's own clock crosses now there, before the sweep.
  const platform: any = s.platform;
  const realShareGone = platform.heldCardShareGone.bind(platform);
  let armed = true;
  platform.heldCardShareGone = (approval: any) => {
    if (armed) {
      armed = false;
      platform.db.prepare("UPDATE approvals SET expires_at = ? WHERE id = ?").run(past(), card);
    }
    return realShareGone(approval);
  };
  t.after(() => { platform.heldCardShareGone = realShareGone; });

  const eventsBefore = count(platform.db, "SELECT COUNT(*) n FROM events WHERE bot_id IN (?,?)", A.bot.id, B.bot.id);
  const { out, error } = await answered(A.owner.req("POST", `/v1/approvals/${card}/decision`, { decision: "approved" }));

  const row: any = platform.db.prepare("SELECT status, decision FROM approvals WHERE id = ?").get(card);
  const message: any = platform.db.prepare("SELECT status FROM messages WHERE id = ?").get(subject);
  const decisions = (platform.db.prepare("SELECT data FROM events WHERE type = 'approval.decided' AND bot_id = ? ORDER BY seq").all(A.bot.id) as any[])
    .map((e) => JSON.parse(e.data).decision);
  const accepted = count(platform.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'approval.decided' AND subject = ?", card);
  const expired = count(platform.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'approval.expired' AND subject = ?", card);
  const eventsAfter = count(platform.db, "SELECT COUNT(*) n FROM events WHERE bot_id IN (?,?)", A.bot.id, B.bot.id);

  // The failure message carries the base's two opposite decisions, not only the missing 409.
  assert.ok(error, `a call whose own card lapsed before its sweep must refuse, not decide: it answered ${JSON.stringify(out)}; the card reads ${row.status}/${row.decision}, message ${message?.status}, the Bot heard ${JSON.stringify(decisions)}, audits expired=${expired} accepted=${accepted}, events added=${eventsAfter - eventsBefore}`);
  assert.equal(error.status, 409);
  assert.equal(error.code, "invalid_state");
  assert.equal(row.status, "expired", "the sweep's settlement is the only outcome on the card");
  assert.equal(row.decision, null, "no decision was stamped on a settled card");
  assert.deepEqual(decisions, ["expired"], "the Bot hears the sweep's one decision, not two opposite ones");
  assert.equal(accepted, 0, "no approval.decided audit line was written by the call");
  assert.equal(expired, 1, "the sweep's expiry is the one settlement");
  assert.equal(message.status, "expired", "the swept draft is not delivered afterwards");
});
