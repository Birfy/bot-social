// The delivery door answers its caller with a refusal, after the platform-wide sweep has already run.
//
// Lane I put the sweep of these kinds at the delivery moment -- every refusal the decision door itself makes is
// behind it -- on the reading that the delivery was the moment a decision lands. The delivery door is not only a
// write, though: `deliverMessage` refuses a frozen or revoked recipient, a share its peer's owner took back, and an
// attachment that died while the card waited; `deliverFaceRoomMessage` refuses a line whose room closed or whose
// sender left; `executeAction` refuses a peer that was removed and an edit that cannot run. All of those are thrown
// after the sweep line, so the refused call has already settled every other owner's lapsed card, given back their
// invite use and told their Bot -- and only then answered `403 bot_frozen`.
//
// Each refusal case below plants a third owner's lapsed join (a pending request, its card, one spent use of a 1-use
// invite, both clocks in the past), records that owner's rows, asks one delivery door to refuse, and then reads the
// same rows back. On the base they have moved: the card is `expired`, `decided_at` is set, the request is `expired`,
// the invite's use is back, and both expiry audit lines plus the `approval.decided` event are there -- the sweep ran
// inside a call that ended in a refusal. The assertion that must hold instead is the recorded snapshot.
//
// The two success controls are the other half: an approved line and an executed action still settle that same third
// owner's queue, so a change that only deletes the sweep fails here instead of looking green. They also show the
// fixture really is one a delivery moment settles, which is what makes the refusal cases above stand for a missing
// delivery moment rather than an ineligible row.
import assert from "node:assert/strict";
import { test } from "node:test";
import { bulkAuth, expectApiError, friends, inDays, ownerWithBot, startServer } from "./helpers.js";

type S = Awaited<ReturnType<typeof startServer>>;

const past = () => new Date(Date.now() - 3600e3).toISOString();
const count = (db: any, sql: string, ...args: unknown[]) => (db.prepare(sql).get(...args) as any).n as number;
const meeting = () => ({
  type: "schedule_meeting", summary: "sync",
  params: { duration_minutes: 30, window: { start: inDays(1, 0), end: inDays(8, 23) } },
});
const decide = (owner: { req: Function }, approvalId: string, body: unknown) =>
  owner.req("POST", `/v1/approvals/${approvalId}/decision`, body as any);
const draftedCard = (d: any) => {
  assert.ok(d.approval_id, `a drafted line waits on a card: ${JSON.stringify(d)}`);
  return d.approval_id as string;
};

/**
 * A third owner's lapsed join: one pending request, the card behind it, and one spent use of a 1-use invite. The
 * joins are minted through the platform's own doors so `releaseInviteUse` has a real `relationship_invites` row to
 * find; then both clocks are set into the past, which is the state a delivery moment is expected to settle.
 */
async function lapsedThirdPartyJoin(s: S, tag: string) {
  const A = await ownerWithBot(s.base, `third-a-${tag}`);
  const B = await ownerWithBot(s.base, `third-b-${tag}`);
  const inv = (s.platform as any).createInvite(
    { kind: "owner" as const, ownerId: A.owner_id },
    { bot_id: A.bot.id, auto_accept: false, max_uses: 1 },
  );
  const join: any = await B.bot.signed(`/v1/invites/${inv.code}/join`, "invite.join", { code: inv.code });
  assert.equal(join.status, "pending_requester_owner", JSON.stringify(join));
  assert.ok(join.approval_id, "a Bot's join waits on its own owner's card");
  s.platform.db.prepare("UPDATE relationships SET expires_at = ? WHERE id = ?").run(past(), join.relationship_id);
  s.platform.db.prepare("UPDATE approvals SET expires_at = ? WHERE id = ?").run(past(), join.approval_id);
  return {
    botId: B.bot.id as string,
    code: inv.code as string,
    relId: join.relationship_id as string,
    approvalId: join.approval_id as string,
  };
}

type Third = Awaited<ReturnType<typeof lapsedThirdPartyJoin>>;

/** Everything a delivery moment writes on that third owner, in one read: rows, audit lines and the Bot's event. */
function thirdParty(s: S, p: Third) {
  return {
    card: s.platform.db.prepare("SELECT status, decided_at FROM approvals WHERE id = ?").get(p.approvalId) as any,
    request: s.platform.db.prepare("SELECT status FROM relationships WHERE id = ?").get(p.relId) as any,
    invite: s.platform.db.prepare("SELECT status, uses FROM invites WHERE code = ?").get(p.code) as any,
    approvalExpired: count(s.platform.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'approval.expired' AND subject = ?", p.approvalId),
    relationshipExpired: count(s.platform.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.expired' AND subject = ?", p.relId),
    events: count(s.platform.db, "SELECT COUNT(*) n FROM events WHERE type = 'approval.decided' AND bot_id = ?", p.botId),
  };
}

/** Row counts across the tables a decision can write; a refused call leaves every one of them unchanged. */
function footprint(s: S) {
  return {
    approvals: count(s.platform.db, "SELECT COUNT(*) n FROM approvals"),
    grants: count(s.platform.db, "SELECT COUNT(*) n FROM grants"),
    relationships: count(s.platform.db, "SELECT COUNT(*) n FROM relationships"),
    invites: count(s.platform.db, "SELECT COUNT(*) n FROM invites"),
    events: count(s.platform.db, "SELECT COUNT(*) n FROM events"),
    webhook_deliveries: count(s.platform.db, "SELECT COUNT(*) n FROM webhook_deliveries"),
    audit: count(s.platform.audit.db, "SELECT COUNT(*) n FROM audit_events"),
  };
}

/**
 * The refusal settled nothing: the third owner's rows are the ones recorded before the call, and no table moved.
 * `answer` names the code the door was expected to refuse with, so the failure reads as "this call settled that
 * owner before it answered".
 */
function assertRefusedWithoutSettling(s: S, p: Third, before: ReturnType<typeof thirdParty>, rows: ReturnType<typeof footprint>, answer: string) {
  const now = thirdParty(s, p);
  assert.equal(now.card.status, "pending", `a refused ${answer} settled another owner's card`);
  assert.equal(now.card.decided_at, null, `a refused ${answer} stamped a decision on another owner's card`);
  assert.equal(now.request.status, "pending_requester_owner", `a refused ${answer} settled another owner's request`);
  assert.equal(now.invite.uses, 1, `a refused ${answer} gave another owner's invite use back`);
  assert.equal(now.approvalExpired, 0, `a refused ${answer} wrote an expiry audit line`);
  assert.equal(now.relationshipExpired, 0, `a refused ${answer} wrote a relationship expiry audit line`);
  assert.equal(now.events, 0, `a refused ${answer} told another owner's Bot`);
  assert.deepEqual(now, before, `a refused ${answer} left another owner's rows moved`);
  assert.deepEqual(footprint(s), rows, `a refused ${answer} wrote a row anyway`);
}

/** The third owner's rows are settled the way a delivery moment settles them: the clock is recorded, never silent. */
function assertSettledByTheDelivery(s: S, p: Third) {
  const st = thirdParty(s, p);
  assert.equal(st.card.status, "expired", "a landed decision still opens the delivery moment");
  assert.ok(st.card.decided_at, "the settlement records the instant it happened");
  assert.equal(st.request.status, "expired", "a lapsed request is written down with the queue it waited in");
  assert.equal(st.invite.uses, 0, "the lapsed request gives its invite use back");
  assert.equal(st.approvalExpired, 1, "the expiry is on the audit chain");
  assert.equal(st.relationshipExpired, 1, "the request's own settlement is on the audit chain");
  assert.equal(st.events, 1, "the asking Bot heard the settlement");
}

// --------------------------------------------------------------- a refusal from the delivery door settles nothing
test("a refused outbound delivery for a frozen recipient settles nothing else", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B } = await friends(s.base);
  const conv: any = await A.bot.startConversation(B.bot.id, meeting());
  const card = draftedCard(await A.bot.draftMessage(conv.conversation_id, { text: "a line to a Bot that stops" }));
  // The stop is the refusal: the card waits, the kill switch holds it, and the door answers `403 bot_frozen` from
  // inside `deliverMessage` -- after the sweep line the decision door put ahead of it.
  await B.owner.req("POST", "/v1/emergency-stop", { bot_id: B.bot.id });
  const third = await lapsedThirdPartyJoin(s, "frozen");
  const before = thirdParty(s, third);
  const rows = footprint(s);

  await expectApiError(decide(A.owner, card, { decision: "approved" }), 403, "bot_frozen");

  assertRefusedWithoutSettling(s, third, before, rows, "403 bot_frozen");
  const row: any = s.platform.db.prepare("SELECT status FROM approvals WHERE id = ?").get(card);
  assert.equal(row.status, "pending", "the held line stays pending, so the owner can decide it after a resume");
});

test("a refused face-room delivery in a closed room settles nothing else", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B } = await friends(s.base);
  const ownerA = { kind: "owner" as const, ownerId: A.owner_id };
  const ownerB = { kind: "owner" as const, ownerId: B.owner_id };
  const first = s.platform.joinFaceRoom(ownerA, { code: "840202", bots: [A.bot.id] });
  s.platform.joinFaceRoom(ownerB, { code: "840202", bots: [B.bot.id] });
  s.platform.startFaceRoom(ownerA, first.room_id);
  const card = draftedCard(s.platform.draftFaceRoomMessage(ownerA, first.room_id, { text: "a room line whose room closes" }));
  // The room closes under the card: `deliverFaceRoomMessage` answers `409 room_closed` from inside the dispatch.
  s.platform.db.prepare("UPDATE face_rooms SET status = 'closed' WHERE id = ?").run(first.room_id);
  const third = await lapsedThirdPartyJoin(s, "room");
  const before = thirdParty(s, third);
  const rows = footprint(s);

  await expectApiError(decide(A.owner, card, { decision: "approved" }), 409, "room_closed");

  assertRefusedWithoutSettling(s, third, before, rows, "409 room_closed");
});

test("a refused action delivery settles nothing else", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B } = await friends(s.base);
  // A books with B, so B holds the invite the card under test answers; then B's accept is edited to a booking that
  // does not exist, which `executeAction` refuses from inside the dispatch, after the sweep.
  const convA: any = await A.bot.startConversation(B.bot.id, meeting());
  const booked = draftedCard(await A.bot.draftAction(convA.conversation_id, "calendar.book", {
    title: "Sync", start: inDays(1, 10), end: inDays(1, 11), attendees: [B.bot.id],
  }, "plan the week"));
  const bookedOut: any = await decide(A.owner, booked, { decision: "approved" });
  assert.equal(bookedOut.status, "executed", JSON.stringify(bookedOut));
  const convB: any = await B.bot.startConversation(A.bot.id, meeting());
  const card = draftedCard(await B.bot.draftAction(convB.conversation_id, "calendar.accept_invite", {
    booking_id: bookedOut.result.booking_id,
  }, "answer the invite"));
  const third = await lapsedThirdPartyJoin(s, "action");
  const before = thirdParty(s, third);
  const rows = footprint(s);

  await expectApiError(decide(B.owner, card, { decision: "approved_with_edits", edited_params: { booking_id: "bkg_nope" } }), 404, "invite_not_found");

  assertRefusedWithoutSettling(s, third, before, rows, "404 invite_not_found");
});

// --------------------------------------------------------------- a decision that lands still settles the queue
test("an approved outbound line still settles the third owner's lapsed card", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B } = await friends(s.base);
  const conv: any = await A.bot.startConversation(B.bot.id, meeting());
  const card = draftedCard(await A.bot.draftMessage(conv.conversation_id, { text: "the line that really lands" }));
  const third = await lapsedThirdPartyJoin(s, "msg-ok");

  const decided: any = await decide(A.owner, card, { decision: "approved" });
  assert.equal(decided.status, "delivered", JSON.stringify(decided));
  assertSettledByTheDelivery(s, third);
});

test("an executed action still settles the third owner's lapsed card", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B } = await friends(s.base);
  const conv: any = await A.bot.startConversation(B.bot.id, meeting());
  const card = draftedCard(await A.bot.draftAction(conv.conversation_id, "calendar.book", {
    title: "Sync", start: inDays(2, 10), end: inDays(2, 11), attendees: [B.bot.id],
  }, "plan the week"));
  const third = await lapsedThirdPartyJoin(s, "action-ok");

  const decided: any = await decide(A.owner, card, { decision: "approved" });
  assert.equal(decided.status, "executed", JSON.stringify(decided));
  assertSettledByTheDelivery(s, third);
});
