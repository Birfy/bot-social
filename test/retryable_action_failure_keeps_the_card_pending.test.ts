/**
 * #266 — a retryable action failure must not consume the approval.
 *
 * `executeAction`'s `fail()` (`platform.ts:3159`) writes `actions.status='failed'`, the audit row and the
 * `action.failed` event, then returns `{status:"failed", reason}`. `decideApprovalOnce` ignores that result and
 * stamps the card `approved` (`:2592`) — so `calendar_conflict`, a failure the owner fixes by moving the event,
 * spends the one affordance built for that fix. The corrected retry never reaches `executeAction`: it 409s on
 * `status !== 'pending'` (`platform.ts:2527-2530`, `approval is approved`), so the second half of this file is a
 * symptom of the first: one root cause, one fix, at the stamp.
 *
 * Red first on `89255e1`: both tests fail — the card reads `approved`, and the corrected retry throws 409.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { friends, inDays, startServer } from "./helpers.js";

const meetingIntent = () => ({ type: "schedule_meeting", summary: "sync", params: { duration_minutes: 30, window: { start: inDays(1, 0), end: inDays(8, 23) } } });

const approvalRow = (S: any, id: string) => S.platform.db.prepare("SELECT status, decision FROM approvals WHERE id = ?").get(id) as any;
const actionRow = (S: any, id: string) => S.platform.db.prepare("SELECT status, result FROM actions WHERE id = ?").get(id) as any;
const entries = async (owner: any) => ((await owner.req("GET", "/v1/calendar/entries")) as any).entries as any[];
const decide = (owner: any, id: string, body: any) => owner.req("POST", `/v1/approvals/${id}/decision`, body);

/**
 * Two cards for the same window on A's owner: the draft door does not check busy, so both sit pending. Approving
 * the first books it; approving the second hits the organizer's own calendar.
 */
async function conflictedCard() {
  const S = await startServer();
  const p = await friends(S.base);
  const cid = (await p.A.bot.startConversation(p.B.bot.id, meetingIntent())).conversation_id;
  const slot = { start: inDays(3, 15), end: inDays(3, 15.5) };
  const first: any = await p.A.bot.draftAction(cid, "calendar.book", { title: "First", ...slot, attendees: [p.B.bot.id] }, "plan");
  const second: any = await p.A.bot.draftAction(cid, "calendar.book", { title: "Second", ...slot, attendees: [p.B.bot.id] }, "plan");
  const booked: any = await decide(p.A.owner, first.approval_id, { decision: "approved" });
  assert.equal(booked.status, "executed", "the first card books the window");
  const failed: any = await decide(p.A.owner, second.approval_id, { decision: "approved" });
  return { S, p, cid, first, second, failed };
}

test("#266a: a calendar conflict keeps the card pending, so the owner can decide it again", async () => {
  const { S, p, second, first, failed } = await conflictedCard();
  try {
    // The failure itself is unchanged: same response, same action row, same reason the console shows.
    assert.deepEqual(failed, {
      approval_id: second.approval_id,
      decision: "approved",
      action_id: second.action_id,
      status: "failed",
      reason: "calendar_conflict",
    });
    assert.equal(actionRow(S, second.action_id).status, "failed");
    assert.equal(JSON.parse(actionRow(S, second.action_id).result).error, "calendar_conflict");

    // What must not happen: the card that could carry a corrected window is spent.
    const card = approvalRow(S, second.approval_id);
    assert.equal(card.status, "pending", "a retryable failure must not consume the approval");
    assert.equal(card.decision, null);

    // And a plain retry is a decision the owner may still take: the same failure again, not a 409.
    const again: any = await decide(p.A.owner, second.approval_id, { decision: "approved" });
    assert.equal(again.status, "failed");
    assert.equal(again.reason, "calendar_conflict");
    assert.equal(approvalRow(S, second.approval_id).status, "pending");

    // The first card is decided and the calendar holds exactly the one booking it made.
    assert.equal(approvalRow(S, first.approval_id).status, "approved");
    assert.equal((await entries(p.A.owner)).length, 1);
    assert.equal((await entries(p.B.owner)).length, 1);
  } finally {
    await S.stop();
  }
});

test("#266b: the same card books the corrected window with approved_with_edits", async () => {
  const { S, p, second, failed } = await conflictedCard();
  try {
    assert.equal(failed.reason, "calendar_conflict");
    const free = { start: inDays(4, 15), end: inDays(4, 15.5) };

    // The documented retry door, on the same card, with only the time moved: executed, both calendars written.
    const retried: any = await decide(p.A.owner, second.approval_id, { decision: "approved_with_edits", edited_params: free });
    assert.equal(retried.status, "executed", "the corrected window is booked, not 409");
    assert.equal(retried.decision, "approved_with_edits");
    assert.equal(retried.action_id, second.action_id);
    assert.equal(retried.result.start, new Date(free.start).toISOString());
    assert.equal(retried.result.end, new Date(free.end).toISOString());

    const mine = await entries(p.A.owner);
    const theirs = await entries(p.B.owner);
    assert.equal(mine.length, 2, "the organizer keeps the first booking and gains the corrected one");
    assert.equal(theirs.length, 2, "the peer is invited to the corrected booking too");
    const corrected = mine.find((e: any) => e.booking_id === retried.result.booking_id);
    assert.equal(corrected?.status, "confirmed");
    assert.equal(corrected?.start, new Date(free.start).toISOString());
    assert.equal(theirs.find((e: any) => e.booking_id === retried.result.booking_id)?.status, "invited");

    assert.equal(approvalRow(S, second.approval_id).status, "approved", "the retry is what decides the card");
    assert.equal(actionRow(S, second.action_id).status, "executed");
  } finally {
    await S.stop();
  }
});
