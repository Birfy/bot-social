// A #266 retryable failure keeps its card pending while `fail()` has already written the action row's
// terminal `failed` (with the conflict in `result`). Rejecting that same kept card is the third way such a
// card settles — after the cancel paths and the card's own clock — and it is a decision on the proposal,
// never a rewrite of the execution that already failed: the action keeps its own ending, so the console and
// botctl keep showing the failure and the peer's conversation view keeps sharing the failed line (it shares
// `executed`/`failed` only). A row still waiting for the card is refused, exactly as today.
import assert from "node:assert/strict";
import { test } from "node:test";
import { friends, inDays, startServer } from "./helpers.js";

const meetingIntent = () => ({ type: "schedule_meeting", summary: "sync", params: { duration_minutes: 60, window: { start: inDays(1, 0), end: inDays(8, 23) } } });
const actionRow = (S: any, id: string) => S.platform.db.prepare("SELECT status, result FROM actions WHERE id = ?").get(id) as any;
const approvalRow = (S: any, id: string) => S.platform.db.prepare("SELECT status FROM approvals WHERE id = ?").get(id) as any;

/** The #266 state: an approve hits a busy slot, `fail()` writes the action row `failed`, and the card stays pending. */
async function conflictKeptCard(S: any) {
  const p = await friends(S.base);
  const cid = (await p.A.bot.startConversation(p.B.bot.id, meetingIntent())).conversation_id as string;
  await p.A.owner.req("POST", "/v1/calendar/entries", { start: inDays(2, 10), end: inDays(2, 11), title: "Standup" });
  const draft: any = await p.A.bot.draftAction(cid, "calendar.book", { title: "Sync", start: inDays(2, 10), end: inDays(2, 11), attendees: [p.B.bot.id] }, "plan");
  const failed: any = await p.A.owner.req("POST", `/v1/approvals/${draft.approval_id}/decision`, { decision: "approved" });
  assert.equal(failed.status, "failed");
  assert.equal(failed.reason, "calendar_conflict");
  assert.equal(actionRow(S, draft.action_id).status, "failed", "the failure wrote the action row, as today");
  assert.equal(approvalRow(S, draft.approval_id).status, "pending", "and the card stayed pending for a retry");
  return { p, cid, draft };
}

test("rejecting a kept card settles the card, and the action keeps its failed ending", async () => {
  const S = await startServer();
  try {
    const { p, cid, draft } = await conflictKeptCard(S);
    const peerBefore: any = await p.B.owner.req("GET", `/v1/conversations/${cid}`);
    assert.ok(peerBefore.actions.some((a: any) => a.action_id === draft.action_id && a.status === "failed"), "the peer sees the failed booking line");

    // The owner rejects the same kept card: a decision on the proposal, not on the execution that already failed.
    const rejected: any = await p.A.owner.req("POST", `/v1/approvals/${draft.approval_id}/decision`, { decision: "rejected" });
    assert.equal(rejected.decision, "rejected");
    assert.equal(approvalRow(S, draft.approval_id).status, "rejected", "the card is settled by the owner's rejection, as today");

    const row = actionRow(S, draft.action_id);
    assert.equal(row.status, "failed", "a rejected card must not rewrite an action that already failed");
    assert.equal(JSON.parse(row.result).error, "calendar_conflict", "the failure's result stays the record");
    assert.equal(rejected.status, "failed", "the answer reports the row's live status, not a decision it never took");
    const peerAfter: any = await p.B.owner.req("GET", `/v1/conversations/${cid}`);
    assert.ok(peerAfter.actions.some((a: any) => a.action_id === draft.action_id && a.status === "failed"), "the peer still sees the failed booking");
  } finally {
    await S.stop();
  }
});

test("a row still waiting for its card is refused by the owner, as today", async () => {
  const S = await startServer();
  try {
    const p = await friends(S.base);
    const cid = (await p.A.bot.startConversation(p.B.bot.id, meetingIntent())).conversation_id as string;
    const draft: any = await p.A.bot.draftAction(cid, "calendar.book", { title: "Sync", start: inDays(2, 15), end: inDays(2, 16) }, "plan");
    assert.equal(actionRow(S, draft.action_id).status, "pending_approval", "a fresh card's action row is still waiting");

    const rejected: any = await p.A.owner.req("POST", `/v1/approvals/${draft.approval_id}/decision`, { decision: "rejected" });
    assert.equal(rejected.decision, "rejected");
    assert.equal(actionRow(S, draft.action_id).status, "rejected", "a decision on a still-waiting proposal refuses it");
    assert.equal(rejected.status, "rejected", "and the answer reports it");
    assert.equal(approvalRow(S, draft.approval_id).status, "rejected");
  } finally {
    await S.stop();
  }
});
