// A #266 retryable failure keeps its card pending while `fail()` has already written the action row's
// terminal `failed` (with the conflict in `result`). When that kept card is later settled by its own
// clock or by a cancel path, the card settles — the action row that already failed must keep its own
// ending: no rewrite to `expired` or `cancelled`, so the console and botctl keep showing the failure
// and the peer's conversation view keeps sharing the failed booking (it shares `executed`/`failed` only).
import assert from "node:assert/strict";
import { test } from "node:test";
import { friends, inDays, startServer } from "./helpers.js";

const meetingIntent = () => ({ type: "schedule_meeting", summary: "sync", params: { duration_minutes: 60, window: { start: inDays(1, 0), end: inDays(8, 23) } } });

async function conflictFailedAction(S: any) {
  const p = await friends(S.base);
  const cid = (await p.A.bot.startConversation(p.B.bot.id, meetingIntent())).conversation_id as string;
  await p.A.owner.req("POST", "/v1/calendar/entries", { start: inDays(2, 10), end: inDays(2, 11), title: "Standup" });
  const draft: any = await p.A.bot.draftAction(cid, "calendar.book", { title: "Sync", start: inDays(2, 10), end: inDays(2, 11), attendees: [p.B.bot.id] }, "plan");
  // #266: the owner says yes, the slot is busy; the action fails and the card stays pending for a retry.
  const failed: any = await p.A.owner.req("POST", `/v1/approvals/${draft.approval_id}/decision`, { decision: "approved" });
  assert.equal(failed.status, "failed");
  assert.equal(failed.reason, "calendar_conflict");
  const row = (id: string) => S.platform.db.prepare("SELECT status, result FROM actions WHERE id = ?").get(id) as any;
  assert.equal(row(draft.action_id).status, "failed", "the failure wrote the action row, as today");
  return { p, cid, draft, row };
}

test("a conflict-failed action is not rewritten when the kept card lapses", async () => {
  const S = await startServer();
  try {
    const { p, cid, draft, row } = await conflictFailedAction(S);

    // The peer side sees the failed booking line (getConversation shares executed/failed rows).
    const peerBefore: any = await p.B.owner.req("GET", `/v1/conversations/${cid}`);
    assert.ok(peerBefore.actions.some((a: any) => a.action_id === draft.action_id && a.status === "failed"), "the failed action is visible to the peer");

    // The kept card's 4h TTL runs out (house idiom: backdate the card, then one legal read runs the sweep).
    S.platform.db.prepare("UPDATE approvals SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), draft.approval_id);
    await p.A.owner.req("GET", "/v1/approvals"); // listApprovals -> expireStale -> expireApproval

    // The card is settled by its clock — that part is right.
    const apr = S.platform.db.prepare("SELECT status FROM approvals WHERE id = ?").get(draft.approval_id) as any;
    assert.equal(apr.status, "expired", "the kept card lapses by its own clock");

    // An action that already reached the terminal `failed` state keeps it.
    assert.equal(row(draft.action_id).status, "failed", "a card's expiry must not rewrite an action that already failed");
    assert.equal(JSON.parse(row(draft.action_id).result).error, "calendar_conflict", "the failure's result stays the record");
    const peerAfter: any = await p.B.owner.req("GET", `/v1/conversations/${cid}`);
    assert.ok(peerAfter.actions.some((a: any) => a.action_id === draft.action_id && a.status === "failed"), "the peer still sees the failed booking");
  } finally {
    await S.stop();
  }
});

test("a conflict-failed action is not rewritten when the kept card is cancelled", async () => {
  const S = await startServer();
  try {
    const { p, draft, row } = await conflictFailedAction(S);

    // Blocking the peer ends the pair's doors and cancels every pending card of the relationship.
    await p.A.owner.req("POST", "/v1/blocks", { bot_id: p.B.bot.id, my_bot_id: p.A.bot.id });
    const apr = S.platform.db.prepare("SELECT status FROM approvals WHERE id = ?").get(draft.approval_id) as any;
    assert.equal(apr.status, "cancelled", "the kept card is settled by the block, as today");

    // The card settles; the action row that already failed keeps its own terminal state.
    assert.equal(row(draft.action_id).status, "failed", "a cancelled card must not rewrite an action that already failed");
    assert.equal(JSON.parse(row(draft.action_id).result).error, "calendar_conflict");
  } finally {
    await S.stop();
  }
});
