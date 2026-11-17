// `botctl approve` is what an agent runs, and the line it prints is what the agent reads back to its owner. A
// decision can land while the action it approved does not: `executeAction` writes `actions.status='failed'`, its
// audit row and its `action.failed` event, and `decideApproval` returns `{status: "failed", reason}` before
// `UPDATE approvals` -- the card is still pending and nothing was booked (#266). The CLI said "✓ Approved" and
// exited 0 for that answer, so an agent told its owner a meeting was booked that the server never made.
//
// The console already words this (`public/ui.js` reads `res.status === "failed"` and prints `actionFailLine`);
// these tests pin the CLI half: a refused action is reported as a failure, with the reason, as a non-zero exit,
// and the two paths that do succeed -- a booking that landed and a rejection -- keep their line word for word.
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { friends, inDays, startServer } from "./helpers.js";

const run = promisify(execFile);

const meetingIntent = () => ({
  type: "schedule_meeting",
  summary: "sync",
  params: { duration_minutes: 60, window: { start: inDays(1, 0), end: inDays(8, 23) } },
});

/**
 * A botctl home holding one config for the owner, so `botctl approve alice <id>` runs exactly as an agent runs it.
 * The runner keeps the exit code and both streams: a refusal is a non-zero exit, which `execFile` rejects with.
 */
function cliHome(base: string, A: any) {
  const dir = mkdtempSync(join(tmpdir(), "botctl-action-failed-"));
  const home = join(dir, ".bot-social");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, "alice.json"), JSON.stringify({
    name: "alice", base, owner_id: A.owner_id, owner_token: A.owner.token, username: "alice",
    bot_id: A.bot.id, bot_token: A.bot.cred.token, handle: A.handle.replace(/^@/, ""), kid: A.bot.cred.kid,
    private_key_pem: A.bot.cred.privateKeyPem, cursor: 0,
  }));
  return async (...a: string[]): Promise<{ code: number; said: string }> => {
    try {
      const r: any = await run(process.execPath, ["--import", "tsx", "scripts/botctl.ts", ...a], {
        env: { ...process.env, BOTSOCIAL_HOME: home, BOTSOCIAL_URL: "" }, encoding: "utf8",
      });
      return { code: 0, said: `${r.stdout}${r.stderr}` };
    } catch (e: any) {
      return { code: typeof e.code === "number" ? e.code : 1, said: `${e.stdout ?? ""}${e.stderr ?? ""}` };
    }
  };
}

/** A drafts a booking for a slot the owner's own calendar already holds: approving it cannot succeed. */
async function conflictingBooking(s: any) {
  const { A, B } = await friends(s.base);
  const cid = (await A.bot.startConversation(B.bot.id, meetingIntent())).conversation_id as string;
  await A.owner.req("POST", "/v1/calendar/entries", { start: inDays(2, 10), end: inDays(2, 11), title: "Standup" });
  const act: any = await A.bot.draftAction(cid, "calendar.book", { title: "Sync", start: inDays(2, 10), end: inDays(2, 11), attendees: [B.bot.id] }, "plan");
  return { A, B, cid, approvalId: act.approval_id as string };
}

/** A drafts a booking for a free slot: approving it succeeds. */
async function bookableMeeting(s: any) {
  const { A, B } = await friends(s.base);
  const cid = (await A.bot.startConversation(B.bot.id, meetingIntent())).conversation_id as string;
  const act: any = await A.bot.draftAction(cid, "calendar.book", { title: "Sync", start: inDays(3, 10), end: inDays(3, 11), attendees: [B.bot.id] }, "plan");
  return { A, B, cid, approvalId: act.approval_id as string };
}

/** A drafts a booking for a window that starts soon, then the platform's clock steps past it: the action cannot run.
 *  The clock is the server's own (`Platform.nowMs`), so this is the card outliving its window, not a sleep. */
async function pastBooking(s: any) {
  let clock = Date.now();
  s.platform.nowMs = () => clock;
  const { A, B } = await friends(s.base);
  const cid = (await A.bot.startConversation(B.bot.id, meetingIntent())).conversation_id as string;
  const start = new Date(clock + 20 * 60e3).toISOString();
  const end = new Date(clock + 80 * 60e3).toISOString();
  const act: any = await A.bot.draftAction(cid, "calendar.book", { title: "Sync", start, end, attendees: [B.bot.id] }, "plan");
  clock += 30 * 60e3; // the owner approves after the window began, while the card's own 4h deadline still holds
  return { A, approvalId: act.approval_id as string };
}

test("an action the server refused is not reported as a plain approval", async (t) => {
  const s = await startServer(); t.after(() => s.stop());
  const { A, approvalId } = await conflictingBooking(s);

  // What the server answers before the CLI is involved: the decision landed, the booking did not, card still pending.
  const answered: any = await A.owner.req("POST", `/v1/approvals/${approvalId}/decision`, { decision: "approved" });
  assert.equal(answered.status, "failed", "the server answers this decision with status failed");
  assert.equal(answered.reason, "calendar_conflict", "and names the busy calendar, not a bare word");

  // Now the same shape through the CLI, on a card of its own.
  const { A: A2, approvalId: id2 } = await conflictingBooking(s);
  const out = await cliHome(s.base, A2)("approve", "alice", id2);
  assert.doesNotMatch(out.said, /✓ Approved/,
    `a booking the server refused must not be reported as a plain approval; the CLI printed:\n${out.said}`);
  assert.notEqual(out.code, 0, `a refused action exits non-zero, not 0; the CLI printed:\n${out.said}`);
  assert.match(out.said, /calendar_conflict/, `the CLI names the reason the server gave; it printed:\n${out.said}`);
  assert.match(out.said, /still pending/i, `and says the card is still waiting on the owner; it printed:\n${out.said}`);

  // The card the CLI just answered is the one still waiting -- not the first card, which this test decided itself.
  const pending = (await A2.owner.req("GET", "/v1/approvals?status=pending")).approvals
    .find((a: any) => a.approval_id === id2);
  assert.ok(pending, "the refused booking leaves the CLI's own card pending so the owner can retry with another time");
  assert.equal((pending as any).status, "pending");
});

test("a failure that settles the card is not reported as one still waiting", async (t) => {
  const s = await startServer(); t.after(() => s.stop());
  const { A, approvalId } = await pastBooking(s);

  // `meeting_in_past` is a final failure: `decideApproval` settles the card as approved (#266 leaves only
  // `calendar_conflict` pending), so the CLI must not send the owner back to a card that is no longer waiting.
  const out = await cliHome(s.base, A)("approve", "alice", approvalId);
  assert.doesNotMatch(out.said, /✓ Approved/,
    `an action that could not run must not be reported as a plain approval; the CLI printed:\n${out.said}`);
  assert.notEqual(out.code, 0, `a failed action exits non-zero; the CLI printed:\n${out.said}`);
  assert.match(out.said, /meeting_in_past/, `the CLI names the reason the server gave; it printed:\n${out.said}`);
  assert.match(out.said, /settled/i, `and says the card was settled by this decision; it printed:\n${out.said}`);
  assert.doesNotMatch(out.said, /still pending/i,
    `this card is not waiting any more, so the CLI must not say it is; it printed:\n${out.said}`);

  const card = (await A.owner.req("GET", "/v1/approvals?status=all")).approvals
    .find((a: any) => a.approval_id === approvalId);
  assert.equal((card as any)?.status, "approved", "the decision settled the card even though the action failed");
});

test("control: a booking that lands is still a plain approval", async (t) => {
  const s = await startServer(); t.after(() => s.stop());
  const { A, approvalId } = await bookableMeeting(s);
  const out = await cliHome(s.base, A)("approve", "alice", approvalId);
  assert.equal(out.code, 0, `a booking that landed exits 0; the CLI printed:\n${out.said}`);
  assert.equal(out.said.trim(), "✓ Approved", "a booking that landed is still a plain approval, word for word");
});

test("control: a rejection keeps its own line", async (t) => {
  const s = await startServer(); t.after(() => s.stop());
  const { A, approvalId } = await conflictingBooking(s);
  const out = await cliHome(s.base, A)("reject", "alice", approvalId);
  assert.equal(out.code, 0, `a rejection exits 0; the CLI printed:\n${out.said}`);
  assert.equal(out.said.trim(), "✓ Rejected", "a rejection still says only that it was rejected");
  const still = (await A.owner.req("GET", "/v1/approvals?status=pending")).approvals
    .some((a: any) => a.approval_id === approvalId);
  assert.equal(still, false, "a rejection settles the card it answers");
});
