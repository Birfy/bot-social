// `grant_request` was the one decision branch that read `body.edited_params` without asking `decision` first: a
// plain `approved` therefore applied whatever edit the body carried (a wider scope, a 365-day expiry) while the
// card, the `approval.decided` event and the audit line all recorded a plain approval — no edit on record. The
// other three kinds read an edit only for `approved_with_edits`, and this branch now does the same: an edit on a
// plain approval is ignored, an explicit edit still lands, and a rejection still writes no grant.
import assert from "node:assert/strict";
import { test } from "node:test";
import { friends, startServer } from "./helpers.js";

const ASKED = { window_days: 14, hours: "09:00-18:00" };
const WIDER = { window_days: 365, hours: "00:00-23:59" };
const DEFAULT_DAYS = 90;

type S = Awaited<ReturnType<typeof startServer>>;

const activeGrant = (s: S, botId: string, cap: string) =>
  s.platform.db.prepare("SELECT * FROM grants WHERE grantee_bot = ? AND capability = ? AND status = 'active'").get(botId, cap) as any;
const daysLeft = (iso: string) => (Date.parse(iso) - Date.now()) / 86400e3;

test("a plain approval writes the grant the Bot asked for, not the edit the body carried", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const { A, B, relId } = await friends(s.base);
  const req = await A.bot.requestGrant(relId, "calendar.freebusy.read", ASKED);
  assert.equal(req.status, "pending_owner_approval");

  const decided = await B.owner.req("POST", `/v1/approvals/${req.approval_id}/decision`, {
    decision: "approved",
    edited_params: { scope: WIDER, expires_in_days: 365 },
  });
  assert.equal(decided.decision, "approved");

  const g = activeGrant(s, A.bot.id, "calendar.freebusy.read");
  assert.ok(g, "the approval writes a grant");
  assert.deepEqual(JSON.parse(g.scope), ASKED, "a plain approval writes the scope the Bot asked for");
  const days = daysLeft(g.expires_at);
  assert.ok(days > DEFAULT_DAYS - 1 && days <= DEFAULT_DAYS + 0.01, `a plain approval keeps the default expiry, got ${days.toFixed(2)} days`);

  // The record still says what happened: a plain approval, not one with an edit.
  const events = s.platform.db.prepare("SELECT data FROM events WHERE type = 'approval.decided'").all()
    .map((r: any) => JSON.parse(r.data)).filter((d: any) => d.approval_id === req.approval_id);
  assert.equal(events.length, 1, "one approval.decided event");
  assert.equal(events[0].decision, "approved", "the event records a plain approval");
  const audits = s.platform.audit.db.prepare("SELECT data FROM audit_events WHERE action = 'approval.decided' AND subject = ?").all(req.approval_id)
    .map((r: any) => JSON.parse(r.data));
  assert.equal(audits.length, 1, "one approval.decided audit line");
  assert.equal(audits[0].decision, "approved", "the audit line records a plain approval");
});

test("an explicit edit still writes the edited grant", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const { A, B, relId } = await friends(s.base);
  const req = await A.bot.requestGrant(relId, "calendar.freebusy.read", ASKED);

  const decided = await B.owner.req("POST", `/v1/approvals/${req.approval_id}/decision`, {
    decision: "approved_with_edits",
    edited_params: { scope: WIDER, expires_in_days: 365 },
  });
  assert.equal(decided.decision, "approved_with_edits");

  const g = activeGrant(s, A.bot.id, "calendar.freebusy.read");
  assert.ok(g, "the edited approval writes a grant");
  assert.deepEqual(JSON.parse(g.scope), WIDER, "an explicit edit still writes the edited scope");
  const days = daysLeft(g.expires_at);
  assert.ok(days > 364 && days <= 366, `an explicit edit still writes the edited expiry, got ${days.toFixed(2)} days`);
});

test("a rejection carrying an edit writes no grant", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const { A, B, relId } = await friends(s.base);
  const req = await A.bot.requestGrant(relId, "calendar.freebusy.read", ASKED);

  const decided = await B.owner.req("POST", `/v1/approvals/${req.approval_id}/decision`, {
    decision: "rejected",
    edited_params: { scope: WIDER, expires_in_days: 365 },
  });
  assert.equal(decided.decision, "rejected");
  const rows = s.platform.db.prepare("SELECT * FROM grants WHERE grantee_bot = ? AND capability = ?").all(A.bot.id, "calendar.freebusy.read");
  assert.deepEqual(rows, [], "a rejected request writes no grant, with or without an edit");
  const card = (await B.owner.req("GET", "/v1/approvals?status=pending")).approvals.find((a: any) => a.approval_id === req.approval_id);
  assert.equal(card, undefined, "the card is decided, not left pending");
});
