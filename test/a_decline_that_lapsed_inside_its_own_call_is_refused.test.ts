/**
 * #792's other half: `consent`'s `accept` branch re-reads the row after its sweep; `decline` does not.
 *
 * Both branches judge the row (`pending_target`), take every refusal, and only then run the platform-wide sweep
 * `expireStale()`. That sweep is a clock: if this row's own `expires_at` crossed now in the window, the sweep settles
 * it `expired` — its audit line, the invite use its join spent, and the `relationship.changed` every reader of the row
 * acts on. The `accept` branch learned this (#792): after the sweep it reads the row again and answers `409
 * invalid_state` when the sweep got there first. The `decline` branch never learned it: it runs the same sweep and then
 * writes `declined` on top of whatever the sweep just wrote.
 *
 * One row then ends with two terminal outcomes: `relationship.expired` and `relationship.declined` on the audit chain,
 * a `relationship.changed` that says `declined` about a row the sweep already settled `expired` (the sweep's expiry is
 * silent in the event stream), and the invite's use given back twice — `releaseInviteUse` clamps at zero, so a link with
 * a spare use reads as if that spare were spent while the other request still holds it.
 *
 * What must happen instead: the call loses. After the sweep, before the covering write, the row is read again; a row the
 * sweep settled is answered with the door's existing `409 invalid_state` and nothing else is written, emitted or
 * audited. A decline of a live row keeps its answer word for word (`200 {status:"declined"}`, one audit line, one
 * event, one use given back).
 *
 * The window is opened deterministically, with no clock or hook in `src`: `expireStale`'s first step,
 * `expireLapsedShares`, is wrapped in the test and pushes that row's expiry into the past once, so the sweep this very
 * call runs is the one that settles it. On the base the assertions below see the double settlement and the double
 * refund; with the re-read they see one outcome.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ownerWithBot, startServer } from "./helpers.js";

const owner = (o: any) => ({ kind: "owner" as const, ownerId: o.owner_id });
const past = () => new Date(Date.now() - 3600e3).toISOString();
const count = (db: any, sql: string, ...args: unknown[]) => (db.prepare(sql).get(...args) as any).n as number;

/** The call's answer: the result it returned, or the error it threw. */
async function answered(call: () => any): Promise<{ out?: any; error?: any }> {
  try { return { out: await call() }; } catch (error) { return { error }; }
}

/** The `relationship.changed` statuses both Bots heard about this row, in the order they were emitted. */
const statusesHeard = (db: any, relId: string, bots: string[]) =>
  (db.prepare("SELECT data FROM events WHERE type = 'relationship.changed' AND bot_id IN (?,?) ORDER BY seq").all(bots[0], bots[1]) as any[])
    .map((e) => JSON.parse(e.data))
    .filter((d) => d.relationship_id === relId)
    .map((d) => d.status);

test("a decline whose own request lapses during the call is refused, and the sweep's expiry is the only outcome", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const p = s.platform as any;
  const A = await ownerWithBot(s.base, "lapseddeclinea");
  const B = await ownerWithBot(s.base, "lapseddeclineb");
  const C = await ownerWithBot(s.base, "lapseddeclinec");
  // A three-use link with two joins waiting for A: two uses are spent, so a double refund shows as 2 -> 0 while a
  // single one leaves the other waiting request's use in place.
  const inv = p.createInvite(owner(A), { bot_id: A.bot.id, auto_accept: false, max_uses: 3 });
  const joinedB: any = p.joinInvite(owner(B), inv.code, { from_bot_id: B.bot.id });
  const joinedC: any = p.joinInvite(owner(C), inv.code, { from_bot_id: C.bot.id });
  assert.equal(joinedB.status, "pending_target", JSON.stringify(joinedB));
  assert.equal(joinedC.status, "pending_target", JSON.stringify(joinedC));
  const uses = () => (s.platform.db.prepare("SELECT uses FROM invites WHERE code = ?").get(inv.code) as any).uses as number;
  assert.equal(uses(), 2, "two joins spent two of the link's three uses");

  // The window: every refusal this door makes about the row is behind it, and the next step is the delivery moment's
  // sweep -- the row's own clock crosses now there, before the sweep reads what is lapsed.
  const realLapsedShares = p.expireLapsedShares.bind(p);
  let armed = true;
  p.expireLapsedShares = () => {
    if (armed) {
      armed = false;
      p.db.prepare("UPDATE relationships SET expires_at = ? WHERE id = ?").run(past(), joinedB.relationship_id);
    }
    return realLapsedShares();
  };
  t.after(() => { p.expireLapsedShares = realLapsedShares; });

  const { out, error } = await answered(() => p.consent(owner(A), joinedB.relationship_id, { decision: "decline" }));

  const row: any = p.db.prepare("SELECT status FROM relationships WHERE id = ?").get(joinedB.relationship_id);
  const other: any = p.db.prepare("SELECT status FROM relationships WHERE id = ?").get(joinedC.relationship_id);
  const expired = count(p.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.expired' AND subject = ?", joinedB.relationship_id);
  const declined = count(p.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.declined' AND subject = ?", joinedB.relationship_id);
  const heard = statusesHeard(p.db, joinedB.relationship_id, [A.bot.id, B.bot.id]);

  // The failure message carries the base's two outcomes, not only the missing 409.
  assert.ok(
    error,
    `a call whose own request lapsed before its sweep must refuse, not decline: it answered ${JSON.stringify(out)}; the row reads ${row.status}, the other request ${other.status}, audits expired=${expired} declined=${declined}, the Bots heard ${JSON.stringify(heard)}, invite uses=${uses()}`,
  );
  assert.equal(error.status, 409);
  assert.equal(error.code, "invalid_state");
  assert.equal(row.status, "expired", "the sweep's settlement is the only outcome on the row");
  assert.equal(other.status, "pending_target", "the other waiting request is not touched");
  assert.equal(expired, 1, "the sweep's expiry is the one settlement this call leaves");
  assert.equal(declined, 0, "the call does not write a decline it never decided");
  assert.deepEqual(heard, [], "the refusal announces nothing: the sweep's expiry is silent and the call never decided a decline");
  assert.equal(uses(), 1, "the joined use is given back once, so the other request still holds its own");
});

test("a decline of a live request keeps its answer: 200 declined, one audit line, one event, one use given back", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const p = s.platform as any;
  const A = await ownerWithBot(s.base, "livedeclinea");
  const B = await ownerWithBot(s.base, "livedeclineb");
  const C = await ownerWithBot(s.base, "livedeclinec");
  const inv = p.createInvite(owner(A), { bot_id: A.bot.id, auto_accept: false, max_uses: 3 });
  const joinedB: any = p.joinInvite(owner(B), inv.code, { from_bot_id: B.bot.id });
  const joinedC: any = p.joinInvite(owner(C), inv.code, { from_bot_id: C.bot.id });
  const uses = () => (s.platform.db.prepare("SELECT uses FROM invites WHERE code = ?").get(inv.code) as any).uses as number;
  assert.equal(uses(), 2);

  const out: any = await answered(() => p.consent(owner(A), joinedB.relationship_id, { decision: "decline" }));

  const row: any = p.db.prepare("SELECT status FROM relationships WHERE id = ?").get(joinedB.relationship_id);
  const other: any = p.db.prepare("SELECT status FROM relationships WHERE id = ?").get(joinedC.relationship_id);
  const expired = count(p.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.expired' AND subject = ?", joinedB.relationship_id);
  const declined = count(p.audit.db, "SELECT COUNT(*) n FROM audit_events WHERE action = 'relationship.declined' AND subject = ?", joinedB.relationship_id);
  const heard = statusesHeard(p.db, joinedB.relationship_id, [A.bot.id, B.bot.id]);

  // The answer and the writes a live decline has always made: unchanged, word for word.
  assert.deepEqual(out.out, { relationship_id: joinedB.relationship_id, status: "declined" }, `a live decline still answers 200 declined: ${JSON.stringify(out)}`);
  assert.equal(out.error, undefined);
  assert.equal(row.status, "declined", "the row is declined");
  assert.equal(other.status, "pending_target", "the other waiting request is not touched");
  assert.equal(expired, 0, "nothing lapsed, so no expiry was written");
  assert.equal(declined, 1, "one decline, one audit line");
  assert.deepEqual(heard, ["declined"], "both Bots hear one ending");
  assert.equal(uses(), 1, "exactly one use is given back");
});
