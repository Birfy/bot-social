import assert from "node:assert/strict";
import { test } from "node:test";
import { expectApiError, ownerWithBot, startServer } from "./helpers.js";

/**
 * An audit line names a write that happened. This one named a write that never did.
 *
 * `POST /v1/relationships/:id/consent` answers the target owner's choices. `writeActivation` writes the grants and the
 * `active` status in one transaction, and `insertGrant` appends a `grant.created` audit row for each grant as it
 * inserts it — but the audit log is its own SQLite database (`src/audit.ts` opens it, not `openDb`), so the platform
 * transaction cannot take those rows back. A `grant_capabilities` entry with a non-positive `expires_in_days` is
 * refused by `grantExpiry` halfway through that transaction: every grant row and the status roll back, the grants
 * never exist, and the `grant.created` rows for the ones written before the refused entry stay behind, each naming a
 * grant id that is in no table. `audit.verify()` still says ok, because the hash chain is intact — it is the chain's
 * claim about the store that is false.
 *
 * Both tests drive the real server. The first one is the refusal; the second pins that the committed path keeps
 * writing one audit row per grant and none for anything else.
 */

const count = (s: any, sql: string, ...args: unknown[]) => (s.platform.db.prepare(sql).get(...args) as any).n as number;
const auditRows = (s: any, action: string) =>
  s.platform.audit.db.prepare("SELECT seq, actor, action, subject, data FROM audit_events WHERE action = ? ORDER BY seq").all(action) as any[];

/** A owns a Bot, B owns a Bot, and A has asked B; the relationship waits for B's owner to consent. */
async function pendingRequest(base: string) {
  const A = await ownerWithBot(base, "alice");
  const B = await ownerWithBot(base, "bob");
  const rel = await A.owner.req("POST", "/v1/relationships", { from_bot_id: A.bot.id, target_handle: B.handle, message: "hi", requested_capabilities: ["chat.public", "calendar.freebusy.read"] });
  return { A, B, relId: rel.relationship_id as string };
}

test("a consent refused halfway writes no grant.created audit and never names a grant that is not there", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const { B, relId } = await pendingRequest(s.base);

  const before = {
    grants: count(s, "SELECT COUNT(*) n FROM grants WHERE relationship_id = ?", relId),
    created: auditRows(s, "grant.created").length,
    status: (s.platform.db.prepare("SELECT status FROM relationships WHERE id = ?").get(relId) as any).status,
  };

  // Two default grants are written before the third entry is refused, so the refusal lands halfway through.
  await expectApiError(
    B.owner.req("POST", `/v1/relationships/${relId}/consent`, {
      decision: "accept",
      grant_capabilities: [{ capability: "calendar.freebusy.read", expires_in_days: -5 }],
    }),
    400,
    "invalid_request",
  );

  assert.equal((s.platform.db.prepare("SELECT status FROM relationships WHERE id = ?").get(relId) as any).status, before.status, "the refusal must leave the relationship where it was");
  assert.equal(count(s, "SELECT COUNT(*) n FROM grants WHERE relationship_id = ?", relId), 0, "no grant row may survive a refused consent");
  assert.equal(auditRows(s, "grant.created").length, before.created, "a grant that rolled back must not leave a grant.created audit behind");
  assert.equal(s.platform.audit.verify().ok, true, "the hash chain must still verify");

  // The audit rows that do name grants must name grants that exist — checked in the committed case below.
  const gone = auditRows(s, "grant.created").filter((a) => !s.platform.db.prepare("SELECT 1 FROM grants WHERE id = ?").get(a.subject));
  assert.deepEqual(gone.map((a) => a.subject), [], "no audit may point at a grant row that is in no table");
});

test("an accepted consent writes exactly one grant.created audit per grant it keeps", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const { B, relId } = await pendingRequest(s.base);
  const before = auditRows(s, "grant.created").length;

  const accepted = await B.owner.req("POST", `/v1/relationships/${relId}/consent`, {
    decision: "accept",
    grant_capabilities: [{ capability: "calendar.freebusy.read", scope: { window_days: 14, hours: "09:00-18:00" } }],
  });
  assert.equal(accepted.status, "active");

  const grants = s.platform.db.prepare("SELECT id FROM grants WHERE relationship_id = ? ORDER BY created_at, id").all(relId) as any[];
  const audits = auditRows(s, "grant.created").slice(before);
  assert.equal(audits.length, grants.length, "one grant.created audit per grant row, no more");
  assert.deepEqual(audits.map((a) => a.subject).sort(), grants.map((g) => g.id).sort(), "every grant.created audit names the grant it wrote");
  // The acceptance announcement is written after the transaction commits and must come after the grants it describes.
  const accepted1 = auditRows(s, "relationship.accepted").at(-1);
  assert.ok(accepted1 && (audits.at(-1)?.seq ?? 0) < accepted1.seq, "relationship.accepted follows the grants it announces");
  assert.equal(s.platform.audit.verify().ok, true, "the hash chain must still verify");
});

test("an audit row follows the outermost transaction: a nested level hands its rows up, and a rollback drops them", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const p: any = s.platform;
  const rows = () => p.audit.db.prepare("SELECT subject FROM audit_events WHERE action = 'test.nested' ORDER BY seq").all() as any[];
  const drop = () => p.db.prepare("DROP TABLE IF EXISTS test_nested").run();

  // A savepoint that commits inside a transaction that then rolls back: the row it queued must go with the outer write.
  assert.throws(() => p.db.transaction(() => {
    p.db.transaction(() => { p.run("CREATE TABLE test_nested (x INTEGER)"); p.auditWrite("test", "test.nested", "inner", [], {}); })();
    throw new Error("the outer transaction rolls back");
  })(), /outer transaction rolls back/);
  assert.deepEqual(rows(), [], "no row survives the outer rollback, not even from the level that committed");
  assert.throws(() => p.db.prepare("SELECT * FROM test_nested").all(), /no such table/, "the outer write rolled back with it");

  // Both levels commit: each row reaches the log once, in the order it was written.
  p.db.transaction(() => {
    p.db.transaction(() => p.auditWrite("test", "test.nested", "inner", [], {}))();
    p.auditWrite("test", "test.nested", "outer", [], {});
  })();
  drop();
  assert.deepEqual(rows().map((r) => r.subject), ["inner", "outer"], "one row per write, in the order written");
  assert.equal(p.audit.verify().ok, true);
  p.audit.db.prepare("DELETE FROM audit_events WHERE action = 'test.nested'").run;
});

test("two consents committing at once write their rows once each and name only grants that exist", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const C = await ownerWithBot(s.base, "cat");
  const request = (to: string) => A.owner.req("POST", "/v1/relationships", { from_bot_id: A.bot.id, target_handle: to, message: "hi", requested_capabilities: ["chat.public"] });
  const one = await request(B.handle);
  const two = await request(C.handle);
  await Promise.all([
    B.owner.req("POST", `/v1/relationships/${one.relationship_id}/consent`, { decision: "accept", grant_capabilities: [] }),
    C.owner.req("POST", `/v1/relationships/${two.relationship_id}/consent`, { decision: "accept", grant_capabilities: [] }),
  ]);
  const grants = s.platform.db.prepare("SELECT id FROM grants ORDER BY id").all() as any[];
  const audits = auditRows(s, "grant.created");
  assert.equal(audits.length, grants.length, "each grant row has exactly one grant.created row");
  assert.deepEqual(audits.map((a) => a.subject).sort(), grants.map((g) => g.id).sort());
  assert.equal(s.platform.audit.verify().ok, true);
});

test("a lapse swept in a transaction that then throws writes no grant.expired, and the next sweep writes exactly one", async (t) => {
  // C14's reading, pinned the other way round: the sweep claimed the lapsed share, wrote `grant.expired` and took the
  // seat, and then a later write in the same transaction threw — the old code kept the audit row and left the seat
  // taken, because the row lived in the audit's own database. Now the row follows the commit: the rollback takes it
  // with the claim, and the next sweep announces the lapse once.
  const s: any = await startServer({ faceRooms: { attemptsPerAccount: 50, attemptsPerIp: 200 } });
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "ann");
  const B = await ownerWithBot(s.base, "ben");
  const F = await ownerWithBot(s.base, "fay");
  // Fay shares her Bot with Ann's, so Ann's Bot may seat it as a guest.
  const rel = await F.owner.req("POST", "/v1/relationships", { from_bot_id: F.bot.id, target_handle: A.handle, message: "hi", requested_capabilities: ["chat.public"] });
  const relId = rel.relationship_id as string;
  await A.owner.req("POST", `/v1/relationships/${relId}/consent`, { decision: "accept", grant_capabilities: [] });
  const grant = await F.owner.req("POST", `/v1/relationships/${relId}/grants`, { capability: "chat.public", expires_in_days: 30 });
  const grantId = grant.grant_id as string;

  const room = await B.owner.req("POST", "/v1/face-rooms/join", { code: "858585", bots: [B.bot.id] });
  const seated = await A.owner.req("POST", "/v1/face-rooms/join", { code: "858585", bots: [A.bot.id, F.bot.id] });
  assert.equal(seated.room_id, room.room_id, "control: the share seated Fay's Bot as a guest");
  const seat = () => s.platform.db.prepare("SELECT * FROM face_room_members WHERE room_id = ? AND bot_id = ?").get(room.room_id, F.bot.id) as any;
  assert.equal(seat().left_at, null, "control: the guest seat is taken");

  s.platform.db.prepare("UPDATE grants SET expires_at = ? WHERE id = ?").run("2020-01-01T00:00:00.000Z", grantId);
  const expiredAudits = () => (s.platform.audit.db.prepare("SELECT COUNT(*) n FROM audit_events WHERE action = 'grant.expired' AND subject = ?").get(grantId) as any).n as number;
  const expiredEvents = () => (s.platform.db.prepare("SELECT COUNT(*) n FROM events WHERE type = 'grant.changed' AND bot_id = ? AND data LIKE '%\"expired\"%'").get(A.bot.id) as any).n as number;

  // The sweep runs at the top of a join transaction, and the join itself is refused below it: one write in that
  // transaction fails after the lapse has been claimed and announced.
  s.platform.db.exec("CREATE TRIGGER refuse_member_insert BEFORE INSERT ON face_room_members BEGIN SELECT RAISE(ABORT, 'store refused the seat'); END");
  await assert.rejects(
    A.owner.req("POST", "/v1/face-rooms/join", { code: "868686", bots: [A.bot.id] }),
    (e: any) => e.status === 500,
    "the join whose transaction carried the sweep was refused",
  );
  s.platform.db.exec("DROP TRIGGER refuse_member_insert");

  const row = () => s.platform.db.prepare("SELECT * FROM grants WHERE id = ?").get(grantId) as any;
  assert.equal(row().revoked_at, null, "the lapse claim rolled back with the transaction");
  assert.equal(expiredAudits(), 0, "no grant.expired row survives a sweep that did not commit");
  assert.equal(expiredEvents(), 0, "and nothing was announced about it");
  assert.equal(seat().left_at, null, "the seat the rolled-back lapse paid for is still taken");

  // The same sweep, committed this time, announces the lapse exactly once.
  await B.owner.req("GET", "/v1/face-rooms");
  assert.equal(expiredAudits(), 1, "the next sweep announces the lapse once");
  assert.equal(expiredEvents(), 1);
  assert.notEqual(row().revoked_at, null);
  assert.notEqual(seat().left_at, null, "and the seat goes with it");
  assert.equal(s.platform.audit.verify().ok, true);
});
