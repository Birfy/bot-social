/**
 * The public preview of a link answers the link, never the people the link let in.
 *
 * `GET /v1/invites/{code}` is unauthenticated: anyone holding the code reads it. Its answer is a fixed whitelist
 * (`code`, `url`, `status`, `inviter`, the capabilities, `message`, `expires_at`, `server`) with no `joins`, so a
 * link holder learns nothing about who joined — that was already true of the answer. What was not true of the work:
 * the preview built the owner's whole view first (`inviteView`), joins included, and then dropped the field, so every
 * anonymous request paid for a `relationship_invites` lookup whose result was thrown away.
 *
 * Two facts pin that here, both about the work and not the answer: the preview must not call `inviteJoins` at all,
 * and the join lookup the owner's list does run must find its rows through the invite rather than scanning every
 * join row in the database. The answer itself is unchanged — `an_invite_names_the_joins_it_produced` still pins the
 * owner's list, and still pins that the preview carries no `joins` field.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { bulkAuth, ownerWithBot, startServer } from "./helpers.js";

type S = Awaited<ReturnType<typeof startServer>>;

/** The exact query `inviteJoins` runs, kept here shape for shape so the plan is about that query and no other. */
const JOINS_SQL =
  "SELECT r.id, r.status, r.created_at, r.requester_bot, r.target_bot FROM relationships r JOIN relationship_invites ri ON ri.relationship_id = r.id WHERE ri.invite_id = ? ORDER BY r.created_at, r.rowid";

test("the joins of a link are found through the invite, not by scanning every join", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const a = await ownerWithBot(s.base, "joinplan");
  const inv = await a.owner.req("POST", "/v1/invites", { bot_id: a.bot.id });
  assert.ok(inv.code, `the link was minted: ${JSON.stringify(inv)}`);
  const id = (s.platform as any).db.prepare("SELECT id FROM invites WHERE code = ?").get(inv.code).id as string;

  const plan = (s.platform as any).db.prepare(`EXPLAIN QUERY PLAN ${JOINS_SQL}`).all(id) as any[];
  const lines = plan.map((p) => String(p.detail)).join("\n");
  const joinRows = plan.filter((p) => /\bri\b/.test(String(p.detail)));
  assert.equal(joinRows.length, 1, `the plan names the join table once:\n${lines}`);
  const row = String(joinRows[0].detail);
  assert.doesNotMatch(row, /\bSCAN\b/, `the join table is not scanned row by row:\n${lines}`);
  assert.match(row, /SEARCH ri USING (COVERING )?INDEX/, `the join table is searched through an index:\n${lines}`);
});

test("the public preview answers without walking the joins at all", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const a = await ownerWithBot(s.base, "joinprev");
  const inv = await a.owner.req("POST", "/v1/invites", { bot_id: a.bot.id });
  assert.ok(inv.code, `the link was minted: ${JSON.stringify(inv)}`);

  // The preview must not be computing joins and dropping them: swap the one method that computes them for a stub
  // that throws, and the preview still has to answer. Nothing is written into src for this.
  const platform: any = s.platform;
  const real = platform.inviteJoins;
  let walked = 0;
  platform.inviteJoins = () => { walked += 1; throw new Error("the public preview walked the joins"); };
  t.after(() => { platform.inviteJoins = real; });

  const preview = platform.inviteInfo(inv.code);
  assert.equal(walked, 0, "the preview never asked for the joins");
  assert.equal(Object.prototype.hasOwnProperty.call(preview, "joins"), false, "and it still answers no joins");
  assert.equal(preview.code, inv.code);
  assert.equal(preview.status, "active");
  assert.equal(preview.inviter.handle, a.handle);
  assert.equal(preview.server, platform.publicBaseUrl);
});
