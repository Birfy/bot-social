/**
 * An invite link answers who it let in, not only how many times it was spent.
 *
 * `inviteView` names the link's Bot, its capabilities, its `uses` and `max_uses` — every fact but the one the owner
 * needs to act: which relationship each use produced. The join row already records it (`relationship_invites` is
 * written by `joinInvite` and by a regrant), so the owner's own list can name the joins it made: the relationship id,
 * the joining Bot's handle, that relationship's status and when it was created.
 *
 * The link's owner is the approval counterparty of every join it made, so the list does not filter by status: a
 * request still waiting for consent, a declined one and an active friendship are all joins this link produced. The
 * rows come in the order the relationships were created, so two joins of one link read in the order they happened.
 * A relationship is written once per link (`relationship_invites` holds one row per relationship), and a regrant
 * reuses that relationship, so it is named once however many uses it spends.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { bulkAuth, ownerWithBot, startServer } from "./helpers.js";

type S = Awaited<ReturnType<typeof startServer>>;

const invites = async (o: any): Promise<any[]> => (await o.req("GET", "/v1/invites")).invites;
const byCode = (list: any[], code: string) => {
  const row = list.find((i) => i.code === code);
  assert.ok(row, `the list names the link ${code}`);
  return row;
};
const createdAt = (s: S, relId: string) =>
  (s.platform as any).db.prepare("SELECT created_at FROM relationships WHERE id = ?").get(relId).created_at as string;

async function connect(base: string, token: string) {
  const c = new Client({ name: "t", version: "0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return c;
}
const parse = (r: any) => JSON.parse(r.content[0].text);

test("a link names the joins it produced, oldest first, and an unused link names none", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "joinlista"), B = await ownerWithBot(s.base, "joinlistb"), C = await ownerWithBot(s.base, "joinlistc");
  const inv = await A.owner.req("POST", "/v1/invites", { bot_id: A.bot.id, max_uses: 2 });

  // A link nobody has used lists no joins at all.
  assert.deepEqual(byCode(await invites(A.owner), inv.code).joins, [], "an unused link names no joins");

  const j1 = await B.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: B.bot.id });
  assert.equal(j1.status, "active", "the default auto-accept link makes this join live at once");
  const one = byCode(await invites(A.owner), inv.code);
  // Exactly what one join is, field by field: nothing extra, nothing missing.
  assert.deepEqual(one.joins, [{ relationship_id: j1.relationship_id, bot: B.handle, status: "active", joined_at: createdAt(s, j1.relationship_id) }]);
  assert.equal(one.uses, 1, "the count the owner already had keeps its meaning");

  const j2 = await C.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: C.bot.id });
  const two = byCode(await invites(A.owner), inv.code);
  assert.deepEqual(two.joins, [
    { relationship_id: j1.relationship_id, bot: B.handle, status: "active", joined_at: createdAt(s, j1.relationship_id) },
    { relationship_id: j2.relationship_id, bot: C.handle, status: "active", joined_at: createdAt(s, j2.relationship_id) },
  ], "the second join is appended, in the order the relationships were created");
  assert.deepEqual(two.joins.map((j: any) => j.joined_at), [...two.joins.map((j: any) => j.joined_at)].sort(), "joined_at reads oldest first");
  assert.equal(two.uses, 2);
});

test("a revoked link keeps the joins it made", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "joinrev-a"), B = await ownerWithBot(s.base, "joinrev-b");
  const inv = await A.owner.req("POST", "/v1/invites", { bot_id: A.bot.id, max_uses: 2 });
  const j = await B.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: B.bot.id });

  await A.owner.req("DELETE", `/v1/invites/${inv.code}`);
  const row = byCode(await invites(A.owner), inv.code);
  assert.equal(row.status, "revoked", "the link is closed");
  assert.deepEqual(row.joins, [{ relationship_id: j.relationship_id, bot: B.handle, status: "active", joined_at: createdAt(s, j.relationship_id) }], "closing the link forgets no join it made");
});

test("a join is named with its own status, waiting for approval or ended", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "joinpend-a"), B = await ownerWithBot(s.base, "joinpend-b");
  const inv = await A.owner.req("POST", "/v1/invites", { bot_id: A.bot.id, max_uses: 2 });
  const j: any = await B.bot.signed(`/v1/invites/${inv.code}/join`, "invite.join", { code: inv.code });
  assert.equal(j.status, "pending_requester_owner", "a Bot's join waits for its own owner first");

  const row = byCode(await invites(A.owner), inv.code);
  assert.deepEqual(row.joins, [{ relationship_id: j.relationship_id, bot: B.handle, status: "pending_requester_owner", joined_at: createdAt(s, j.relationship_id) }], "the link's owner is the counterparty of a request still waiting, so it is named as one");

  // The relationship ending does not hide it: the list answers every status the link produced, the one it has now.
  (s.platform as any).db.prepare("UPDATE relationships SET status = 'ended' WHERE id = ?").run(j.relationship_id);
  const ended = byCode(await invites(A.owner), inv.code);
  assert.deepEqual(ended.joins, [{ relationship_id: j.relationship_id, bot: B.handle, status: "ended", joined_at: createdAt(s, j.relationship_id) }], "an ended relationship stays named, with the status it has now");
});

test("another owner's list never carries these joins", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "joinown-a"), B = await ownerWithBot(s.base, "joinown-b");
  const invA = await A.owner.req("POST", "/v1/invites", { bot_id: A.bot.id, max_uses: 2 });
  const j = await B.owner.req("POST", `/v1/invites/${invA.code}/join`, { from_bot_id: B.bot.id });
  const invB = await B.owner.req("POST", "/v1/invites", { bot_id: B.bot.id });

  const listed = await invites(B.owner);
  assert.deepEqual(listed.map((i: any) => i.code), [invB.code], "an owner lists their own links only");
  assert.deepEqual(byCode(listed, invB.code).joins, [], "and the joining owner's own link names no joins on the strength of the join they made");
  // The joiner's Bot also reads only its own links: no row of the inviter's link is reachable through it.
  const botList = await B.bot.req("GET", "/v1/invites");
  assert.deepEqual(botList.invites.map((i: any) => i.code), [invB.code], "a Bot's list is its own links");
  // The join itself is real; only the attribution stays with the link's owner.
  assert.equal(byCode(await invites(A.owner), invA.code).joins[0].relationship_id, j.relationship_id);
  // Anyone holding the link can read its public preview, so the preview must not answer the joins too.
  const preview: any = await (await fetch(`${s.base}/v1/invites/${invA.code}`)).json();
  assert.equal(preview.status, "active", "the preview answers as it always did");
  assert.equal(Object.prototype.hasOwnProperty.call(preview, "joins"), false, "a link holder learns nothing about who joined it");
});

test("the owner MCP tool answers the same joins field", async (t) => {
  const s = await startServer(bulkAuth);
  const A = await ownerWithBot(s.base, "joinmcp-a"), B = await ownerWithBot(s.base, "joinmcp-b");
  const c = await connect(s.base, (A.owner as any).token);
  t.after(async () => { await c.close(); await s.stop(); });

  const inv = await A.owner.req("POST", "/v1/invites", { bot_id: A.bot.id, max_uses: 2 });
  const j = await B.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: B.bot.id });

  const rest = byCode(await invites(A.owner), inv.code);
  const mcp: any = parse(await c.callTool({ name: "list_invites", arguments: {} }));
  const row = mcp.invites.find((i: any) => i.invite_id === inv.invite_id);
  assert.ok(row, "the tool lists the link");
  assert.deepEqual(row.joins, rest.joins, "one `inviteView`, one answer");
  assert.deepEqual(row.joins, [{ relationship_id: j.relationship_id, bot: B.handle, status: "active", joined_at: createdAt(s, j.relationship_id) }]);
});

test("a link reused to regrant one relationship names it once", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const A = await ownerWithBot(s.base, "joindup-a"), B = await ownerWithBot(s.base, "joindup-b");
  const inv = await A.owner.req("POST", "/v1/invites", { bot_id: A.bot.id, max_uses: 3 });
  const j1 = await B.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: B.bot.id });

  // The inviter's own share of that Bot was withdrawn, so the same link shares it again over the same relationship.
  (s.platform as any).db.prepare("UPDATE grants SET status = 'revoked' WHERE relationship_id = ? AND grantor_owner = ? AND grantee_bot = ?")
    .run(j1.relationship_id, A.owner_id, B.bot.id);
  const j2 = await B.owner.req("POST", `/v1/invites/${inv.code}/join`, { from_bot_id: B.bot.id });
  assert.equal(j2.regranted, true, "the reuse is a regrant of the relationship the link already made");
  assert.equal(j2.relationship_id, j1.relationship_id);

  const row = byCode(await invites(A.owner), inv.code);
  assert.equal(row.uses, 2, "both uses are spent");
  assert.deepEqual(row.joins, [{ relationship_id: j1.relationship_id, bot: B.handle, status: "active", joined_at: createdAt(s, j1.relationship_id) }], "one relationship is named once, however many uses it took");
});
