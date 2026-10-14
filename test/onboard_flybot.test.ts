import assert from "node:assert/strict";
import { test } from "node:test";
import { startServer } from "./helpers.js";

async function post(base: string, path: string, body: unknown) {
  const r = await fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() as any };
}
async function mcp(base: string, token: string, name: string, args: unknown = {}) {
  const r = await fetch(base + "/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
  const j: any = await r.json();
  return JSON.parse(j.result.content[0].text);
}

test("POST /v1/onboard/flybot returns identity, connector token and webhook config in one call", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const r = await post(s.base, "/v1/onboard/flybot", { display_name: "Dan", bot_handle: "dan.flybot", webhook_url: "http://127.0.0.1:9/hook" });
  assert.equal(r.status, 201);
  assert.equal(r.body.bot.handle, "@dan.flybot");
  assert.equal(r.body.bot.custodial, true);
  assert.match(r.body.connector.token, /.+/);
  assert.equal(r.body.mcp_url.endsWith("/mcp"), true);
  assert.equal(r.body.webhook.url, "http://127.0.0.1:9/hook");
  assert.match(r.body.webhook.secret, /.+/);
  assert.equal(r.body.webhook.signature_header, "x-botsocial-signature");
  // The connector token works on the owner MCP endpoint right away.
  const overview = await mcp(s.base, r.body.connector.token, "list_friends");
  assert.equal(overview.bot.handle, "@dan.flybot");
  // Without a webhook the call still onboards; a taken handle is refused.
  const plain = await post(s.base, "/v1/onboard/flybot", { display_name: "Eve" });
  assert.equal(plain.status, 201);
  assert.equal(plain.body.webhook, null);
  assert.equal((await post(s.base, "/v1/onboard/flybot", { bot_handle: "dan.flybot" })).status, 409);
  assert.equal((await post(s.base, "/v1/onboard/flybot", { webhook_url: "not a url" })).status >= 400, true);
});

test("FlyBot homes: members of friend homes can message each other; revoked members cannot", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const a = (await post(s.base, "/v1/onboard/flybot", { display_name: "Danyang" })).body;
  const b = (await post(s.base, "/v1/onboard/flybot", { display_name: "Bob" })).body;
  assert.equal(a.home.handle, "@danyang.home");
  const A = (name: string, args: unknown = {}) => mcp(s.base, a.connector.token, name, args);
  const B = (name: string, args: unknown = {}) => mcp(s.base, b.connector.token, name, args);
  const writer = await A("add_home_member", { home: a.home.bot_id, name: "Writer" });
  assert.equal(writer.handle, "@writer.danyang.home");
  const coder = await B("add_home_member", { home: b.home.bot_id, name: "coder" });
  // Not friends yet: members cannot reach each other.
  const refused = await fetch(s.base + "/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${a.connector.token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_as_member", arguments: { from_bot_id: writer.bot_id, to: coder.handle, text: "hi" } } }) }).then((r) => r.json()) as any;
  assert.equal(refused.result.isError, true);
  // Home-to-home friendship through an invite.
  const inv = await A("create_invite", { bot_id: a.home.bot_id, auto_accept: true, offered_capabilities: ["chat.public"], requested_capabilities: ["chat.public"] });
  await B("join_invite", { code: inv.code ?? inv.invite?.code, from_bot_id: b.home.bot_id });
  const pending = await A("list_friends", { bot_id: a.home.bot_id });
  if (pending.pending_incoming?.length) {
    // Not auto-accepted on this server: the owner accepts it (confirmation flow is out of scope here).
    (s.platform as any).respondRelationship?.({ kind: "owner", ownerId: a.owner_id } as any, pending.pending_incoming[0].relationship_id, { decision: "accept", grant_capabilities: ["chat.public"] });
  }
  const remote = await A("list_remote_bots", { home: a.home.bot_id });
  assert.equal(remote.homes.length, 1);
  assert.equal(remote.homes[0].home.handle, "@bob.home");
  assert.deepEqual(remote.homes[0].bots.map((x: any) => x.handle), ["@coder.bob.home"]);
  const sent = await A("send_as_member", { from_bot_id: writer.bot_id, to: coder.handle, text: "hello from writer" });
  assert.match(sent.conversation_id, /.+/);
  // Revoked member: refused.
  await A("remove_home_member", { home: a.home.bot_id, member: writer.bot_id });
  const after = await A("list_home_members", { home: a.home.bot_id });
  assert.deepEqual(after.members, []);
  const raw = await fetch(s.base + "/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${a.connector.token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "send_as_member", arguments: { from_bot_id: writer.bot_id, to: coder.handle, text: "still there?" } } }) }).then((r) => r.json()) as any;
  assert.equal(raw.result.isError, true);
  assert.match(raw.result.content[0].text, /bot_revoked/);
  // The draft is waiting for Danyang's approval on the server (home-level setting).
  const approvals = await A("list_approvals");
  assert.ok(approvals.approvals.some((x: any) => x.kind === "message" || /message/.test(x.kind ?? "")));
});
