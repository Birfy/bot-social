import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { bulkAuth, friends, startServer } from "./helpers.js";

/** What each read entry must declare. The three list reads call `expireStale()`, which settles a lapsed grant and
 *  emits `grant.changed` (one webhook POST when the affected Bot has one), so they reach outside the server.
 *  `get_conversation` settles the same lapsed grant through `findGrant` silently, so its world stays closed.
 *  None of them deletes or revokes anything: an expiry records a lapse that already happened. */
const DECLARED: Record<string, Record<string, boolean>> = {
  list_friends: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  list_bot_grants: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  list_remote_bots: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  get_conversation: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
};

async function connect(base: string, token: string) {
  const c = new Client({ name: "t", version: "0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return c;
}
const parse = (r: any) => JSON.parse(r.content[0].text);
const call = async (c: any, name: string, args: any = {}) => { const r: any = await c.callTool({ name, arguments: args }); assert.ok(!r.isError, JSON.stringify(r)); return parse(r); };
const past = "2000-01-01T00:00:00.000Z";

test("the four read entries declare that reading settles lapsed access", async (t) => {
  const s = await startServer(bulkAuth);
  const { A } = await friends(s.base);
  const c = await connect(s.base, (A.owner as any).token);
  t.after(async () => { await c.close(); await s.stop(); });

  const tools: any[] = (await c.listTools()).tools;
  const seen: Record<string, Record<string, boolean | undefined>> = {};
  for (const name of Object.keys(DECLARED)) {
    const tool = tools.find((x) => x.name === name);
    assert.ok(tool, `${name} is registered`);
    seen[name] = { readOnlyHint: tool.annotations?.readOnlyHint, destructiveHint: tool.annotations?.destructiveHint, openWorldHint: tool.annotations?.openWorldHint };
  }
  // All four in one comparison: a red run names every tool that still lies, not just the first.
  assert.deepEqual(seen, DECLARED, "each read entry declares the write it performs");
});

test("each read still performs the write it now declares", async (t) => {
  const sink = createServer((req, res) => {
    req.on("data", () => {});
    req.on("end", () => { hits.push(1); res.writeHead(200, { "content-type": "application/json" }).end("{}"); });
  });
  const hits: number[] = [];
  await new Promise<void>((resolve) => sink.listen(0, "127.0.0.1", () => resolve()));
  const hook = `http://127.0.0.1:${(sink.address() as any).port}/hook`;
  t.after(async () => { await new Promise<void>((r) => sink.close(() => r())); });

  // One server per tool, so one tool's sweep cannot settle the fixture prepared for the next.
  const cases: { name: string; withConversation?: boolean }[] = [
    { name: "list_friends" },
    { name: "list_bot_grants" },
    { name: "list_remote_bots" },
    { name: "get_conversation", withConversation: true },
  ];
  for (const spec of cases) {
    const s = await startServer({ ...bulkAuth, webhooks: { debounceMs: 0 } });
    const { A, B } = await friends(s.base, { freebusy: true });
    const conv = spec.withConversation ? await A.bot.startConversation(B.bot.id, { type: "general_chat", summary: "hi" }) : null;
    // B granted A `calendar.freebusy.read`; the lapsed row is what each read settles.
    const grant = s.platform.db.prepare("SELECT id FROM grants WHERE grantee_bot = ? AND grantor_owner = ?").get(A.bot.id, B.owner_id) as any;
    assert.ok(grant, "the fixture holds one grant");
    s.platform.db.prepare("UPDATE grants SET expires_at = ? WHERE id = ?").run(past, grant.id);
    const c = await connect(s.base, (A.owner as any).token);
    await call(c, "set_webhook", { url: hook });
    await s.platform.webhooks.flush();
    hits.length = 0;

    const row = () => s.platform.db.prepare("SELECT status FROM grants WHERE id = ?").get(grant.id) as any;
    const events = () => (s.platform.db.prepare("SELECT COUNT(*) n FROM events").get() as any).n;
    const audit = () => s.platform.audit.list({ limit: 2000 }).length;
    const before = { status: row().status, events: events(), audit: audit() };
    assert.equal(before.status, "active", "the fixture starts live");

    if (spec.name === "list_bot_grants") await call(c, "list_bot_grants", { bot_id: A.bot.id });
    else if (spec.name === "get_conversation") await call(c, "get_conversation", { conversation_id: (conv as any).conversation_id });
    else await call(c, spec.name, {});
    await s.platform.webhooks.flush();

    assert.equal(row().status, "expired", `${spec.name} still settles the lapsed grant`);
    if (spec.withConversation) {
      // The reach check's lazy write-back is silent on master and stays silent: no audit row, no event, no POST.
      assert.equal(events(), before.events, `${spec.name} emits nothing`);
      assert.equal(audit(), before.audit, `${spec.name} writes no audit row`);
      assert.equal(hits.length, 0, `${spec.name} pushes no webhook`);
    } else {
      assert.equal(events(), before.events + 1, `${spec.name} emits one event`);
      assert.equal(audit(), before.audit + 1, `${spec.name} writes one audit row`);
      assert.equal(hits.length, 1, `${spec.name} pushes exactly one webhook`);
    }
    await c.close();
    await s.stop();
  }
});
