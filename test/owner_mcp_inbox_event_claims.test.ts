import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { bulkAuth, friends, startServer } from "./helpers.js";

/** The owner connector as a client reaches it: a real MCP client over HTTP, the door the tools travel through. */
async function connect(base: string, token: string) {
  const c = new Client({ name: "t", version: "0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return c;
}

const parse = (r: any) => {
  assert.ok(!r.isError, JSON.stringify(r));
  return JSON.parse(r.content[0].text);
};
const claim = async (c: Client, event_id: string, holder: string, ttl_seconds?: number) =>
  parse(await c.callTool({ name: "claim_inbox_event", arguments: { event_id, holder, ...(ttl_seconds === undefined ? {} : { ttl_seconds }) } } as any));
const ack = async (c: Client, event_id: string, holder: string, outcome: "replied" | "failed" | "needs-human") =>
  parse(await c.callTool({ name: "ack_inbox_event", arguments: { event_id, holder, outcome } } as any));

/** One custody-enabled owner with something to deliver: B opens a conversation with A's bot, then A peeks
 *  (peek leaves the cursor alone, exactly like the two-client case this feature exists for). */
async function fixture(box: { t: number }) {
  const s = await startServer({ ...bulkAuth, now: () => box.t });
  const { A, B } = await friends(s.base);
  const c = await connect(s.base, (A.owner as any).token);
  const en: any = await c.callTool({ name: "enable_custody", arguments: {} });
  assert.ok(!en.isError, JSON.stringify(en));
  await B.bot.startConversation(A.bot.id, { type: "general_chat", summary: "probe" });
  const peek = parse(await c.callTool({ name: "list_inbox", arguments: { peek: true } } as any));
  assert.ok(peek.events.length > 0, "the fixture leaves an event to claim");
  const cursor = () => (s.platform.db.prepare("SELECT events_cursor FROM bot_custody WHERE bot_id = ?").get(A.bot.id) as any).events_cursor;
  return { s, A, c, eventId: peek.events[0].event_id as string, cursor };
}

test("two holders claiming one event: exactly one claimed, the other held", async () => {
  const box = { t: Date.now() };
  const { s, c, eventId } = await fixture(box);
  try {
    const [x, y]: any[] = await Promise.all([claim(c, eventId, "host-a"), claim(c, eventId, "host-b")]);
    assert.deepEqual([x.status, y.status].sort(), ["claimed", "held"], `one claim wins: ${JSON.stringify([x, y])}`);
    const won = x.status === "claimed" ? x : y;
    const lost = x.status === "claimed" ? y : x;
    assert.equal(won.holder, x.status === "claimed" ? "host-a" : "host-b");
    assert.equal(won.lease_until, box.t + 300_000, "the default lease is 300 s, in epoch milliseconds");
    assert.equal(lost.holder, won.holder, "the loser is told who holds it");
    assert.equal(lost.lease_until, won.lease_until);

    // The same holder calling again renews rather than colliding with itself, and does not shorten the lease.
    const renew: any = await claim(c, eventId, won.holder);
    assert.equal(renew.status, "claimed");
    assert.equal(renew.lease_until, box.t + 300_000);
    // The winning holder is still the only one; a second holder keeps getting held, not claimed.
    const third: any = await claim(c, eventId, "host-c");
    assert.equal(third.status, "held");
    assert.equal(third.holder, won.holder);
  } finally { await c.close(); await s.stop(); }
});

test("replied is terminal: a later claim answers settled and writes nothing", async () => {
  const box = { t: Date.now() };
  const { s, c, eventId, cursor } = await fixture(box);
  try {
    const before = cursor();
    assert.equal((await claim(c, eventId, "host-a")).status, "claimed");
    assert.equal((await ack(c, eventId, "host-a", "replied")).status, "acked");
    assert.equal((await claim(c, eventId, "host-b")).status, "settled");
    assert.equal((await claim(c, eventId, "host-a")).status, "settled", "the delivering holder does not re-open it either");
    // A retried ack of the same outcome is the ack that already landed.
    assert.equal((await ack(c, eventId, "host-a", "replied")).status, "acked");
    assert.equal(cursor(), before, "claims never move the inbox cursor");
  } finally { await c.close(); await s.stop(); }
});

test("an expired lease belongs to nobody: the old holder's ack is stale, a new holder can claim", async () => {
  const box = { t: Date.now() };
  const { s, c, eventId } = await fixture(box);
  try {
    const first: any = await claim(c, eventId, "host-a");
    assert.equal(first.status, "claimed");
    box.t += 300_000; // exactly at the edge: the lease is over, not merely about to end
    assert.equal((await ack(c, eventId, "host-a", "replied")).status, "stale-holder", "an expired lease may not write");
    const second: any = await claim(c, eventId, "host-b");
    assert.equal(second.status, "claimed");
    assert.equal(second.holder, "host-b");
    assert.equal(second.lease_until, box.t + 300_000);
    assert.equal((await ack(c, eventId, "host-a", "failed")).status, "stale-holder", "the old holder is not the current one");
    assert.equal((await ack(c, eventId, "host-b", "replied")).status, "acked");
    assert.equal((await claim(c, eventId, "host-a")).status, "settled", "the new holder's answered event stays settled");
  } finally { await c.close(); await s.stop(); }
});

test("failed releases at once and a repeated ack is idempotent", async () => {
  const box = { t: Date.now() };
  const { s, c, eventId } = await fixture(box);
  try {
    assert.equal((await claim(c, eventId, "host-a")).status, "claimed");
    assert.equal((await ack(c, eventId, "host-a", "failed")).status, "acked");
    assert.equal((await ack(c, eventId, "host-a", "failed")).status, "acked", "repeating the release is still acked");
    // No clock moved: a failed attempt must not make the event wait out a lease.
    const next: any = await claim(c, eventId, "host-b");
    assert.equal(next.status, "claimed");
    assert.equal(next.holder, "host-b");
    assert.equal((await ack(c, eventId, "host-a", "failed")).status, "stale-holder", "the released holder lost it");
    assert.equal((await ack(c, eventId, "host-b", "needs-human")).status, "acked");
    assert.equal((await claim(c, eventId, "host-a")).status, "settled", "needs-human is terminal too");
    assert.equal((await ack(c, eventId, "nobody", "replied")).status, "stale-holder");
    const unknown: any = await ack(c, "evt_that_was_never_claimed", "host-a", "replied");
    assert.equal(unknown.status, "unknown", "no claim on that event");
  } finally { await c.close(); await s.stop(); }
});

test("ttl_seconds is bounded: above 3600 s the claim is refused", async () => {
  const box = { t: Date.now() };
  const { s, c, eventId } = await fixture(box);
  try {
    const tooLong: any = await c.callTool({ name: "claim_inbox_event", arguments: { event_id: eventId, holder: "host-a", ttl_seconds: 3601 } } as any);
    assert.ok(tooLong.isError, "3601 s is out of range");
    assert.equal((await claim(c, eventId, "host-a", 3600)).status, "claimed", "the upper bound itself is allowed");
  } finally { await c.close(); await s.stop(); }
});
