// P7: newest-N audit pages, and limit/since that cannot reach SQLite as NaN (audit/limit family).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { AuditLog } from "../src/audit.js";
import { ownerWithBot, startServer } from "./helpers.js";

let S: Awaited<ReturnType<typeof startServer>>;
let A: Awaited<ReturnType<typeof ownerWithBot>>;
const seqs = (r: any) => (r.events as any[]).map((e) => e.seq);

before(async () => {
  S = await startServer();
  A = await ownerWithBot(S.base, "auditlimit");
  for (let i = 0; i < 5; i++) await A.owner.req("PATCH", "/v1/me", { display_name: `p7-${i}` });
});
after(async () => { await S.stop(); });

test("audit ?limit=N is the newest N records, still ascending (not the oldest N)", async () => {
  const all = await A.owner.req("GET", "/v1/audit-events?limit=1000");
  assert.equal(all.events.length, 7); // owner.registered + bot.registered + 5 settings updates
  const two = await A.owner.req("GET", "/v1/audit-events?limit=2");
  assert.deepEqual(seqs(two), seqs(all).slice(-2));
  assert.equal(two.chain.count, all.chain.count);
  const five = await A.owner.req("GET", "/v1/audit-events?limit=5");
  assert.deepEqual(seqs(five), seqs(all).slice(-5));
});

test("audit ?limit: abc, 1.5, 1e21 and -5 answer 200 with a bounded page (never 500)", async () => {
  const all = await A.owner.req("GET", "/v1/audit-events?limit=1000");
  for (const raw of ["abc", "1e21"]) {
    const r = await A.owner.req("GET", `/v1/audit-events?limit=${raw}`);
    assert.equal(seqs(r).length, all.events.length, `limit=${raw} falls back to 1000`);
  }
  const frac = await A.owner.req("GET", "/v1/audit-events?limit=1.5");
  assert.deepEqual(seqs(frac), seqs(all).slice(-1), "1.5 floors to 1");
  const neg = await A.owner.req("GET", "/v1/audit-events?limit=-5");
  assert.ok(seqs(neg).length <= 1000, "-5 is a fallback page, not SQLite's unlimited");
});

test("storage guard: a negative, fractional or unsafe limit never becomes an SQL LIMIT", () => {
  const a = new AuditLog(":memory:");
  const ins = a.db.prepare("INSERT INTO audit_events (seq,id,ts,actor,action,subject,owners,data,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?)");
  for (let i = 1; i <= 1001; i++) ins.run(i, `evt-${i}`, new Date(0).toISOString(), "platform", "test.record", null, "[]", "{}", "0".repeat(64), "x");
  assert.deepEqual(a.list({ limit: 2 }).map((e) => e.seq), [1000, 1001]);
  assert.equal(a.list({ limit: 1001 }).length, 1001, "a safe integer is honoured");
  for (const bad of [-5, 1.5, 1e21] as number[]) {
    const rows = a.list({ limit: bad });
    assert.equal(rows.length, 1000, `limit=${bad} falls back to 1000, not ${rows.length}`);
    assert.equal(rows[rows.length - 1].seq, 1001);
  }
  assert.equal(a.list({ limit: 0 }).length, 0, "0 is an empty page, not a default");
  a.db.close();
});

test("webhook deliveries ?limit=abc answers 200 instead of passing NaN to SQLite", async () => {
  const all = await A.owner.req("GET", `/v1/bots/${A.bot.id}/webhook/deliveries`);
  assert.deepEqual(all.deliveries, []);
  for (const raw of ["abc", "1.5", "-5", "1e21"]) {
    const r = await A.owner.req("GET", `/v1/bots/${A.bot.id}/webhook/deliveries?limit=${raw}`);
    assert.equal(r.deliveries.length, 0, `limit=${raw} still answers a page`);
  }
});

test("events ?limit=abc and ?since=abc/1.5 stay integers on the wire", async () => {
  for (const raw of ["abc", "1.5", "1e21", "-5"]) {
    const r = await A.bot.req("GET", `/v1/events?limit=${raw}`);
    assert.ok(Array.isArray(r.events), `limit=${raw} answers events`);
  }
  const bad = await A.bot.req("GET", "/v1/events?since=abc");
  assert.equal(bad.next_cursor, 0, "a bad cursor is 0, not NaN/null");
  const frac = await A.bot.req("GET", "/v1/events?since=1.5");
  assert.equal(frac.next_cursor, 1, "a fractional cursor floors to an integer");
  const neg = await A.bot.req("GET", "/v1/events?since=-3");
  assert.equal(neg.next_cursor, 0, "a negative cursor is a fallback, not a rewind");
});

test("botctl audit rejects a bad --limit up front and prints the newest page", async () => {
  const dir = mkdtempSync(join(tmpdir(), "botctl-audit-"));
  const home = join(dir, ".bot-social");
  mkdirSync(home, { recursive: true }); // BOTSOCIAL_HOME must exist for load() to find the config
  writeFileSync(join(home, "p7.json"), JSON.stringify({ name: "p7", base: S.base, owner_id: A.owner_id, owner_token: A.owner.token }));
  const run = (...a: string[]) => promisify(execFile)(process.execPath, ["--import", "tsx", "scripts/botctl.ts", ...a], {
    env: { ...process.env, BOTSOCIAL_HOME: home, BOTSOCIAL_URL: "" }, encoding: "utf8",
  });
  await assert.rejects(run("audit", "--limit", "abc"), (e: any) => {
    assert.equal(e.code, 1);
    assert.match(String(e.stderr), /--limit must be a positive integer/);
    return true;
  });
  await assert.rejects(run("audit", "--limit", "-5"), (e: any) => {
    assert.equal(e.code, 1);
    assert.match(String(e.stderr), /--limit must be a positive integer/);
    return true;
  });
  const lim = JSON.parse((await run("audit", "--limit", "2", "--json")).stdout);
  assert.deepEqual(lim.events.map((e: any) => e.seq), [7, 8], "the CLI shows the newest two, not the oldest two");
});
