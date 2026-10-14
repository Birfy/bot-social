import { AddressInfo } from "node:net";
import { BotClient, OwnerClient } from "../src/client.js";
import { generateEd25519 } from "../src/crypto.js";
import { Platform } from "../src/platform.js";
import { buildServer } from "../src/server.js";

export async function startServer() {
  const platform = new Platform();
  const app = buildServer(platform);
  await app.listen({ port: 0, host: "127.0.0.1" });
  const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  return { platform, app, base, stop: async () => { await app.close(); platform.close(); } };
}

let n = 0;
export async function ownerWithBot(base: string, name: string, webhook_url?: string) {
  const u = `${name}${++n}`;
  const { client: owner, owner_id } = await OwnerClient.register(base, u, "secret-pw", name);
  const kp = generateEd25519();
  const r = await owner.req("POST", "/v1/bots", { handle: `${u}.bot`, public_key: { alg: "Ed25519", kid: "k1", value: kp.publicKey }, webhook_url });
  const bot = new BotClient({ base, botId: r.bot_id, token: r.bot_token, kid: "k1", privateKeyPem: kp.privateKeyPem });
  return { owner, owner_id, bot, handle: `@${u}.bot`, kp, webhookSecret: r.webhook_secret as string, reg: r };
}

/** Two owners with bots that are friends; B granted A freebusy if `freebusy`. */
export async function friends(base: string, opts: { freebusy?: boolean } = {}) {
  const A = await ownerWithBot(base, "alice");
  const B = await ownerWithBot(base, "bob");
  const rel = await A.owner.req("POST", "/v1/relationships", { from_bot_id: A.bot.id, target_handle: B.handle, message: "hi", requested_capabilities: ["chat.public"] });
  await B.owner.req("POST", `/v1/relationships/${rel.relationship_id}/consent`, {
    decision: "accept", grant_capabilities: opts.freebusy ? [{ capability: "calendar.freebusy.read", scope: { window_days: 14, hours: "09:00-18:00" } }] : [],
  });
  return { A, B, relId: rel.relationship_id as string };
}

export async function approveAll(owner: OwnerClient, decision = "approved") {
  const { approvals } = await owner.req("GET", "/v1/approvals?status=pending");
  for (const a of approvals) await owner.req("POST", `/v1/approvals/${a.approval_id}/decision`, { decision });
  return approvals;
}

export async function expectApiError(p: Promise<unknown>, status: number, code?: string) {
  try { await p; } catch (e: any) {
    if (e.status !== status || (code && e.code !== code)) throw new Error(`expected ${status} ${code}, got ${e.status} ${e.code}: ${e.message}`);
    return e;
  }
  throw new Error(`expected ${status} ${code}, but call succeeded`);
}

export const inDays = (d: number, h = 10) => {
  const t = new Date(Date.now() + d * 86400e3);
  t.setUTCHours(0, 0, 0, 0);
  return new Date(t.getTime() + (h - 8) * 3600e3).toISOString(); // h o'clock Asia/Shanghai (fractional ok)
};
