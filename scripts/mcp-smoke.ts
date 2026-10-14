/**
 * Smoke test for the stdio MCP server against a running platform:
 *   BOTSOCIAL_URL=http://127.0.0.1:8787 npx tsx scripts/mcp-smoke.ts
 * Registers a throwaway owner + bot, writes its private key to a temp file, spawns `tsx src/mcp.ts`
 * over stdio exactly like an MCP client (e.g. Grok Bot) would, lists tools and calls list_friends.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { OwnerClient } from "../src/client.js";
import { generateEd25519 } from "../src/crypto.js";

const base = process.env.BOTSOCIAL_URL ?? "http://127.0.0.1:8787";
const sfx = Math.random().toString(36).slice(2, 7);
const { client: owner } = await OwnerClient.register(base, `mcp_${sfx}`, "password", "MCP Smoke");
const kp = generateEd25519();
const bot = await owner.req("POST", "/v1/bots", { handle: `mcp.${sfx}`, integration_type: "mcp", public_key: { alg: "Ed25519", kid: "k1", value: kp.publicKey } });
const keyFile = join(mkdtempSync(join(tmpdir(), "bs-")), "bot.pem");
writeFileSync(keyFile, kp.privateKeyPem, { mode: 0o600 });

const transport = new StdioClientTransport({
  command: "npx", args: ["tsx", "src/mcp.ts"],
  env: { ...process.env as Record<string, string>, BOTSOCIAL_URL: base, BOTSOCIAL_BOT_ID: bot.bot_id, BOTSOCIAL_BOT_TOKEN: bot.bot_token, BOTSOCIAL_KID: "k1", BOTSOCIAL_PRIVATE_KEY_FILE: keyFile },
});
const client = new Client({ name: "mcp-smoke", version: "0" });
await client.connect(transport);
console.log("tools:", (await client.listTools()).tools.map((t) => t.name).join(", "));
const r: any = await client.callTool({ name: "list_friends", arguments: {} });
console.log("list_friends →", r.content[0].text.replace(/\s+/g, " "));
await client.close();
console.log("MCP SMOKE OK");
