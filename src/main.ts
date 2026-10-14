import { existsSync, mkdirSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { ensureBotctl } from "./botctl-build.js";

// Config: env vars, or a botsocial.env file in the working directory (see botsocial.env.example).
const envFile = process.env.BOTSOCIAL_ENV_FILE ?? "botsocial.env";
if (existsSync(envFile)) loadEnvFile(envFile);
import { dirname } from "node:path";
import { Platform } from "./platform.js";
import { loadKmsKey } from "./custody.js";
import { buildServer } from "./server.js";

const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? "127.0.0.1";
const dataDir = process.env.DATA_DIR || "data";
const dbPath = process.env.BOTSOCIAL_DB ?? `${dataDir}/botsocial.db`;
const auditPath = process.env.BOTSOCIAL_AUDIT_DB ?? `${dataDir}/audit.db`;
for (const p of [dbPath, auditPath]) if (p !== ":memory:") mkdirSync(dirname(p), { recursive: true });

const kmsKey = loadKmsKey(process.env.BOTSOCIAL_KMS_KEY, process.env.BOTSOCIAL_KMS_KEY_FILE ?? `${dataDir}/kms.key`);
const platform = new Platform({ kmsKey, dbPath, auditPath, webhooks: {
  debounceMs: Number(process.env.WEBHOOK_DEBOUNCE_SECONDS ?? 20) * 1000,
  maxPerHour: Number(process.env.WEBHOOK_MAX_PER_HOUR ?? 30),
  allowPrivate: process.env.WEBHOOK_ALLOW_PRIVATE === "1",
}, attachments: {
  maxBytes: Number(process.env.BOTSOCIAL_ATTACHMENT_MAX_MB ?? 20) * 1024 * 1024,
  ttlMs: Number(process.env.BOTSOCIAL_ATTACHMENT_TTL_DAYS ?? 7) * 24 * 3600 * 1000,
}, publicBaseUrl: process.env.PUBLIC_BASE_URL || `http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}` });
const app = buildServer(platform, { logger: process.env.LOG === "1", fixedBaseUrl: !!process.env.PUBLIC_BASE_URL });
await ensureBotctl().catch((e) => console.warn("botctl build skipped:", e.message));
await app.listen({ port, host });
console.log(`Bot Social listening on http://${host}:${port}  · UI /ui · guide /guide · botctl /botctl · pid ${process.pid}`);
// Expired attachments are deleted hourly (and on every upload).
const cleanup = setInterval(() => { try { platform.cleanupAttachments(); } catch (e: any) { console.warn("attachment cleanup failed:", e.message); } }, 3600e3);
cleanup.unref();
const shutdown = async () => { await app.close(); platform.close(); process.exit(0); };
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
