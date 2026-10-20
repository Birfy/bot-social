import Fastify, { FastifyInstance, FastifyRequest } from "fastify";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ApiError } from "./errors.js";
import { Platform, Principal } from "./platform.js";
import { ensureBotctl } from "./botctl-build.js";
import { marked } from "marked";
import { registerOwnerMcp } from "./owner-mcp.js";

const here = dirname(fileURLToPath(import.meta.url));
const UI_HTML = () => readFileSync(join(here, "..", "public", "index.html"), "utf8");

export function buildServer(platform: Platform, opts: { logger?: boolean; fixedBaseUrl?: boolean } = {}): FastifyInstance {
  const app = Fastify({ logger: opts.logger ?? false, bodyLimit: 256 * 1024, trustProxy: true });
  // Without PUBLIC_BASE_URL, derive links (invites, /botctl, /guide) from the Host the client used.
  if (!opts.fixedBaseUrl) app.addHook("onRequest", async (req) => { if (req.headers.host) platform.publicBaseUrl = `${req.protocol}://${req.headers.host}`; });
  const page = (name: string) => readFileSync(join(here, "..", "public", name), "utf8");

  app.setErrorHandler((err: any, _req, reply) => {
    if (err instanceof ApiError) return reply.status(err.status).send({ error: { code: err.code, message: err.message, ...err.extra } });
    if (err.validation || err.statusCode === 400 || err.code === "FST_ERR_CTP_INVALID_JSON_BODY") return reply.status(400).send({ error: { code: "invalid_request", message: err.message } });
    if (err.statusCode === 413) return reply.status(413).send({ error: { code: "payload_too_large", message: err.message } });
    app.log.error(err);
    return reply.status(500).send({ error: { code: "internal_error", message: "internal error" } });
  });

  const auth = (req: FastifyRequest): Principal => {
    const h = req.headers.authorization;
    const p = platform.authenticate(h?.startsWith("Bearer ") ? h.slice(7) : undefined);
    if (p.kind === "owner" && p.scope === "connector") throw new ApiError(403, "connector_token_rest_forbidden", "connector tokens work at /mcp and the FlyBot REST routes only; use the MCP tools at /mcp or log in for this route");
    return p;
  };
  // Connector token (FlyBot / MCP) or owner login. Used for per-bot access management and webhooks.
  const ownerAny = (req: FastifyRequest) => {
    const h = req.headers.authorization;
    const p = platform.authenticate(h?.startsWith("Bearer ") ? h.slice(7) : undefined);
    if (p.kind !== "owner") throw new ApiError(403, "owner_only", "owner or connector token required");
    return p;
  };
  const P = (req: FastifyRequest) => req.params as Record<string, string>;
  const B = (req: FastifyRequest) => (req.body ?? {}) as any;
  const Q = (req: FastifyRequest) => req.query as Record<string, string>;

  // ---- public
  app.get("/", async (_req, reply) => reply.redirect("/ui"));
  app.get("/friends", async (_req, reply) => reply.redirect("/ui#/friends"));
  app.get("/i/:code", async (_req, reply) => reply.type("text/html; charset=utf-8").send(page("invite.html")));
  app.get("/botctl", async (_req, reply) => {
    const js = (await ensureBotctl()).replace("__BOTSOCIAL_DEFAULT_URL__", platform.publicBaseUrl);
    return reply.type("text/javascript; charset=utf-8").header("content-disposition", 'attachment; filename="botctl"').send(js);
  });
  const guideMd = () => readFileSync(join(here, "..", "docs", "AGENT_GUIDE.md"), "utf8").replaceAll("{{BASE_URL}}", platform.publicBaseUrl);
  app.get("/guide.md", async (_req, reply) => reply.type("text/markdown; charset=utf-8").send(guideMd()));
  app.get("/guide", async (_req, reply) => reply.type("text/html; charset=utf-8").send(page("guide.html").replace("<!--GUIDE-->", await marked.parse(guideMd()))));
  app.get("/ui", async (_req, reply) => reply.type("text/html; charset=utf-8").send(UI_HTML()));
  app.get("/ui.js", async (_req, reply) => reply.type("text/javascript; charset=utf-8").header("cache-control", "no-cache").send(page("ui.js")));
  registerOwnerMcp(app, platform);
  app.get("/connect", async (_req, reply) => reply.type("text/html; charset=utf-8").header("cache-control", "no-cache").send(page("connect.html")));
  const onboardHits = new Map<string, number[]>();
  app.post("/v1/onboard/flybot", async (req, reply) => {
    const now = Date.now(), ip = req.ip, hits = (onboardHits.get(ip) ?? []).filter((t) => now - t < 3600e3);
    if (hits.length >= 10) return reply.status(429).send({ error: { code: "rate_limited", message: "too many sign-ups from this address; try again later" } });
    onboardHits.set(ip, [...hits, now]);
    return reply.status(201).send(platform.onboardFlybot(B(req)));
  });
  app.get("/v1/homes/:id/members", async (req) => platform.listHomeMembers(auth(req), P(req).id));
  app.post("/v1/homes/:id/members", async (req, reply) => reply.status(201).send(platform.addHomeMember(auth(req), P(req).id, B(req))));
  app.delete("/v1/homes/:id/members/:member", async (req) => platform.removeHomeMember(auth(req), P(req).id, P(req).member));
  app.post("/v1/attachments", { bodyLimit: Math.ceil(platform.attachmentLimits.maxBytes / 3) * 4 + 64 * 1024 }, async (req, reply) => reply.status(201).send(platform.uploadAttachment(auth(req), B(req))));
  app.get("/v1/attachments/:id", async (req) => platform.getAttachment(auth(req), { attachment_id: P(req).id, bot_id: Q(req)?.bot_id }));
  app.get("/v1/homes/:id/remote-bots", async (req) => platform.remoteBots(ownerAny(req), P(req).id));
  app.get("/v1/remote-bots", async (req) => platform.listRemoteBots(ownerAny(req), Q(req).home || Q(req).home_id));
  app.get("/v1/bots/:id/grants", async (req) => platform.listBotGrants(ownerAny(req), P(req).id));
  app.post("/v1/bots/:id/grants", async (req, reply) => reply.status(201).send(platform.grantBotToFriend(ownerAny(req), P(req).id, B(req).friend_owner_id)));
  app.delete("/v1/bots/:id/grants/:grantId", async (req) => platform.revokeBotGrant(ownerAny(req), P(req).grantId, P(req).id));
  // Recipient side: the grantee removes a grant given to one of their bots (the granting owner's list_bot_grants drops it).
  app.delete("/v1/remote-bots/:grantId", async (req) => platform.declineBotGrant(ownerAny(req), P(req).grantId, Q(req).bot_id || undefined));
  app.post("/v1/homes/:id/send", async (req, reply) => reply.status(202).send(platform.sendAsMember(auth(req), B(req))));
  app.post("/v1/onboard", async (req, reply) => {
    const now = Date.now(), ip = req.ip, hits = (onboardHits.get(ip) ?? []).filter((t) => now - t < 3600e3);
    if (hits.length >= 10) return reply.status(429).send({ error: { code: "rate_limited", message: "too many sign-ups from this address; try again later" } });
    onboardHits.set(ip, [...hits, now]);
    return reply.status(201).send(platform.onboard(B(req)));
  });
  const setupMd = () => readFileSync(join(here, "..", "docs", "SETUP.md"), "utf8").replaceAll("{{BASE_URL}}", platform.publicBaseUrl);
  app.get("/setup", async (_req, reply) => reply.type("text/markdown; charset=utf-8").header("cache-control", "no-cache").send(setupMd()));
  app.get("/setup.md", async (_req, reply) => reply.type("text/markdown; charset=utf-8").send(setupMd()));
  app.post("/v1/connector-tokens", async (req, reply) => reply.status(201).send(platform.createConnectorToken(auth(req), B(req))));
  app.get("/v1/connector-tokens", async (req) => ({ tokens: platform.listConnectorTokens(auth(req)) }));
  app.delete("/v1/connector-tokens/:id", async (req) => platform.revokeConnectorToken(auth(req), P(req).id));
  // Webhook via shell (so a secret header from an env var never passes through the model). Accepts connector or login owner tokens.
  const myBotId = (p: Principal, id?: string) => { const bots = platform.listBots(p); const b = id ? bots.find((x: any) => x.id === id || "@" + x.handle === id || x.handle === id) : bots[0]; if (!b) throw new ApiError(404, "bot_not_found"); return b.id as string; };
  app.put("/v1/connector/webhook", async (req) => { const p = ownerAny(req); const b = B(req); return platform.setWebhook(p, myBotId(p, b.bot_id), { url: b.url, headers: b.headers }); });
  app.get("/v1/connector/webhook", async (req) => { const p = ownerAny(req); return platform.getWebhook(p, myBotId(p, Q(req).bot_id)); });
  app.post("/v1/connector/webhook/test", async (req) => { const p = ownerAny(req); return platform.testWebhook(p, myBotId(p, B(req).bot_id)); });
  app.delete("/v1/connector/webhook", async (req) => { const p = ownerAny(req); return platform.clearWebhook(p, myBotId(p, Q(req).bot_id)); });
  app.get("/healthz", async () => ({ ok: true }));
  app.get("/v1/platform", async () => platform.platformInfo());

  // ---- owners
  app.post("/v1/owners", async (req, reply) => reply.status(201).send(platform.registerOwner(B(req))));
  app.post("/v1/auth/login", async (req) => platform.login(B(req)));
  app.get("/v1/me", async (req) => platform.me(auth(req)));
  app.patch("/v1/me", async (req) => platform.updateSettings(auth(req), B(req)));

  // ---- bots & keys
  app.post("/v1/bots", async (req, reply) => reply.status(201).send(platform.registerBot(auth(req), B(req))));
  app.get("/v1/bots", async (req) => ({ bots: platform.listBots(auth(req)) }));
  app.get("/v1/bots/:id/profile", async (req) => platform.profile(auth(req), P(req).id));
  // Owner (login or connector token) sets display_name and/or avatar/color; avatar/color null clears.
  app.patch("/v1/bots/:id/profile", async (req) => platform.updateBotProfile(ownerAny(req), P(req).id, B(req)));
  app.post("/v1/bots/:id/keys", async (req, reply) => reply.status(201).send(platform.addKey(auth(req), P(req).id, B(req))));
  app.delete("/v1/bots/:id/keys/:kid", async (req) => platform.revokeKey(auth(req), P(req).id, P(req).kid));
  app.get("/v1/bots/:id/webhook", async (req) => platform.getWebhook(auth(req), P(req).id));
  app.put("/v1/bots/:id/webhook", async (req) => platform.setWebhook(auth(req), P(req).id, B(req)));
  app.delete("/v1/bots/:id/webhook", async (req) => platform.clearWebhook(auth(req), P(req).id));
  app.post("/v1/bots/:id/webhook/test", async (req) => platform.testWebhook(auth(req), P(req).id));
  app.get("/v1/bots/:id/webhook/deliveries", async (req) => platform.webhookDeliveries(auth(req), P(req).id, Number(Q(req).limit ?? 30)));
  app.post("/v1/bots/:id/resume", async (req) => platform.resumeBot(auth(req), P(req).id));
  app.post("/v1/bots/:id/token", async (req) => platform.rotateBotToken(auth(req), P(req).id));
  app.post("/v1/emergency-stop", async (req) => platform.emergencyStop(auth(req), B(req)));

  // ---- relationships & grants
  app.post("/v1/relationships", async (req, reply) => reply.status(201).send(platform.requestRelationship(auth(req), B(req))));
  app.get("/v1/relationships", async (req) => ({ relationships: platform.listRelationships(auth(req)) }));
  app.put("/v1/relationships/:id/settings", async (req) => platform.updateRelationshipSettings(auth(req), P(req).id, B(req)));
  app.post("/v1/invites", async (req, reply) => reply.status(201).send(platform.createInvite(auth(req), B(req))));
  app.get("/v1/invites", async (req) => ({ invites: platform.listInvites(auth(req)) }));
  app.get("/v1/invites/:code", async (req) => platform.inviteInfo(P(req).code));
  app.delete("/v1/invites/:code", async (req) => platform.revokeInvite(auth(req), P(req).code));
  app.post("/v1/invites/:code/join", async (req, reply) => reply.status(201).send(platform.joinInvite(auth(req), P(req).code, B(req))));
  app.get("/v1/friends-overview", async (req) => platform.friendsOverview(auth(req), Q(req).bot_id || undefined));
  app.get("/v1/friends", async (req) => ({ friends: platform.listFriends(auth(req)) }));
  app.post("/v1/relationships/:id/consent", async (req) => platform.consent(auth(req), P(req).id, B(req)));
  app.delete("/v1/relationships/:id", async (req) => platform.removeRelationship(auth(req), P(req).id));
  app.post("/v1/blocks", async (req) => platform.block(auth(req), B(req)));
  app.post("/v1/relationships/:id/grants", async (req, reply) => reply.status(201).send(platform.addGrant(auth(req), P(req).id, B(req))));
  app.post("/v1/grant-requests", async (req, reply) => reply.status(202).send(platform.requestGrant(auth(req), B(req))));
  app.delete("/v1/grants/:id", async (req) => platform.revokeGrant(auth(req), P(req).id));

  // ---- conversations
  app.post("/v1/conversations", async (req, reply) => reply.status(201).send(platform.createConversation(auth(req), B(req))));
  app.get("/v1/conversations", async (req) => ({ conversations: platform.listConversations(auth(req)) }));
  app.get("/v1/conversations/:id", async (req) => platform.getConversation(auth(req), P(req).id));
  app.post("/v1/conversations/:id/messages", async (req, reply) => reply.status(202).send(platform.draftMessage(auth(req), P(req).id, B(req))));
  app.post("/v1/conversations/:id/actions", async (req, reply) => reply.status(202).send(platform.draftAction(auth(req), P(req).id, B(req))));
  app.post("/v1/conversations/:id/close", async (req) => platform.closeConversation(auth(req), P(req).id, B(req)));
  app.post("/v1/conversations/:id/extend", async (req) => platform.extendConversation(auth(req), P(req).id, B(req)));

  // ---- approvals
  app.get("/v1/approvals", async (req) => ({ approvals: platform.listApprovals(auth(req), Q(req).status ?? "pending") }));
  app.post("/v1/approvals/:id/decision", async (req) => platform.decideApproval(auth(req), P(req).id, B(req)));

  // ---- calendar
  app.post("/v1/calendar/freebusy", async (req) => platform.freebusy(auth(req), B(req)));
  app.post("/v1/calendar/entries", async (req, reply) => reply.status(201).send(platform.addCalendarEntry(auth(req), B(req))));
  app.get("/v1/calendar/entries", async (req) => ({ entries: platform.listCalendar(auth(req)) }));

  // ---- events & audit
  app.get("/v1/events", async (req) => platform.listEvents(auth(req), Number(Q(req).since ?? 0), Math.min(Number(Q(req).limit ?? 100), 500)));
  app.get("/v1/audit-events", async (req) => platform.auditEvents(auth(req), { subject: Q(req).subject, limit: Q(req).limit ? Number(Q(req).limit) : undefined }));

  // ---- face-to-face rooms (FlyBot #83). Accepts owner login tokens, connector tokens
  // (the same Bearer FlyBot already stores from /v1/onboard/flybot), and bot tokens
  // (a bot token may only bring / act as itself).
  const faceAuth = (req: FastifyRequest): Principal => {
    const h = req.headers.authorization;
    return platform.authenticate(h?.startsWith("Bearer ") ? h.slice(7) : undefined);
  };
  const faceIp = (req: FastifyRequest) => req.ip;
  app.post("/v1/face-rooms/join", async (req, reply) => reply.status(200).send(platform.joinFaceRoom(faceAuth(req), B(req), { ip: faceIp(req) })));
  // Presence ("thinking"): owner login, connector token or the Bot's own token (a Bot token acts only as itself).
  app.put("/v1/presence", async (req) => platform.setPresence(faceAuth(req), B(req)));
  app.get("/v1/presence", async (req) => platform.listPresence(faceAuth(req), { bot_id: Q(req).bot_id || undefined, room_id: Q(req).room_id || undefined }));
  app.get("/v1/face-rooms", async (req) => platform.listFaceRooms(faceAuth(req)));
  app.get("/v1/face-rooms/:id", async (req) => platform.getFaceRoom(faceAuth(req), P(req).id, { after: Q(req).after ? Number(Q(req).after) : undefined, as_bot: Q(req).as ?? Q(req).bot ?? Q(req).as_bot }));
  app.post("/v1/face-rooms/:id/start", async (req) => platform.startFaceRoom(faceAuth(req), P(req).id));
  app.post("/v1/face-rooms/:id/leave", async (req) => platform.leaveFaceRoom(faceAuth(req), P(req).id, B(req)));
  // Room lead (FlyBot #476): only the room creator's owner token; roles: your own Bots' role labels.
  app.post("/v1/face-rooms/:id/lead", async (req) => platform.setFaceRoomLead(faceAuth(req), P(req).id, B(req)));
  app.put("/v1/face-rooms/:id/roles", async (req) => platform.setFaceRoomRoles(faceAuth(req), P(req).id, B(req)));
  app.post("/v1/face-rooms/:id/messages", async (req, reply) => reply.status(202).send(platform.draftFaceRoomMessage(faceAuth(req), P(req).id, B(req))));

  return app;
}
