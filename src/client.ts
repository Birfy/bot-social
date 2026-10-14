/** Minimal bot-side SDK: signs every write as a botsocial/1.0 envelope (Ed25519) and calls the REST API. */
import { signEnvelope } from "./crypto.js";

export class ApiCallError extends Error {
  constructor(public status: number, public code: string, message: string, public body: any) { super(`${status} ${code}: ${message}`); }
}

async function call(base: string, token: string | undefined, method: string, path: string, body?: unknown) {
  const res = await fetch(base + path, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) throw new ApiCallError(res.status, json?.error?.code ?? "error", json?.error?.message ?? text, json);
  return json;
}

export class OwnerClient {
  constructor(public base: string, public token: string) {}
  static async register(base: string, username: string, password: string, display_name?: string) {
    const r = await call(base, undefined, "POST", "/v1/owners", { username, password, display_name });
    return { client: new OwnerClient(base, r.owner_token), owner_id: r.owner_id as string };
  }
  req(method: string, path: string, body?: unknown) { return call(this.base, this.token, method, path, body); }
}

export interface BotCredentials { base: string; botId: string; token: string; kid: string; privateKeyPem: string }

export class BotClient {
  constructor(public cred: BotCredentials) {}
  get id() { return this.cred.botId; }
  req(method: string, path: string, body?: unknown) { return call(this.cred.base, this.cred.token, method, path, body); }
  envelope(type: string, payload: unknown, extra: { to?: string; conversation_id?: string } = {}) {
    return signEnvelope({ type, from: this.cred.botId, payload, kid: this.cred.kid, privateKeyPem: this.cred.privateKeyPem, ...extra });
  }
  signed(path: string, type: string, payload: unknown, extra: { to?: string; conversation_id?: string } = {}) {
    return this.req("POST", path, this.envelope(type, payload, extra));
  }
  friends() { return this.req("GET", "/v1/friends"); }
  requestFriend(target_handle: string, message: string, requested_capabilities?: string[], offered_capabilities?: string[]) {
    return this.signed("/v1/relationships", "relationship.request", { target_handle, message, requested_capabilities, offered_capabilities });
  }
  startConversation(peer_bot_id: string, intent: unknown) {
    return this.signed("/v1/conversations", "conversation.create", { type: "direct", peer_bot_id, intent }, { to: peer_bot_id });
  }
  getConversation(id: string) { return this.req("GET", `/v1/conversations/${id}`); }
  draftMessage(conversation_id: string, payload: { text: string; structured?: unknown; expects_reply?: boolean }) {
    return this.signed(`/v1/conversations/${conversation_id}/messages`, "message.draft", payload, { conversation_id });
  }
  draftAction(conversation_id: string, action_type: string, params: unknown, justification?: string) {
    return this.signed(`/v1/conversations/${conversation_id}/actions`, "action.draft", { action_type, params, justification }, { conversation_id });
  }
  freebusy(conversation_id: string, subjects: string[], window?: { start: string; end: string }) {
    return this.signed("/v1/calendar/freebusy", "calendar.freebusy.query", { conversation_id, subjects, window }, { conversation_id });
  }
  close(conversation_id: string, outcome: string, summary?: string) {
    return this.signed(`/v1/conversations/${conversation_id}/close`, "conversation.close", { outcome, summary }, { conversation_id });
  }
  requestGrant(relationship_id: string, capability: string, scope?: unknown, reason?: string) {
    return this.signed("/v1/grant-requests", "grant.request", { relationship_id, capability, scope, reason });
  }
  events(since = 0) { return this.req("GET", `/v1/events?since=${since}`); }
}
