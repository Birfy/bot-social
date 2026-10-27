import assert from "node:assert/strict";
import { test } from "node:test";
import { OwnerClient } from "../src/client.js";
import { generateEd25519 } from "../src/crypto.js";
import { expectApiError, startServer } from "./helpers.js";
import { mcp, post } from "./flybot_helpers.js";

const publicKey = () => ({ alg: "Ed25519", kid: "k1", value: generateEd25519().publicKey });
const CAPS = { auto_accept: true, offered_capabilities: ["chat.public"], requested_capabilities: ["chat.public"] };

test("a Bot handle is stored lowercased and every case variant is handle_taken", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const { client: owner } = await OwnerClient.register(s.base, "zed", "secret-pw", "Zed");
  const first = await owner.req("POST", "/v1/bots", { handle: "Zed.Bot", public_key: publicKey() });
  assert.equal(first.handle, "@zed.bot", "the returned handle is the lowercased one");

  await expectApiError(owner.req("POST", "/v1/bots", { handle: "zed.bot", public_key: publicKey() }), 409, "handle_taken");
  await expectApiError(owner.req("POST", "/v1/bots", { handle: "ZED.BOT", public_key: publicKey() }), 409, "handle_taken");

  // uniqueness is global, not per owner
  const { client: other } = await OwnerClient.register(s.base, "zed2", "secret-pw", "Zed Two");
  await expectApiError(other.req("POST", "/v1/bots", { handle: "zEd.bOt", public_key: publicKey() }), 409, "handle_taken");

  const { bots } = await owner.req("GET", "/v1/bots");
  assert.equal(bots.length, 1, "no case-variant duplicate rows");
  assert.equal(bots[0].handle, "zed.bot");

  assert.equal(s.platform.botByHandle("@ZED.BOT").id, first.bot_id);
  assert.equal(s.platform.botByHandle("@zed.bot").id, first.bot_id);
  assert.equal(s.platform.botByHandle("zed.bot").id, first.bot_id);
});

test("the /v1/onboard path normalises too and refuses a second case variant", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const home = (await post(s.base, "/v1/onboard/flybot", { display_name: "Fly", bot_handle: "Home.Bot" })).body;
  assert.equal(home.home.handle, "@home.bot");
  const again = await post(s.base, "/v1/onboard/flybot", { display_name: "Fly Two", bot_handle: "HOME.BOT" });
  assert.equal(again.status, 409);
  assert.equal(again.body.error.code, "handle_taken");
});

test("home members are normalised, re-added by any case, and removed by any case", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const fly = (await post(s.base, "/v1/onboard/flybot", { display_name: "Wes", bot_handle: "Wes.Home" })).body;
  const p = { kind: "owner" as const, ownerId: fly.owner_id };
  const h1 = s.platform.addHomeMember(p, fly.home.bot_id, { name: "WriTer" });
  const h2 = s.platform.addHomeMember(p, "@WES.HOME", { name: "WRITER" });
  assert.equal(h1.handle, "@writer.wes.home");
  assert.equal(h2.bot_id, h1.bot_id, "re-adding in another case returns the same Bot");
  assert.equal(h2.reactivated, true);
  assert.equal(s.platform.homeMembers(fly.home.bot_id).length, 1, "no duplicate member");
  assert.equal(s.platform.botByHandle("@WRITER.WES.HOME").id, h1.bot_id);
  const gone = s.platform.removeHomeMember(p, "@WES.HOME", "@WRITER.WES.HOME");
  assert.equal(gone.bot_id, h1.bot_id);
  assert.equal(gone.status, "revoked");
});

test("send_as_member resolves a recipient handle in any case", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const a = (await post(s.base, "/v1/onboard/flybot", { display_name: "Danyang" })).body;
  const b = (await post(s.base, "/v1/onboard/flybot", { display_name: "Bob" })).body;
  const A = (name: string, args: unknown = {}) => mcp(s.base, a.connector.token, name, args);
  const B = (name: string, args: unknown = {}) => mcp(s.base, b.connector.token, name, args);
  const chief = await A("add_home_member", { home: a.home.bot_id, name: "chief" });
  const coder = await B("add_home_member", { home: b.home.bot_id, name: "coder" });
  const inv = await A("create_invite", { bot_id: chief.bot_id, ...CAPS });
  await B("join_invite", { code: inv.code ?? inv.invite?.code, from_bot_id: coder.bot_id });
  const back = await B("create_invite", { bot_id: coder.bot_id, ...CAPS });
  await A("join_invite", { code: back.code, from_bot_id: chief.bot_id });

  const sent = await A("send_as_member", { from_bot_id: chief.bot_id, to: String(coder.handle).toUpperCase(), text: "mixed-case recipient" });
  assert.equal(sent.error, undefined, `the recipient must resolve: ${JSON.stringify(sent.error)}`);
  assert.ok(sent.conversation_id, "a conversation is opened for the resolved recipient");
});
