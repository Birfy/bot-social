// Signing keys under My Bots only offered "Revoke", with one fixed sentence and no way to add a key.
// `addKey` exists on the platform but the console had no control for it, so an owner who revoked the last
// usable key left the Bot unable to sign anything: every signed call answers 401 invalid_signature
// ("unknown, revoked or expired kid") and nothing in the console brings it back.
//
// The count that matters is keys that can actually sign, not rows whose status reads active: addKey stamps
// `expires_at` on the keys already there without touching their status (src/platform.ts:931-933), so a key
// can be "active" and already unable to sign. The warning is decided when the button is clicked, because the
// list on screen can be minutes old.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { startServer, ownerWithBot, expectApiError } from "./helpers.js";
import { BotClient, OwnerClient } from "../src/client.js";
import { generateEd25519 } from "../src/crypto.js";

const here = dirname(fileURLToPath(import.meta.url));

/** The sentence in the console before this change; a key that still has company keeps exactly this one. */
const OLD_TEXT = "Revoke this key? Requests signed with it will be rejected.";
/** What the owner reads when the click would take away the Bot's last way to sign. */
const lastKeyText = (handle: string, kid: string) => `Revoke key ${kid}? It is the last key @${handle} can sign with, so every signed request is rejected (401 invalid_signature) until you add a key.`;

/** One owner, one Bot registered with k1 (generated here so the test can sign as it). */
async function ownerAndBot(base: string, name: string) {
  const { client: owner, owner_id } = await OwnerClient.register(base, name, "secret-pw", name);
  const k1 = generateEd25519();
  const k2 = generateEd25519();
  const reg = await owner.req("POST", "/v1/bots", { handle: `${name}.bot`, public_key: { alg: "Ed25519", kid: "k1", value: k1.publicKey } });
  return { owner, owner_id, k1, k2, botId: reg.bot_id as string, botToken: reg.bot_token as string, handle: `${name}.bot` };
}

/**
 * The console (public/ui.js) rendered against the test server, without boot(): the page's own PAGES.bots
 * builds the markup, and the click handlers it wires are the ones the test invokes.
 */
function loadBotsPage(base: string, token: string) {
  const src = readFileSync(join(here, "..", "public", "ui.js"), "utf8").replace(/\nboot\(\);\s*$/, "\n;globalThis.__ui = { PAGES };\n");

  const confirms: string[] = [];
  const calls: { method: string; path: string; body: any }[] = [];
  const bySelector = new Map<string, any>();
  const makeEl = (): any => ({
    value: "", innerHTML: "", textContent: "", dataset: {} as Record<string, string>, disabled: false, onclick: null as any,
    className: "", checked: false,
    setAttribute() {}, removeAttribute() {}, remove() {}, appendChild() {}, focus() {}, select() {},
    classList: { add() {}, remove() {} },
    closest: () => makeEl(), querySelector: () => makeEl(), querySelectorAll: () => [] as any[],
  });
  // Elements are looked up lazily, like document.querySelector: an input starts with the value its markup carries,
  // and a re-render (new markup) resets what the page has not touched since.
  let elHtml = "";
  const el = (sel: string) => {
    if (elHtml !== view.innerHTML) { bySelector.clear(); elHtml = view.innerHTML; }
    if (!bySelector.has(sel)) {
      const e = makeEl();
      if (sel.startsWith("#")) {
        const tag = new RegExp(`<input[^>]*id="${sel.slice(1)}"[^>]*>`).exec(String(view.innerHTML))?.[0];
        const value = tag && /value="([^"]*)"/.exec(tag);
        if (value) e.value = value[1];
      }
      bySelector.set(sel, e);
    }
    return bySelector.get(sel)!;
  };
  const view: any = makeEl();
  view.querySelector = () => makeEl();
  // The page wires every generated [data-*] button by reading them back out of the markup it just wrote, so the
  // stub has to do the same: parse the current HTML, not a list the test owns.
  const parsed = new Map<string, { html: string; list: any[] }>();
  view.querySelectorAll = (sel: string) => {
    const hit = parsed.get(sel);
    if (hit && hit.html === view.innerHTML) return hit.list;
    const attr = /^\[data-([a-z-]+)\]$/.exec(sel)?.[1];
    const list: any[] = [];
    if (attr) {
      const key = attr.replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase());
      for (const m of String(view.innerHTML).matchAll(new RegExp(`data-${attr}="([^"]*)"`, "g"))) {
        const b = makeEl(); b.dataset[key] = m[1]; list.push(b);
      }
    }
    parsed.set(sel, { html: view.innerHTML, list });
    return list;
  };

  const ctx: any = {
    localStorage: { getItem: (k: string) => (k === "bs_owner_token" ? token : null), setItem() {}, removeItem() {} },
    window: { addEventListener() {} },
    document: {
      querySelector: (sel: string) => (sel === "#view" ? view : el(sel)),
      querySelectorAll: () => [],
      getElementById: (id: string) => el("#" + id),
      createElement: () => makeEl(),
    },
    location: { hash: "#/bots", origin: "https://example.test", reload() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    fetch: (path: string, init?: any) => {
      calls.push({ method: init?.method ?? "GET", path, body: init?.body ? JSON.parse(init.body) : undefined });
      return fetch(base + path, init);
    },
    setInterval() {}, setTimeout: () => 0, clearTimeout() {}, URLSearchParams, Intl, Date, console,
    confirm: (msg: string) => { confirms.push(msg); return true; },
    prompt: () => null,
  };
  vm.runInNewContext(src, ctx);

  const flush = () => new Promise((r) => setTimeout(r, 0));
  const until = async (fn: () => boolean, what: string) => {
    const t0 = Date.now();
    while (!fn()) { if (Date.now() - t0 > 5000) throw new Error("timed out waiting for " + what); await new Promise((r) => setTimeout(r, 10)); }
  };
  const page: any = {
    confirms, calls,
    el,
    html: () => String(view.innerHTML),
    load: async () => { await ctx.__ui.PAGES.bots(view); return page; },
    /** Click a control the page generated, by its data attribute and value — same markup the browser gets. */
    click: async (attr: string, value: string) => {
      const key = attr.replace(/-([a-z])/g, (_: string, c: string) => c.toUpperCase());
      const b = (view.querySelectorAll(`[data-${attr}]`) as any[]).find((x) => x.dataset[key] === value);
      assert.ok(b, `the Bot card has no [data-${attr}="${value}"] control`);
      await b.onclick();
      await flush();
      return b;
    },
    /** The Bot card's signing-key rows, including the header row the table always has; 0 while the card is absent. */
    keyRows: (botId: string) => {
      const start = page.html().indexOf(`data-wh="${botId}"`);
      if (start < 0) return 0;
      const rest = page.html().slice(start);
      const end = rest.indexOf("</table>");
      return (rest.slice(0, end < 0 ? rest.length : end).match(/<tr/g) || []).length;
    },
    errorIn: (botId: string) => String(el(`#akerr-${botId}`).innerHTML),
    waitFor: until,
  };
  return page;
}

test("the last usable key warns before it is revoked, and revoking it really does brick signatures", async () => {
  const s = await startServer();
  try {
    const { owner, k2, botId, botToken, handle } = await ownerAndBot(s.base, "kira");
    const peer = await ownerWithBot(s.base, "peer");
    // retire_others_in_days: 0 leaves k1 status "active" with expires_at in the past and k2 the only usable key.
    // That value is test-only: the route passes the body straight through today (src/server.ts:166). If addKey
    // ever validates the window, build the expired row another way rather than loosening this fixture.
    const added = await owner.req("POST", `/v1/bots/${botId}/keys`, { kid: "k2", value: k2.publicKey, retire_others_in_days: 0 });
    assert.equal(added.kid, "k2");
    const me = await owner.req("GET", "/v1/me");
    const keys = (me.bots as any[]).find((b: any) => b.id === botId).keys;
    assert.deepEqual(keys.map((k: any) => [k.kid, k.status, Boolean(k.expires_at)]), [["k1", "active", true], ["k2", "active", false]]);

    const bot = new BotClient({ base: s.base, botId, token: botToken, kid: "k2", privateKeyPem: k2.privateKeyPem });
    const page = await loadBotsPage(s.base, owner.token).load();
    assert.equal(page.keyRows(botId), 3, "header plus k1 and k2");

    await page.click("rk", `${botId}|k2`);
    assert.equal(page.confirms.length, 1, "one confirmation, and it is the only prompt");
    assert.notEqual(page.confirms[0], OLD_TEXT, "revoking the last usable key is not the old generic sentence any more");
    assert.equal(page.confirms[0], lastKeyText(handle, "k2"), "the sentence names the key, the Bot and the 401 that follows");
    assert.ok(page.confirms[0].includes("401"), "the consequence is spelled out");
    assert.ok(page.confirms[0].includes("add a key"), "and so is the way out");
    await page.waitFor(() => /<td>revoked<\/td>/.test(page.html()), "the revoked row to render");
    assert.equal(/data-rk="[^"]*\|k2"/.test(page.html()), false, "no Revoke button is left on the revoked key");

    // The same call that worked a moment ago is now refused at the signature, not at the payload: the Bot
    // has no key left that can sign.
    await expectApiError(bot.signed("/v1/relationships", "relationship.request", { target_handle: peer.handle, message: "hi" }), 401, "invalid_signature");
  } finally { await s.stop(); }
});

test("revoking an expired key keeps the old sentence, word for word (no false alarm)", async () => {
  const s = await startServer();
  try {
    const { owner, k2, botId } = await ownerAndBot(s.base, "lena");
    await owner.req("POST", `/v1/bots/${botId}/keys`, { kid: "k2", value: k2.publicKey, retire_others_in_days: 0 });
    const page = await loadBotsPage(s.base, owner.token).load();
    await page.click("rk", `${botId}|k1`);
    assert.deepEqual(page.confirms, [OLD_TEXT], "k1 is expired but not the last usable key, so nothing changes for it");
  } finally { await s.stop(); }
});

test("the console can add a signing key, and a rejected key changes nothing", async () => {
  const s = await startServer();
  try {
    const { owner, botId } = await ownerAndBot(s.base, "milo");
    const page = await loadBotsPage(s.base, owner.token).load();
    assert.ok(page.html().includes("7 days"), "the form says the current keys expire 7 days after adding one");
    const before = page.keyRows(botId);
    assert.equal(before, 2, "header plus k1");

    page.el(`#akid-${botId}`).value = "k2";
    page.el(`#akv-${botId}`).value = "abc";
    await page.click("ak", botId);
    const post = page.calls.filter((c: any) => c.method === "POST" && c.path === `/v1/bots/${botId}/keys`);
    assert.equal(post.length, 1, "the form posts to the Bot's keys route");
    assert.deepEqual(post[0].body, { kid: "k2", value: "abc" }, "kid and value go as typed, with no client-side rewrite");
    assert.match(page.errorIn(botId), /public key is not valid/, "400 invalid_public_key is reported where the form is");
    assert.equal(page.keyRows(botId), before, "a rejected key adds no row");
  } finally { await s.stop(); }
});

test("adding a valid key prefills the next free kid and shows the old keys' expiry", async () => {
  const s = await startServer();
  try {
    const { owner, k2, botId } = await ownerAndBot(s.base, "nora");
    // k1 is expired (retire_others_in_days: 0, as in the first case) and k2 is usable, so ids k1 and k2 are taken.
    await owner.req("POST", `/v1/bots/${botId}/keys`, { kid: "k2", value: k2.publicKey, retire_others_in_days: 0 });
    const page = await loadBotsPage(s.base, owner.token).load();
    assert.equal(page.el(`#akid-${botId}`).value, "k3", "k1 and k2 are taken, so the field proposes k3 and the first submit cannot 409");
    assert.equal(page.keyRows(botId), 3);

    page.el(`#akv-${botId}`).value = generateEd25519().publicKey;
    await page.click("ak", botId);
    await page.waitFor(() => page.keyRows(botId) === 4, "the new key row to render");
    const card = page.html().slice(page.html().indexOf(`data-wh="${botId}"`));
    assert.match(card, /<td><code>k3<\/code><\/td>/, "the added key is listed under its own kid");
    assert.equal((card.match(/until /g) || []).length, 2, "k2 now carries the 7-day expiry line beside k1's past one; the new key carries none");
    assert.equal(page.errorIn(botId), "", "a successful add leaves no error behind");

    const keys = ((await owner.req("GET", "/v1/me")).bots as any[]).find((b: any) => b.id === botId).keys;
    assert.deepEqual(keys.map((k: any) => k.kid), ["k1", "k2", "k3"], "all three keys are listed, oldest first");
    const days = (Date.parse(keys.find((k: any) => k.kid === "k2").expires_at) - Date.now()) / 86400e3;
    assert.ok(days > 6.9 && days < 7.1, `the default retirement window is 7 days, got ${days}`);
    assert.equal(keys.find((k: any) => k.kid === "k3").expires_at, null, "the key just added is not stamped");
  } finally { await s.stop(); }
});

test("a kid that already exists is refused inline and leaves the table alone", async () => {
  const s = await startServer();
  try {
    const { owner, botId } = await ownerAndBot(s.base, "otto");
    const page = await loadBotsPage(s.base, owner.token).load();
    page.el(`#akid-${botId}`).value = "k1";
    page.el(`#akv-${botId}`).value = generateEd25519().publicKey;
    await page.click("ak", botId);
    assert.match(page.errorIn(botId), /already/, "409 kid_exists is reported next to the form");
    assert.equal(page.keyRows(botId), 2, "no row was added");
  } finally { await s.stop(); }
});

test("a key with another usable key beside it keeps the old sentence, and revokes by its own path", async () => {
  const s = await startServer();
  try {
    const { owner, k2, botId } = await ownerAndBot(s.base, "pia");
    await owner.req("POST", `/v1/bots/${botId}/keys`, { kid: "k2", value: k2.publicKey });
    // addKey stamped a 7-day expiry on k1; clear it so both keys are plain usable keys with no expiry line.
    s.platform.db.prepare("UPDATE bot_keys SET expires_at = NULL WHERE bot_id = ?").run(botId);
    const page = await loadBotsPage(s.base, owner.token).load();
    await page.click("rk", `${botId}|k1`);
    assert.deepEqual(page.confirms, [OLD_TEXT], "with k2 still usable there is nothing special to warn about");
    const del = page.calls.filter((c: any) => c.method === "DELETE");
    assert.deepEqual(del, [{ method: "DELETE", path: `/v1/bots/${botId}/keys/k1`, body: undefined }], "one DELETE to the key's own path, no body");
  } finally { await s.stop(); }
});
