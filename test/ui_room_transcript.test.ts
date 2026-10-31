// P1 (#213): `GET /v1/face-rooms/:id` already returns the room's events (`src/platform.ts:3359`, each one
// flattened by `faceEventPublic`, `:3074`), including every `room.message` whose text sits in
// `untrusted_content.text` (`:4120`). The console threw them away: `roomDetailModel` (`public/ui.js:462`) kept
// only `members`, and the detail page rendered the member list alone (`:482`-`:485`), so an owner could not see
// what their own Bot said in a room.
//
// These tests are behavioural, not layout: they stub the two endpoints the page really calls, render it with the
// response shape the server really returns, and then read the message lines the owner would see.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "..", "public", "ui.js"), "utf8")
  .replace(/\nboot\(\);\s*$/, "\n;globalThis.__ui = { PAGES, setMe: (x) => { me = x; } };\n");

const member = (bot_id: string, handle: string, display_name: string) => ({
  bot_id, handle, display_name, owner_name: "Owner", label: `${display_name}'s Bot`, role: "member",
});

/** The shape `platform.faceRoomView` returns (`src/platform.ts:3352-3362`), members and events included. */
const roomView = (events: any[]) => ({
  room_id: "room_1", status: "open", expires_at: "2026-10-30T10:00:00.000Z", started_at: "2026-10-30T09:00:00.000Z", closed_at: null,
  created_by: { owner_name: "Alice" }, created_by_me: true,
  lead_bot_handle: "@alice.bot", effective_lead_bot_handle: "@alice.bot",
  members: [member("bot_alice", "@alice.bot", "Alice Bot"), member("bot_bob", "@bob.bot", "Bob Bot")],
  event_cursor: events.length ? events[events.length - 1].event_cursor : 0,
  events,
});

// `member.joined` carries the sentence the server wrote in `data.text`; `room.message` carries the peer's text in
// `untrusted_content.text` and the sender snapshot in `from` (`src/platform.ts:3183`, `:4120`).
const joined = { event_id: "fev_1", event_cursor: 1, type: "member.joined", created_at: "2026-10-30T09:00:30.000Z", actor_bot: "bot_alice", text: "@alice.bot joined the room", member: member("bot_alice", "@alice.bot", "Alice Bot"), trust: "platform" };
const saidAlice = { event_id: "fev_2", event_cursor: 2, type: "room.message", created_at: "2026-10-30T09:01:00.000Z", actor_bot: "bot_alice", from: member("bot_alice", "@alice.bot", "Alice Bot"), trust: "peer_untrusted", untrusted_content: { text: "Hello Bob, shall we plan the demo?" }, security: { injection_suspected: false } };
const saidBob = { event_id: "fev_3", event_cursor: 3, type: "room.message", created_at: "2026-10-30T09:02:00.000Z", actor_bot: "bot_bob", from: member("bot_bob", "@bob.bot", "Bob Bot"), trust: "peer_untrusted", untrusted_content: { text: "Yes <img src=x onerror=alert(1)>" }, security: { injection_suspected: false } };

const el = (extra: any = {}) => ({ innerHTML: "", textContent: "", onclick: null, classList: { add() {}, remove() {} }, querySelector: () => null, querySelectorAll: () => [], ...extra });

/** The console in a sandbox with the two rooms endpoints stubbed, so the detail page renders without a server. */
function renderRoom(events: any[]) {
  const state = { html: "" };
  const view = el();
  Object.defineProperty(view, "innerHTML", { get: () => state.html, set: (x: string) => { state.html = x; } });
  const ctx: any = {
    localStorage: { getItem: () => "tkn", setItem() {}, removeItem() {} },
    window: { addEventListener() {}, open() {} },
    document: {
      querySelector: (s: string) => {
        if (s === "#toast") return el();
        if (s === "#view") return view;
        if (s === "#root") return el();
        if (s === "#lo" || s === "#lo2") return el();
        if (s === "#room-leave") return /id="room-leave"/.test(state.html) ? el() : null;
        return null;
      },
      querySelectorAll: () => [], getElementById: () => null,
      createElement: () => el(),
    },
    location: { hash: "#/rooms/room_1", origin: "https://example.test", reload() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    fetch: async (path: string, init?: any) => {
      if ((init?.method || "GET") !== "GET") throw new Error(`unexpected ${init?.method} ${path}`);
      // `listFaceRooms` returns `my_bots` as `{handle, display_name, ...lookOf}` only — it carries no `bot_id`
      // (`src/platform.ts`, the `SELECT m.handle, m.display_name, b.avatar…` inside `listFaceRooms`), so the page
      // must not read one. Keeping the real shape here is what caught the bug in the first place.
      if (path === "/v1/face-rooms") return { ok: true, status: 200, json: async () => ({ rooms: [{ room_id: "room_1", status: "open", member_count: 2, my_bots: [{ handle: "@alice.bot", display_name: "Alice Bot", avatar: null, avatar_kind: null, color: null, avatar_updated_at: null }], expires_at: "2026-10-30T10:00:00.000Z" }] }) };
      if (path === "/v1/face-rooms/room_1") return { ok: true, status: 200, json: async () => roomView(events) };
      throw new Error(`unexpected request ${path}`);
    },
    setInterval() {}, setTimeout, clearTimeout, URLSearchParams, Intl, Date, console, confirm: () => true, prompt: () => null,
  };
  vm.runInNewContext(src, ctx);
  ctx.__ui.setMe({ owner_id: "own_1", display_name: "Test Owner", timezone: "UTC", bots: [{ id: "bot_alice", handle: "alice.bot" }] });
  return async () => {
    await ctx.__ui.PAGES.rooms(view);
    return {
      html: () => state.html,
      // The transcript is the last section of the page; everything after its anchor is what the owner reads.
      transcript: () => state.html.split('id="room-transcript"')[1] || "",
    };
  };
}

test("the room detail page shows what was said in the room, oldest first", async () => {
  const page = await renderRoom([joined, saidAlice, saidBob])();
  const t = page.transcript();
  assert.ok(t.includes("Hello Bob, shall we plan the demo?"), "the room detail page renders what the Bots said in the room");
  assert.ok(t.includes("Yes &lt;img src=x onerror=alert(1)&gt;"), "both messages are on the page, in the room's own order");
  assert.ok(t.indexOf("Hello Bob, shall we plan the demo?") < t.indexOf("Yes "), "the API returns events oldest first and the page keeps that order");
  assert.ok(t.includes("@alice.bot") && t.includes("@bob.bot"), "each message names the Bot that said it");
  assert.equal((t.match(/\d{1,2}\/\d{1,2}, \d{2}:\d{2}/g) || []).length >= 2, true, "each message carries its time");
});

test("room lifecycle events read as one system line, not as something a Bot said", async () => {
  const page = await renderRoom([joined, saidAlice])();
  const t = page.transcript();
  assert.ok(t.includes("@alice.bot joined the room"), "the server's own sentence for member.joined is shown");
  assert.equal((t.match(/class="bub"/g) || []).length, 1, "only the message is a bubble: the joined line is not something a Bot said");
  assert.equal((t.match(/class="sys"/g) || []).length, 1, "the lifecycle event is one system line");
});

test("a message text from another owner's Bot is escaped, never markup", async () => {
  const html = (await renderRoom([saidBob])()).html();
  assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;"), "the peer's text is shown as text");
  assert.equal(html.includes("<img"), false, "and it never becomes an element in the owner's console");
});

test("my own Bot's line is mine, the other owner's is the peer's", async () => {
  // `my_bots` on the rooms list carries no `bot_id`, so ownership has to come from the console's own Bot list
  // (`/v1/me`), exactly as `PAGES.chat` decides it. Reading `bot_id` off `my_bots` leaves the set empty and every
  // line, including the owner's own Bot's, renders as the peer's bubble.
  const t = (await renderRoom([saidAlice, saidBob])()).transcript();
  const me = (t.match(/<div class="b [^"]*"><div class="bub">Hello Bob/) || [""])[0];
  const peer = (t.match(/<div class="b [^"]*"><div class="bub">Yes/) || [""])[0];
  assert.match(me, /class="b me"/, `my own Bot's line is the owner's own bubble, not the peer's: got "${me}"`);
  assert.match(peer, /class="b peer"/, `the other owner's Bot stays the peer bubble: got "${peer}"`);
});

test("a room where nobody has spoken says so instead of showing a blank page", async () => {
  const page = await renderRoom([])();
  assert.ok(page.transcript().includes("Nothing said yet"), "an empty transcript has its own line");
  assert.equal((page.transcript().match(/class="bub"/g) || []).length, 0, "and no invented messages");
});

test("a message from a Bot that is no longer a member still names it", async () => {
  const fromGhost = { ...saidBob, actor_bot: "bot_ghost", from: undefined, untrusted_content: { text: "I left, but I said this first" } };
  const t = (await renderRoom([fromGhost])()).transcript();
  assert.ok(t.includes("bot_ghost"), "the handle map misses a Bot that left, so the page falls back to the bot id");
  assert.ok(t.includes("I left, but I said this first"), "and the message itself is still shown");
});
