/**
 * An approval card draws an editable line and two accept buttons: the primary "✓ Approve" (`data-dec="approved"`)
 * and "Approve with edits". Only the second one used to hang the box's text on the decision, and the server applies
 * an edit only for `decision: "approved_with_edits"` (`deliverMessage` -> `editedPayloadOf(body)`). So an owner who
 * corrected the line and pressed the primary button sent `{decision:"approved"}`: the draft went out, the peer read
 * the text the owner had just changed, the envelope said `edited_by_owner: false`, and there is no unsend.
 *
 * The console must speak the server's one edit door: a changed box on the plain Approve becomes
 * `approved_with_edits` with `edited_payload: { text }`; an untouched box keeps exactly `{decision:"approved"}`; an
 * empty box is refused before any request. "Approve with edits" and "Reject" keep their behaviour.
 *
 * The harness is the console's own: the real `public/ui.js` in a vm sandbox, the real API over real `fetch`, and a
 * fake DOM holding exactly one card. Nothing is hooked in `src/`.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { bulkAuth, friends, startServer } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "..", "public", "ui.js"), "utf8")
  .replace(/\nboot\(\);\s*$/, "\n;globalThis.__ui = { bindApprovals, setMe: (x) => { me = x; } };\n");

const el = (over: any = {}) => ({
  innerHTML: "", textContent: "", value: "", disabled: false, onclick: null, dataset: {},
  style: {}, classList: { add() {}, remove() {} }, setAttribute() {}, removeAttribute() {},
  appendChild() {}, querySelector: () => null, querySelectorAll: () => [], ...over,
});

/** ui.js in a vm sandbox whose fetch is the real API; only the approval-card subtree is faked. */
function consoleFor(base: string, token: string, me: any, promptAnswer: string | null = null) {
  const calls: any[] = [];
  const toastEl = el();
  const ctx: any = {
    localStorage: { getItem: () => token, setItem() {}, removeItem() {} },
    window: { addEventListener() {} },
    // A page other than "" keeps refreshBadges from re-rendering behind the assertions; `$` hands back a throwaway
    // stub for anything the page would have had, exactly as an element that is not there would.
    document: { querySelector: (s: string) => (s === "#toast" ? toastEl : el()), querySelectorAll: () => [], createElement: () => el(), body: el(), activeElement: null },
    location: { hash: "#/friends", origin: "https://example.test" },
    navigator: { clipboard: { writeText: async () => {} } },
    fetch: async (path: string, init?: any) => {
      const method = init?.method || "GET";
      const body = init?.body ? JSON.parse(init.body) : undefined;
      calls.push({ method, path, body });
      const r = await fetch(base + path, { method, headers: init?.headers, body: init?.body });
      const json = await r.json().catch(() => ({}));
      return { ok: r.ok, status: r.status, json: async () => json };
    },
    setInterval() {}, setTimeout: () => 0, clearTimeout() {}, URLSearchParams, Intl, Date, console,
    confirm: () => true, prompt: () => promptAnswer,
  };
  vm.runInNewContext(src, ctx);
  ctx.__ui.setMe(me);
  return { calls, bind: ctx.__ui.bindApprovals as any, toast: () => toastEl.textContent };
}

/** The card the page would have drawn for one approval: its three decision buttons and its editable line. */
function approvalCard(aprId: string, draft: string) {
  const box = el({ value: draft, dataset: { edit: aprId } });
  const mk = (dec: string) => el({ dataset: { dec } });
  const buttons = [mk("approved"), mk("approved_with_edits"), mk("rejected")];
  const cardEl: any = el({ dataset: { apr: aprId } });
  cardEl.querySelector = (sel: string) => (sel === `[data-edit="${aprId}"]` ? box : null);
  cardEl.querySelectorAll = (sel: string) => (sel === "[data-dec]" || sel === "button" ? buttons : []);
  const root: any = el();
  root.querySelectorAll = (sel: string) => (sel === "[data-apr]" ? [cardEl] : []);
  return { root, box, buttons, approved: buttons[0], withEdits: buttons[1], rejected: buttons[2] };
}

/** One friend pair where A's Bot has drafted a line to B, so A's owner holds the card. */
async function pendingCard(s: any, text = "the draft line") {
  const { A, B } = await friends(s.base);
  const c = await B.bot.startConversation(A.bot.id, { type: "general_chat", summary: "Lunch" });
  const draft = await A.bot.draftMessage(c.conversation_id, { text });
  const me = await A.owner.req("GET", "/v1/me");
  return { A, B, convId: c.conversation_id as string, approvalId: draft.approval_id as string, me };
}

/** What the other side can read as delivered line(s). */
async function deliveredText(owner: any, convId: string) {
  const { messages } = await owner.req("GET", `/v1/conversations/${convId}`);
  const out = (messages as any[]).filter((m: any) => m.direction === "outbound" && m.status === "delivered");
  return out.map((m: any) => m.content?.text);
}

const decisionCalls = (ui: any) => ui.calls.filter((c: any) => c.path.endsWith("/decision"));

test("a corrected line and the plain Approve sends the correction, not the draft", async (t) => {
  const s = await startServer(bulkAuth); t.after(s.stop);
  const { A, convId, approvalId, me } = await pendingCard(s);
  const ui = consoleFor(s.base, A.owner.token, me);
  const card = approvalCard(approvalId, "the draft line");
  ui.bind(card.root, () => {});
  card.box.value = "the corrected line";
  await card.approved.onclick();
  const [decision] = decisionCalls(ui);
  assert.ok(decision, `the card decided the approval (${JSON.stringify(ui.calls)})`);
  assert.deepEqual(await deliveredText(A.owner, convId), ["the corrected line"],
    `the owner corrected the line on the card and pressed Approve: the server was told ${JSON.stringify(decision.body)}`);
  assert.equal(decision.body.decision, "approved_with_edits", "the one decision the server applies an edit on");
  assert.deepEqual(decision.body.edited_payload, { text: "the corrected line" }, "the box's text travels as the edit");
});

test("control: an untouched line still sends exactly the plain decision", async (t) => {
  const s = await startServer(bulkAuth); t.after(s.stop);
  const { A, convId, approvalId, me } = await pendingCard(s);
  const ui = consoleFor(s.base, A.owner.token, me);
  const card = approvalCard(approvalId, "the draft line");
  ui.bind(card.root, () => {});
  await card.approved.onclick();
  assert.deepEqual(await deliveredText(A.owner, convId), ["the draft line"], "the draft is delivered unchanged");
  const [decision] = decisionCalls(ui);
  assert.deepEqual(decision.body, { decision: "approved" }, "an untouched card keeps the plain body, nothing attached");
});

test("control: Approve with edits is unchanged", async (t) => {
  const s = await startServer(bulkAuth); t.after(s.stop);
  const { A, convId, approvalId, me } = await pendingCard(s);
  const ui = consoleFor(s.base, A.owner.token, me);
  const card = approvalCard(approvalId, "the draft line");
  ui.bind(card.root, () => {});
  card.box.value = "the corrected line";
  await card.withEdits.onclick();
  assert.deepEqual(await deliveredText(A.owner, convId), ["the corrected line"]);
  const [decision] = decisionCalls(ui);
  assert.equal(decision.body.decision, "approved_with_edits");
  assert.deepEqual(decision.body.edited_payload, { text: "the corrected line" });
});

test("control: Reject still sends its note and never an edit", async (t) => {
  const s = await startServer(bulkAuth); t.after(s.stop);
  const { A, convId, approvalId, me } = await pendingCard(s);
  const ui = consoleFor(s.base, A.owner.token, me, "not this one");
  const card = approvalCard(approvalId, "the draft line");
  ui.bind(card.root, () => {});
  card.box.value = "a rewrite nobody will send";
  await card.rejected.onclick();
  const [decision] = decisionCalls(ui);
  assert.deepEqual(decision.body, { decision: "rejected", note_to_bot: "not this one" }, "a rejection is unchanged");
  assert.deepEqual(await deliveredText(A.owner, convId), [], "a rejected line is never delivered");
});

test("an empty or blank line is refused before any request", async (t) => {
  for (const blank of ["", "   "]) {
    const s = await startServer(bulkAuth); t.after(s.stop);
    const { A, approvalId, me } = await pendingCard(s);
    const ui = consoleFor(s.base, A.owner.token, me);
    const card = approvalCard(approvalId, "the draft line");
    ui.bind(card.root, () => {});
    card.box.value = blank;
    await card.approved.onclick();
    assert.equal(decisionCalls(ui).length, 0, `no decision is sent for a ${JSON.stringify(blank)} box`);
    assert.match(ui.toast(), /write the line first/i, "the owner is told why nothing was sent");
    assert.equal(card.approved.disabled, false, "the card stays usable");
  }
});
