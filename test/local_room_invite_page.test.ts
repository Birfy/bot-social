import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { startServer } from "./helpers.js";

// Bot Social #61: a local room's link is /r/@handle/<ticket> (two segments, FlyBot
// core/src/shared/room-share.js). The landing route only had one segment, so a camera scan of the QR code
// was a 404 — not a missing page. These cases pin the route, the two shapes, and what the page says.
const page = readFileSync(new URL("../public/room-invite.html", import.meta.url), "utf8");
const LOCAL_TICKET = "abcdefghijklmnopqrstuv"; // 22 characters, inside FlyBot's 16-64 window
const FACE_TICKET = "A".repeat(43); // a face ticket is exactly 43 base64url characters

async function get(base: string, path: string) {
  const r = await fetch(base + path);
  return { status: r.status, type: r.headers.get("content-type") ?? "", body: await r.text() };
}

test("#61: a local link opens the page; before this route it was a 404", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const r = await get(s.base, `/r/@ann.bot/${LOCAL_TICKET}`);
  assert.equal(r.status, 200);
  assert.match(r.type, /text\/html/);
  // The page, not a JSON 404: Fastify's own not-found answers { statusCode: 404, error: "Not Found" }.
  assert.equal(r.body.includes("statusCode"), false);
  assert.match(r.body, /id="c"/);
});

test("#61: the page tells the two link shapes apart and asks the matching endpoint", async () => {
  // The local shape is two segments; the face shape stays one and keeps its own endpoint (negative control).
  assert.match(page, /seg\.length>=3/);
  assert.match(page, /\/v1\/local-room-invites\//);
  assert.match(page, /\/v1\/face-rooms\/invites\//);
  // The local copy is the "paste it back into FlyBot" step, never the face-room one-click join.
  assert.match(page, /paste it back into your own FlyBot/);
  const localBranch = page.slice(page.indexOf("if(local){"), page.indexOf("document.getElementById(\"c\").innerHTML=`<h2>Room invite</h2>"));
  assert.equal(localBranch.includes("join_room_invite"), false, "the local page must not promise join_room_invite");
  const faceBranch = page.slice(page.lastIndexOf("document.getElementById(\"c\").innerHTML=`<h2>Room invite</h2>"));
  assert.match(faceBranch, /join_room_invite/, "the face page keeps today's wording");
});

test("#61: a local ticket has a sentence per refusal, and an uncheckable link is not a 404 in disguise", async () => {
  for (const code of ["invite_not_found", "expired", "revoked", "ended", "already_claimed", "rate_limited", "locked_out", "network", "unchecked", "server_error"]) {
    assert.match(page, new RegExp(`${code}:"`), `every refusal has its own sentence: ${code}`);
  }
  // "Nothing can check this yet" is a different fact from "this link is not valid", and it is the one a
  // server without the local endpoint answers (Fastify's 404 has no invite code).
  assert.match(page, /status===404&&!known\?ERR\.unchecked/);
  // A rate limit that names a retry time is not shown as a raw code either.
  assert.equal(/Something went wrong \(\$\{/.test(page), false, "no raw code on screen");
});

test("#61: the handle in the path is display-only and escaped; the server never reflects it", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const plain = await get(s.base, `/r/@ann.bot/${LOCAL_TICKET}`);
  const hostile = await get(s.base, `/r/${encodeURIComponent("<script>alert(1)</script>")}/${LOCAL_TICKET}`);
  assert.equal(hostile.status, 200, "an odd handle is still just a page");
  // Byte-identical: the path never reaches the HTML, so injection can only happen in the page's own
  // rendering, where the handle goes through esc() (asserted below).
  assert.equal(hostile.body, plain.body);
  assert.equal(hostile.body.includes("<script>alert(1)"), false);
  assert.match(page, /const host=local\?\(handle\?esc\(handle\):esc\(lead\)\):esc\(lead\)/);
  assert.equal(/innerHTML=[^;]*\$\{handle\}/.test(page), false, "the raw handle is never interpolated");
});

test("#61: a face ticket on the one-segment route still serves the page, unchanged in shape", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const r = await get(s.base, `/r/${FACE_TICKET}`);
  assert.equal(r.status, 200);
  assert.equal(r.body, (await get(s.base, `/r/@ann.bot/${LOCAL_TICKET}`)).body, "one template for both shapes");
});
