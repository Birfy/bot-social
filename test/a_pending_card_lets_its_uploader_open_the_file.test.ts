/**
 * A file a waiting card names is still the uploader's own file.
 *
 * `checkRefs` binds an upload to the message at draft time, so the card and the file are one thing until the owner
 * decides. The console draws an Open control on the approval card and fetches the bytes with the owner's token, but
 * `getAttachment` only recognised a reader once the message was `delivered`: the uploader's owner and the bot that
 * drafted the file got `404 attachment_not_found` from the very card asking them to send it. `cleanupAttachments`
 * meanwhile keeps a bound row alive exactly because that card may still be approved, so the bytes were there and only
 * the door was shut.
 *
 * (1) the uploader's home reads its own file while the card waits: the owner who uploaded it and the Bot that drafted
 * it both get the same bytes back, by the same id; (2) the control: the peer is still refused before delivery and the
 * recipient's owner reads the file once the card is approved -- delivery's rule is untouched, and after it the
 * uploader's owner is no longer the reader.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { bulkAuth, friends, startServer } from "./helpers.js";

const b64 = (s: string | Buffer) => Buffer.from(s).toString("base64");
type S = Awaited<ReturnType<typeof startServer>>;

/** A raw read, so a refused one can be told apart from a successful one by status and code. */
async function open(base: string, id: string, token: string) {
  const r = await fetch(`${base}/v1/attachments/${id}`, { headers: { authorization: `Bearer ${token}` } });
  const body: any = await r.json().catch(() => ({}));
  return { status: r.status, body };
}

/** One upload, then a draft that carries it and waits for its owner: the card the console draws. */
async function pendingCard(s: S) {
  const { A, B } = await friends(s.base);
  const bytes = "# Plan\nship it\n";
  const up: any = await A.owner.req("POST", "/v1/attachments", { bot_id: A.bot.id, name: "plan.md", content_base64: b64(bytes) });
  const file = up.attachment as { id: string; name: string; size: number; mime: string; sha256: string };
  const conv: any = await A.bot.startConversation(B.bot.id, { type: "general_chat", summary: "a pending card's file" });
  const draft: any = await A.bot.signed(`/v1/conversations/${conv.conversation_id}/messages`, "message.draft",
    { text: "the plan is attached", attachments: [file] }, { conversation_id: conv.conversation_id });
  assert.equal(draft.status, "pending_approval", JSON.stringify(draft));
  assert.equal(draft.policy.hold_reason, "attachment", "the card is the file's, not the blanket hold's");
  return { A, B, bytes, file, approvalId: draft.approval_id as string, messageId: draft.message_id as string };
}

test("the uploader's home can open the file its waiting card names", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, bytes, file, messageId } = await pendingCard(s);

  const asOwner = await open(s.base, file.id, A.owner.token);
  assert.equal(asOwner.status, 200, `the uploader's owner can open the file the card is asking them to send — got ${asOwner.status} ${asOwner.body?.error?.code ?? ""}`);
  assert.equal(Buffer.from(asOwner.body.content_base64, "base64").toString(), bytes, "the owner reads back the bytes they uploaded");
  assert.equal(asOwner.body.message_id, messageId, "the answer names the line the file is waiting on");
  assert.equal(asOwner.body.attachment.sha256, file.sha256, "the answer carries the hash the draft signed");

  const asBot = await open(s.base, file.id, A.bot.cred.token);
  assert.equal(asBot.status, 200, `the uploading Bot can open the file it drafted — got ${asBot.status} ${asBot.body?.error?.code ?? ""}`);
  assert.equal(Buffer.from(asBot.body.content_base64, "base64").toString(), bytes, "the Bot reads the same bytes back");
  assert.equal(asBot.body.message_id, messageId, "both readers are answered about the same line");
});

test("the peer stays refused until delivery, and reads the file after the card lands", async (t) => {
  const s = await startServer(bulkAuth);
  t.after(s.stop);
  const { A, B, bytes, file, approvalId } = await pendingCard(s);

  const peerOwnerBefore = await open(s.base, file.id, B.owner.token);
  assert.equal(peerOwnerBefore.status, 404, `a peer owner reads a file before the card is decided — got ${peerOwnerBefore.status}`);
  assert.equal(peerOwnerBefore.body.error.code, "attachment_not_found", "a refusal still cannot tell a waiting file from a missing one");
  const peerBotBefore = await open(s.base, file.id, B.bot.cred.token);
  assert.equal(peerBotBefore.status, 404, `a peer Bot reads a file before the card is decided — got ${peerBotBefore.status}`);
  assert.equal(peerBotBefore.body.error.code, "attachment_not_found");

  const decided: any = await A.owner.req("POST", `/v1/approvals/${approvalId}/decision`, { decision: "approved" });
  assert.equal(decided.decision, "approved", JSON.stringify(decided));

  const peerOwnerAfter = await open(s.base, file.id, B.owner.token);
  assert.equal(peerOwnerAfter.status, 200, `delivery still hands the file to the recipient's owner — got ${peerOwnerAfter.status}`);
  assert.equal(Buffer.from(peerOwnerAfter.body.content_base64, "base64").toString(), bytes, "the recipient reads the file that was sent");

  const uploaderAfter = await open(s.base, file.id, A.owner.token);
  assert.equal(uploaderAfter.status, 404, `once delivered, the recipient's rule decides, not the uploader's — got ${uploaderAfter.status}`);
});
