import assert from "node:assert/strict";
import { test } from "node:test";
import { expectApiError, startServer } from "./helpers.js";

test("revoking a home member cancels its pending drafts and nothing is delivered", async (t) => {
  const s = await startServer();
  t.after(s.stop);
  const p = s.platform;
  const a = p.onboardFlybot({ display_name: "Alice" });
  const b = p.onboardFlybot({ display_name: "Bob" });
  const A = { kind: "owner" as const, ownerId: a.owner_id };
  const B = { kind: "owner" as const, ownerId: b.owner_id };
  const writer = p.addHomeMember(A, a.home.bot_id, { name: "writer", display_name: "Writer" });
  const coder = p.addHomeMember(B, b.home.bot_id, { name: "coder", display_name: "Coder" });
  const rel = p.requestRelationship(A, { from_bot_id: writer.bot_id, target_bot_id: coder.bot_id, message: "hi" });
  p.consent(B, rel.relationship_id, { decision: "accept", grant_capabilities: [] });
  const sent = p.sendAsMember(A, { from_bot_id: writer.bot_id, to: coder.handle, text: "hello" });
  assert.equal(sent.message.status, "pending_approval");
  const approval = sent.message.approval_id as string;

  p.removeHomeMember(A, a.home.bot_id, writer.bot_id);

  assert.equal(p.listApprovals(A, "pending").some((x: any) => x.approval_id === approval), false, "the card is no longer pending");
  await expectApiError(Promise.resolve().then(() => p.decideApproval(A, approval, { decision: "approved" })), 409, "invalid_state");
  const conv = p.getConversation(B, sent.conversation_id);
  assert.equal(conv.messages.filter((m: any) => m.direction === "inbound").length, 0, "nothing reached the peer");
  assert.equal(conv.status, "open", "a cancelled-only conversation is not left awaiting approval");
});
