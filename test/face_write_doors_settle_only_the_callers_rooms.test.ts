/**
 * Six member-only write doors were starting other homes' face rooms.
 *
 * `startFaceRoom`, `leaveFaceRoom`, `setFaceRoomLead`, `setFaceRoomNote`, `setFaceRoomRoles` and
 * `draftFaceRoomMessage` each opened with `this.advanceFaceRooms()`, whose sweep is unscoped: every lapsed candidate
 * room on the platform was promoted by it — the room flipped to `open`, its 6-digit number was voided, its
 * `face_room_codes` rows deleted, a `room.started` event written, its members woken and an audit row appended. The
 * sweep runs before the door reads the caller's seat, so a caller seated nowhere settled every lapsed room on the
 * platform and was refused afterwards — and the room id it named did not even have to exist.
 *
 * The sweep on these six doors now settles only the lapsed rooms the caller's own Bots already sit in; a caller with
 * no seat settles nothing. The doors keep their order (the sweep still runs before the seat is read), their
 * permissions, their status answers and their error codes.
 *
 * Each case below proves both halves at once: a stranger's refused call leaves the third party's lapsed room exactly
 * as it was, and then the room's own member makes the same call and that settles the room. A change that drops the
 * sweep to pass the first half fails the second.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ownerWithBot, startServer } from "./helpers.js";

const PAST = "2020-01-01T00:00:00.000Z";
const PUSH = "https://push.test/write-doors";

type S = Awaited<ReturnType<typeof startServer>>;

/** A server whose webhook POSTs are captured instead of sent, so a push is counted, not guessed. */
async function server() {
  const calls: { url: string; body: string }[] = [];
  const fetchImpl = (async (url: string, init: any) => {
    calls.push({ url: String(url), body: String(init?.body ?? "") });
    return new Response("ok", { status: 200 });
  }) as unknown as typeof fetch;
  const s = await startServer({
    faceRooms: { attemptsPerAccount: 50, attemptsPerIp: 200, createsPerAccount: 50, createsPerIp: 50 },
    fetchImpl,
  });
  return { s, calls };
}

const roomRow = (s: S, id: string) => s.platform.db.prepare("SELECT * FROM face_rooms WHERE id = ?").get(id) as any;
const codeRows = (s: S, id: string) => (s.platform.db.prepare("SELECT COUNT(*) n FROM face_room_codes WHERE room_id = ?").get(id) as any).n as number;
const startedEvents = (s: S, id: string) => (s.platform.db.prepare("SELECT COUNT(*) n FROM face_room_events WHERE room_id = ? AND type = 'room.started'").get(id) as any).n as number;
const startedAudits = (s: S, id: string) => ((s.platform.audit as any).db.prepare("SELECT COUNT(*) n FROM audit_events WHERE action = 'face_room.started' AND subject = ?").get(id) as any).n as number;
const roomPushes = (calls: { body: string }[]) => calls.filter((c) => c.body.includes("face_room.started")).length;

/** The answer a door gave, whether it answered or refused. */
async function answerOf(call: () => Promise<any>) {
  try {
    const body = await call();
    return { status: 200, code: null as string | null, body };
  } catch (e: any) {
    return { status: e?.status ?? 0, code: e?.code ?? null, body: e };
  }
}

/** A lapsed candidate room owned by the other home, a stranger seated nowhere, and the room's own member. */
async function scene(base: string, code: string) {
  const owner = await ownerWithBot(base, "owner", PUSH);
  const guest = await ownerWithBot(base, "guest", PUSH);
  const stranger = await ownerWithBot(base, "stranger");
  const made = await owner.owner.req("POST", "/v1/face-rooms/join", { code, bots: [owner.bot.id] });
  const roomId = made.room_id as string;
  const joined = await guest.owner.req("POST", "/v1/face-rooms/join", { code, bots: [guest.bot.id] });
  assert.equal(joined.room_id, roomId, "the second home joins the same number");
  const row = roomRow(s, roomId);
  assert.equal(row.status, "candidate", "two joins make a candidate room");
  assert.ok(row.code, "the candidate room still holds its number");
  return { owner, guest, stranger, roomId };
}

let s: S;
let calls: { url: string; body: string }[] = [];

for (const [index, door] of [
  { name: "start", method: "POST", path: (id: string) => `/v1/face-rooms/${id}/start`, body: () => ({}) },
  { name: "leave", method: "POST", path: (id: string) => `/v1/face-rooms/${id}/leave`, body: () => ({}) },
  { name: "lead", method: "POST", path: (id: string) => `/v1/face-rooms/${id}/lead`, body: (who: any) => ({ bot: who.bot.id }) },
  { name: "note", method: "POST", path: (id: string) => `/v1/face-rooms/${id}/note`, body: () => ({ note: "a room note" }) },
  { name: "roles", method: "PUT", path: (id: string) => `/v1/face-rooms/${id}/roles`, body: (who: any) => ({ roles: { [who.bot.id]: "Writer" } }) },
  { name: "messages", method: "POST", path: (id: string) => `/v1/face-rooms/${id}/messages`, body: () => ({ text: "hello" }) },
].entries()) {
  test(`a stranger's ${door.name} settles nothing, and the room's own member's ${door.name} settles it`, async () => {
    const started = await server();
    s = started.s;
    calls = started.calls;
    try {
      const { owner, stranger, roomId } = await scene(s.base, String(600100 + index));
      s.platform.db.prepare("UPDATE face_rooms SET expires_at = ? WHERE id = ?").run(PAST, roomId);
      await s.platform.flushWebhooks();
      calls.length = 0;

      const codeBefore = roomRow(s, roomId).code;
      const madeUp = "00000000-0000-4000-8000-000000000000";
      const refused = await answerOf(() => (stranger.owner as any).req(door.method, door.path(madeUp), door.body(stranger)));
      assert.equal(refused.status, 404, `a room id that does not exist is refused (${door.name}): ${JSON.stringify(refused.body?.body ?? refused.body)}`);
      await s.platform.flushWebhooks();

      const afterStranger = roomRow(s, roomId);
      assert.equal(afterStranger.status, "candidate", "the stranger did not start the other home's room");
      assert.equal(afterStranger.code, codeBefore, "and left its number in place");
      assert.equal(codeRows(s, roomId), 1, "its code row is still there");
      assert.equal(startedEvents(s, roomId), 0, "no room.started event was written for it");
      assert.equal(startedAudits(s, roomId), 0, "no face_room.started audit row was written for it");
      assert.equal(roomPushes(calls), 0, "and nobody was woken");

      // The other half: the room's own member makes the same call, and that does settle the lapsed room.
      const settled = await answerOf(() => (owner.owner as any).req(door.method, door.path(roomId), door.body(owner)));
      assert.ok(settled.status < 400, `the room's own member is not refused (${door.name}): ${settled.status} ${JSON.stringify(settled.body?.body ?? settled.body)}`);
      await s.platform.flushWebhooks();
      const afterMember = roomRow(s, roomId);
      assert.equal(afterMember.status, "open", "the member's own call starts the lapsed room");
      assert.equal(afterMember.code, null, "and voids its number");
      assert.equal(afterMember.expires_at, "", "the matching window is gone with the number");
      assert.equal(codeRows(s, roomId), 0, "the code row is deleted");
      assert.equal(startedEvents(s, roomId), 1, "one room.started event records the promotion");
      assert.equal(startedAudits(s, roomId), 1, "and one audit row");
      assert.ok(roomPushes(calls) >= 1, "and the members are woken");
    } finally {
      await s.stop();
    }
  });
}

test("none of the six write doors sweeps without a scope", () => {
  // A pin on these six doors only, not on the file: each door must hand its sweep the set it read, and none of them
  // may fall back to the unscoped call. Counting call sites across the whole file breaks whenever a neighbouring
  // lane lands, which is exactly what happened to the count pinned for the join door.
  const src = readFileSync(new URL("../src/platform.ts", import.meta.url), "utf8");
  const doorBody = (name: string) => {
    const start = src.indexOf(`\n  ${name}(`);
    assert.ok(start >= 0, `${name} is still a method of Platform`);
    const end = src.indexOf("\n  }\n", start);
    assert.ok(end > start, `${name} still closes after its opening line`);
    return src.slice(start, end);
  };
  for (const name of ["startFaceRoom", "leaveFaceRoom", "setFaceRoomLead", "setFaceRoomNote", "setFaceRoomRoles", "draftFaceRoomMessage"]) {
    const body = doorBody(name);
    assert.ok(body.includes("this.advanceFaceRooms(seatRooms)"), `${name} sweeps the rooms its caller already sits in`);
    assert.ok(!body.includes("this.advanceFaceRooms()"), `${name} has no unscoped sweep`);
  }
});
