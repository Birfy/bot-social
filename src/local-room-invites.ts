import { randomBytes } from "node:crypto";

/**
 * Bot Social #60: a ticket for a room that lives in one FlyBot home, not on this server. The server keeps the
 * ticket and nothing of the room: who minted it, which of their Bots the link knocks on, the room id that home
 * uses, and — once — which home claimed it with which Bots. That claim is the only reach a stranger gets.
 */

/** 16 random bytes in base64url: 22 characters, the shape FlyBot's local link carries (`[A-Za-z0-9_-]{16,64}`). */
export const LOCAL_INVITE_TICKET_BYTES = 16;
export const LOCAL_INVITE_MAX_BOTS = 8;
/** A local room's link has no deadline (owner decision 2026-10-24): it lives until withdrawn or spent. */
export const LOCAL_INVITE_NO_DEADLINE = "";
export function newLocalInviteTicket(): string {
  return randomBytes(LOCAL_INVITE_TICKET_BYTES).toString("base64url");
}
export function isLocalInviteTicket(raw: unknown): raw is string {
  return typeof raw === "string" && /^[A-Za-z0-9_-]{16,64}$/.test(raw.trim());
}
/** The id the inviter's home gives its room: the same shape `send_as_member` accepts for `room_id`. */
export function isLocalRoomId(raw: unknown): raw is string {
  return typeof raw === "string" && /^[A-Za-z0-9._:-]{1,64}$/.test(raw.trim());
}

export const LOCAL_ROOM_INVITE_SCHEMA = `
CREATE TABLE IF NOT EXISTS local_room_invites (
  ticket TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  name TEXT,
  created_by_owner_id TEXT NOT NULL,
  inviter_bot TEXT NOT NULL,
  expires_at TEXT NOT NULL, -- '' = no deadline (every ticket minted now); a date only on older tickets
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  claimed_by_owner_id TEXT,
  claimed_bots TEXT,
  claimed_at TEXT,
  released_at TEXT
);
CREATE INDEX IF NOT EXISTS local_room_invites_room ON local_room_invites (room_id, inviter_bot);
`;
