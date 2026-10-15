/** Face-to-face rooms: 6-digit matching, membership, windowed history. See docs/FACE_ROOMS.md. */
import { ApiError } from "./errors.js";
import { limitFromEnv } from "./policy.js";

export const FACE_ROOM_NAME_MAX = 60;

export interface FaceRoomLimits {
  ttlMs: number;
  maxMembers: number;
  attemptsPerIp: number;
  attemptsPerAccount: number;
  attemptWindowMs: number;
  createsPerIp: number;
  createsPerAccount: number;
  createWindowMs: number;
  failsBeforeLockout: number;
  lockoutMs: number;
}

export const DEFAULT_FACE_ROOM_LIMITS: FaceRoomLimits = {
  ttlMs: 10 * 60 * 1000,
  maxMembers: 8,
  attemptsPerIp: 20,
  attemptsPerAccount: 10,
  attemptWindowMs: 10 * 60 * 1000,
  createsPerIp: 5,
  createsPerAccount: 3,
  createWindowMs: 60 * 60 * 1000,
  failsBeforeLockout: 8,
  lockoutMs: 15 * 60 * 1000,
};

/** Env vars (all optional, positive integers). Operator note: see README / docs/FACE_ROOMS.md. */
export function loadFaceRoomLimits(override: Partial<FaceRoomLimits> = {}): FaceRoomLimits {
  const env: Partial<FaceRoomLimits> = {
    ttlMs: envMs("BOTSOCIAL_FACE_ROOM_TTL_SECONDS", DEFAULT_FACE_ROOM_LIMITS.ttlMs / 1000),
    maxMembers: envN("BOTSOCIAL_FACE_ROOM_MAX_MEMBERS", DEFAULT_FACE_ROOM_LIMITS.maxMembers),
    attemptsPerIp: envN("BOTSOCIAL_FACE_ROOM_ATTEMPTS_PER_IP", DEFAULT_FACE_ROOM_LIMITS.attemptsPerIp),
    attemptsPerAccount: envN("BOTSOCIAL_FACE_ROOM_ATTEMPTS_PER_ACCOUNT", DEFAULT_FACE_ROOM_LIMITS.attemptsPerAccount),
    attemptWindowMs: envMs("BOTSOCIAL_FACE_ROOM_ATTEMPT_WINDOW_SECONDS", DEFAULT_FACE_ROOM_LIMITS.attemptWindowMs / 1000),
    createsPerIp: envN("BOTSOCIAL_FACE_ROOM_CREATES_PER_IP", DEFAULT_FACE_ROOM_LIMITS.createsPerIp),
    createsPerAccount: envN("BOTSOCIAL_FACE_ROOM_CREATES_PER_ACCOUNT", DEFAULT_FACE_ROOM_LIMITS.createsPerAccount),
    createWindowMs: envMs("BOTSOCIAL_FACE_ROOM_CREATE_WINDOW_SECONDS", DEFAULT_FACE_ROOM_LIMITS.createWindowMs / 1000),
    failsBeforeLockout: envN("BOTSOCIAL_FACE_ROOM_FAILS_BEFORE_LOCKOUT", DEFAULT_FACE_ROOM_LIMITS.failsBeforeLockout),
    lockoutMs: envMs("BOTSOCIAL_FACE_ROOM_LOCKOUT_SECONDS", DEFAULT_FACE_ROOM_LIMITS.lockoutMs / 1000),
  };
  return { ...DEFAULT_FACE_ROOM_LIMITS, ...omitUndef(env), ...omitUndef(override) };
}

function envN(name: string, fallback: number): number | undefined {
  const v = process.env[name];
  if (v === undefined) return undefined;
  return limitFromEnv(v, fallback);
}
function envMs(name: string, fallbackSeconds: number): number | undefined {
  const n = envN(name, fallbackSeconds);
  return n === undefined ? undefined : n * 1000;
}
function omitUndef<T extends Record<string, unknown>>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>;
}

/**
 * Sanitize a peer-controlled name (bot display name, owner name) before it is stored or shown.
 * Strips `@`, control characters and newlines, collapses whitespace, caps length.
 */
export function sanitizePeerName(value: unknown, fallback = "", max = FACE_ROOM_NAME_MAX): string {
  const cleaned = String(value ?? "")
    .replace(/@/g, "")
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
  return cleaned || fallback;
}

/** Six decimal digits, nothing else. Does not look up a room (no leak). */
export function parseFaceCode(raw: unknown): string {
  const s = String(raw ?? "").trim();
  if (!/^\d{6}$/.test(s)) throw new ApiError(400, "invalid_code", "code must be exactly 6 digits");
  return s;
}

export function isFaceCode(raw: unknown): boolean {
  return /^\d{6}$/.test(String(raw ?? "").trim());
}

export function memberLabel(displayName: string, ownerName: string): string {
  return `${displayName} · ${ownerName}`;
}

export function joinSystemText(ownerName: string, displayName: string): string {
  return `${ownerName}'s ${displayName} joined`;
}

export function leaveSystemText(ownerName: string, displayName: string): string {
  return `${ownerName}'s ${displayName} left`;
}

export const FACE_ROOM_SCHEMA = `
CREATE TABLE IF NOT EXISTS face_rooms (
  id TEXT PRIMARY KEY,
  code TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  started_at TEXT,
  closed_at TEXT
);
CREATE TABLE IF NOT EXISTS face_room_codes (
  code TEXT PRIMARY KEY,
  room_id TEXT NOT NULL UNIQUE REFERENCES face_rooms(id),
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS face_room_members (
  room_id TEXT NOT NULL REFERENCES face_rooms(id),
  bot_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  handle TEXT NOT NULL,
  display_name TEXT NOT NULL,
  owner_name TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 1,
  added_by_owner_id TEXT,
  joined_at TEXT NOT NULL,
  join_seq INTEGER NOT NULL DEFAULT 0,
  left_at TEXT,
  PRIMARY KEY (room_id, bot_id)
);
CREATE INDEX IF NOT EXISTS face_room_members_room ON face_room_members (room_id, left_at);
CREATE TABLE IF NOT EXISTS face_room_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  room_id TEXT NOT NULL REFERENCES face_rooms(id),
  type TEXT NOT NULL,
  actor_bot TEXT,
  data TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS face_room_events_room ON face_room_events (room_id, seq);
CREATE TABLE IF NOT EXISTS face_room_drafts (
  id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL REFERENCES face_rooms(id),
  sender_bot TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL,
  approval_id TEXT,
  event_seq INTEGER,
  created_at TEXT NOT NULL,
  created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS face_room_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id TEXT,
  ip TEXT,
  code TEXT,
  outcome TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS face_room_attempts_owner ON face_room_attempts (owner_id, created_at);
CREATE INDEX IF NOT EXISTS face_room_attempts_ip ON face_room_attempts (ip, created_at);
CREATE TABLE IF NOT EXISTS face_room_lockouts (
  key TEXT PRIMARY KEY,
  until TEXT NOT NULL,
  fails INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
`;
