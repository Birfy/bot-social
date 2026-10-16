import Database from "better-sqlite3";
import { FACE_ROOM_SCHEMA } from "./face-rooms.js";

export function openDb(path: string): Database.Database {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  // additive migrations for existing databases
  const cols = (db.prepare("PRAGMA table_info(bots)").all() as { name: string }[]).map((c) => c.name);
  if (!cols.includes("webhook_headers")) db.exec("ALTER TABLE bots ADD COLUMN webhook_headers TEXT NOT NULL DEFAULT '[]'");
  if (!cols.includes("webhook_updated_at")) db.exec("ALTER TABLE bots ADD COLUMN webhook_updated_at TEXT");
  // FlyBot homes: a sub-identity bot names its home bot. Access is always per-bot (default deny);
  // a home or Chief bot is not a wildcard for its members.
  if (!cols.includes("home_bot_id")) db.exec("ALTER TABLE bots ADD COLUMN home_bot_id TEXT");
  // Legacy `published` flag: keep the column so existing databases are not rewritten, but the
  // server no longer reads or writes it. There is no global "publish all my Bots".
  if (!cols.includes("published")) {
    db.exec("ALTER TABLE bots ADD COLUMN published INTEGER NOT NULL DEFAULT 1");
  }
  // Optional owner-chosen look of a Bot (avatar preset/emoji/small image data URL, color), synced to peers who may see the Bot.
  if (!cols.includes("avatar")) db.exec("ALTER TABLE bots ADD COLUMN avatar TEXT");
  if (!cols.includes("color")) db.exec("ALTER TABLE bots ADD COLUMN color TEXT");
  if (!cols.includes("avatar_updated_at")) db.exec("ALTER TABLE bots ADD COLUMN avatar_updated_at TEXT");
  const ocols = (db.prepare("PRAGMA table_info(owners)").all() as { name: string }[]).map((c) => c.name);
  if (!ocols.includes("auto_approve_face_rooms")) db.exec("ALTER TABLE owners ADD COLUMN auto_approve_face_rooms INTEGER NOT NULL DEFAULT 0");
  db.exec(FACE_ROOM_SCHEMA);
  const tcols = (db.prepare("PRAGMA table_info(tokens)").all() as { name: string }[]).map((c) => c.name);
  if (!tcols.includes("id")) db.exec("ALTER TABLE tokens ADD COLUMN id TEXT");
  if (!tcols.includes("label")) db.exec("ALTER TABLE tokens ADD COLUMN label TEXT");
  if (!tcols.includes("scope")) db.exec("ALTER TABLE tokens ADD COLUMN scope TEXT");
  if (!tcols.includes("last_used_at")) db.exec("ALTER TABLE tokens ADD COLUMN last_used_at TEXT");
  // Friendship scope columns are kept for existing rows. Access is always the two endpoint bots
  // (default deny); a legacy 'home' value is ignored and never covers members.
  const rcols = (db.prepare("PRAGMA table_info(relationships)").all() as { name: string }[]).map((c) => c.name);
  if (!rcols.includes("requester_scope")) db.exec("ALTER TABLE relationships ADD COLUMN requester_scope TEXT");
  if (!rcols.includes("target_scope")) db.exec("ALTER TABLE relationships ADD COLUMN target_scope TEXT");
  const icols = (db.prepare("PRAGMA table_info(invites)").all() as { name: string }[]).map((c) => c.name);
  if (!icols.includes("scope")) db.exec("ALTER TABLE invites ADD COLUMN scope TEXT");
  migrateFriendshipScopes(db);
  // Per-bot access: record which rooms a grant is used in (owner can see and revoke).
  db.exec(`CREATE TABLE IF NOT EXISTS grant_rooms (
    grant_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ended_at TEXT,
    PRIMARY KEY (grant_id, room_id)
  )`);
  db.exec("CREATE INDEX IF NOT EXISTS grant_rooms_room ON grant_rooms (room_id, ended_at)");
  const gcols = (db.prepare("PRAGMA table_info(grants)").all() as { name: string }[]).map((c) => c.name);
  if (!gcols.includes("room_id")) db.exec("ALTER TABLE grants ADD COLUMN room_id TEXT");
  const fm = (db.prepare("PRAGMA table_info(face_room_members)").all() as { name: string }[]).map((c) => c.name);
  if (!fm.includes("added_by_owner_id")) db.exec("ALTER TABLE face_room_members ADD COLUMN added_by_owner_id TEXT");
  return db;
}

/** Pins the scope of invite-born friendships to the invite's target. Idempotent; only fills NULLs.
 *  The inviter side gets the invite's target exactly (a member invite exposes that member only;
 *  a home invite keeps exposing the home). The joiner side is left NULL: unchanged behavior. */
export function migrateFriendshipScopes(db: Database.Database): number {
  const r = db.prepare(`UPDATE relationships SET target_scope = (
      SELECT CASE WHEN b.integration_type = 'flybot-home' THEN 'home' ELSE 'bot' END
      FROM relationship_invites ri JOIN invites i ON i.id = ri.invite_id JOIN bots b ON b.id = i.bot_id
      WHERE ri.relationship_id = relationships.id AND i.bot_id = relationships.target_bot)
    WHERE target_scope IS NULL AND id IN (
      SELECT ri.relationship_id FROM relationship_invites ri JOIN invites i ON i.id = ri.invite_id WHERE i.bot_id = relationships.target_bot)`).run();
  db.exec("UPDATE invites SET scope = CASE WHEN (SELECT integration_type FROM bots WHERE id = invites.bot_id) = 'flybot-home' THEN 'home' ELSE 'bot' END WHERE scope IS NULL");
  return r.changes;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS bot_custody (
  bot_id TEXT PRIMARY KEY REFERENCES bots(id), kid TEXT NOT NULL, sealed_key TEXT NOT NULL,
  events_cursor INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY, bot_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0, event_types TEXT NOT NULL DEFAULT '{}', url_redacted TEXT,
  attempts INTEGER NOT NULL DEFAULT 0, response_status INTEGER, error TEXT,
  created_at TEXT NOT NULL, sent_at TEXT, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_bot ON webhook_deliveries (bot_id, created_at);
CREATE TABLE IF NOT EXISTS owners (
  id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL, timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
  sensitive_terms TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('owner','bot')), subject_id TEXT NOT NULL,
  created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS bots (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES owners(id), handle TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL, integration_type TEXT NOT NULL, webhook_url TEXT, webhook_secret TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bot_keys (
  bot_id TEXT NOT NULL REFERENCES bots(id), kid TEXT NOT NULL, alg TEXT NOT NULL, public_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, expires_at TEXT, PRIMARY KEY (bot_id, kid)
);
CREATE TABLE IF NOT EXISTS nonces (bot_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL, PRIMARY KEY (bot_id, nonce));
CREATE TABLE IF NOT EXISTS relationships (
  id TEXT PRIMARY KEY, requester_bot TEXT NOT NULL, target_bot TEXT NOT NULL,
  requester_owner TEXT NOT NULL, target_owner TEXT NOT NULL,
  status TEXT NOT NULL, message TEXT, requested_caps TEXT NOT NULL, offered_caps TEXT NOT NULL,
  blocked_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT
);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL REFERENCES relationships(id),
  grantor_owner TEXT NOT NULL, grantee_bot TEXT NOT NULL, capability TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, relationship_id TEXT NOT NULL, initiator_bot TEXT NOT NULL, peer_bot TEXT NOT NULL,
  intent TEXT NOT NULL, status TEXT NOT NULL, outcome TEXT, summary TEXT, max_turns INTEGER NOT NULL, turn_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id), sender_bot TEXT NOT NULL, recipient_bot TEXT NOT NULL,
  envelope TEXT NOT NULL, payload TEXT NOT NULL, delivered_payload TEXT, status TEXT NOT NULL,
  risk_flags TEXT NOT NULL DEFAULT '[]', injection TEXT NOT NULL DEFAULT '{}', expects_reply INTEGER NOT NULL DEFAULT 1,
  approval_id TEXT, created_at TEXT NOT NULL, created_ms INTEGER NOT NULL, delivered_at TEXT
);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, actor_bot TEXT NOT NULL, action_type TEXT NOT NULL,
  params TEXT NOT NULL, justification TEXT, envelope TEXT NOT NULL, status TEXT NOT NULL, result TEXT,
  approval_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, kind TEXT NOT NULL, subject_id TEXT NOT NULL, bot_id TEXT,
  conversation_id TEXT, summary TEXT NOT NULL, reasons TEXT NOT NULL DEFAULT '[]', risk_flags TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending', decision TEXT, note TEXT, created_at TEXT NOT NULL, expires_at TEXT, decided_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, bot_id TEXT NOT NULL, type TEXT NOT NULL,
  data TEXT NOT NULL, created_at TEXT NOT NULL, webhook_status TEXT
);
CREATE TABLE IF NOT EXISTS calendar_entries (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL,
  title TEXT, location TEXT, attendees TEXT NOT NULL DEFAULT '[]', source TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'confirmed', organizer_owner TEXT, booking_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, bot_id TEXT NOT NULL, owner_id TEXT NOT NULL, created_by TEXT NOT NULL,
  offered_caps TEXT NOT NULL, requested_caps TEXT NOT NULL, message TEXT, auto_accept INTEGER NOT NULL DEFAULT 1,
  max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active',
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS relationship_settings (
  relationship_id TEXT NOT NULL, owner_id TEXT NOT NULL, auto_approve_chat INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
  PRIMARY KEY (relationship_id, owner_id)
);
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, bot_id TEXT NOT NULL, name TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL,
  sha256 TEXT NOT NULL, sealed BLOB NOT NULL, message_id TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS attachments_expiry ON attachments (expires_at);
CREATE TABLE IF NOT EXISTS relationship_invites (relationship_id TEXT PRIMARY KEY, invite_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_bot ON events(bot_id, seq);
CREATE INDEX IF NOT EXISTS idx_msgs_conv ON messages(conversation_id, created_ms);
`;
