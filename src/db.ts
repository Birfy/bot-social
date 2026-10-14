import Database from "better-sqlite3";

export function openDb(path: string): Database.Database {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  // additive migrations for existing databases
  const cols = (db.prepare("PRAGMA table_info(bots)").all() as { name: string }[]).map((c) => c.name);
  if (!cols.includes("webhook_headers")) db.exec("ALTER TABLE bots ADD COLUMN webhook_headers TEXT NOT NULL DEFAULT '[]'");
  if (!cols.includes("webhook_updated_at")) db.exec("ALTER TABLE bots ADD COLUMN webhook_updated_at TEXT");
  const tcols = (db.prepare("PRAGMA table_info(tokens)").all() as { name: string }[]).map((c) => c.name);
  if (!tcols.includes("id")) db.exec("ALTER TABLE tokens ADD COLUMN id TEXT");
  if (!tcols.includes("label")) db.exec("ALTER TABLE tokens ADD COLUMN label TEXT");
  if (!tcols.includes("scope")) db.exec("ALTER TABLE tokens ADD COLUMN scope TEXT");
  if (!tcols.includes("last_used_at")) db.exec("ALTER TABLE tokens ADD COLUMN last_used_at TEXT");
  return db;
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
CREATE TABLE IF NOT EXISTS relationship_invites (relationship_id TEXT PRIMARY KEY, invite_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_bot ON events(bot_id, seq);
CREATE INDEX IF NOT EXISTS idx_msgs_conv ON messages(conversation_id, created_ms);
`;
