import Database from 'better-sqlite3';

// SQLite keeps the prototype self-contained. The schema maps one to one onto Postgres,
// where row-level security would add tenant isolation in the database itself.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS vehicles (
  id           TEXT PRIMARY KEY,          -- opaque record id, the only identifier put on-chain
  vin          TEXT NOT NULL,
  make         TEXT, model TEXT, year INTEGER,
  created_at   TEXT NOT NULL
);

-- Custody of the digital record. Legal ownership is decided by contracts and the
-- registration papers; this table only says who controls the record right now.
CREATE TABLE IF NOT EXISTS custody (
  id           INTEGER PRIMARY KEY,
  vehicle_id   TEXT NOT NULL REFERENCES vehicles(id),
  owner        TEXT NOT NULL,
  since        TEXT NOT NULL,
  until        TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
  id           TEXT PRIMARY KEY,
  vehicle_id   TEXT NOT NULL REFERENCES vehicles(id),
  kind         TEXT NOT NULL,             -- photo | service_record | certificate | assessment ...
  filename     TEXT NOT NULL,
  version      INTEGER NOT NULL,
  supersedes   TEXT REFERENCES evidence(id),
  file_sha256  TEXT NOT NULL,
  salt         TEXT NOT NULL,
  commitment   TEXT NOT NULL,
  wrapped_key  BLOB,                      -- NULL once shredded
  status       TEXT NOT NULL DEFAULT 'active', -- active | superseded | revoked | shredded
  uploaded_by  TEXT NOT NULL,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
  id           TEXT PRIMARY KEY,
  vehicle_id   TEXT NOT NULL REFERENCES vehicles(id),
  granted_by   TEXT NOT NULL,
  grantee      TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,             -- JSON array: share selected items, not the whole record
  expires_at   TEXT NOT NULL,
  revoked_at   TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
  uid          TEXT PRIMARY KEY,
  vehicle_id   TEXT NOT NULL UNIQUE REFERENCES vehicles(id),
  last_counter INTEGER NOT NULL DEFAULT -1, -- a chip may report counter 0 on its first tap
                                            -- (keys are derived from the master + UID, not stored)
  bound_at     TEXT NOT NULL
);

-- Every event that changes the record is anchored on-chain. prev_sig links each anchor
-- to the previous one for the same vehicle, so a removed event breaks the chain.
CREATE TABLE IF NOT EXISTS anchors (
  sig          TEXT PRIMARY KEY,
  vehicle_id   TEXT NOT NULL REFERENCES vehicles(id),
  type         TEXT NOT NULL,
  ref          TEXT,                      -- evidence id or custody id the anchor is about
  memo         TEXT NOT NULL,
  created_at   TEXT NOT NULL
);

-- Hash-chained audit log, including denied access attempts.
CREATE TABLE IF NOT EXISTS audit (
  id           INTEGER PRIMARY KEY,
  at           TEXT NOT NULL,
  actor        TEXT NOT NULL,
  action       TEXT NOT NULL,
  target       TEXT,
  outcome      TEXT NOT NULL,             -- ok | denied | error
  detail       TEXT,
  prev_hash    TEXT NOT NULL,
  hash         TEXT NOT NULL
);
`;

export function openDb(file = ':memory:') {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  return db;
}

export type Db = ReturnType<typeof openDb>;
