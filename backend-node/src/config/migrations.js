// Idempotent schema migrations, applied at backend start-up.
// database/init.sql only runs when the Postgres volume is created for the
// first time, so existing installs (e.g. an already-running Docker volume)
// get new tables/columns from here. Every statement is safe to re-run.
const sequelize = require('./db');

const MIGRATIONS = [
  {
    id: '2026-09-ml-gmail-nids',
    statements: [
      `ALTER TABLE scans ADD COLUMN IF NOT EXISTS source VARCHAR(30) NOT NULL DEFAULT 'manual'`,
      `ALTER TABLE scans ADD COLUMN IF NOT EXISTS external_ref VARCHAR(255)`,
      `ALTER TABLE scans ADD COLUMN IF NOT EXISTS ml_result JSONB`,
      `ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_scan_type_check`,
      `ALTER TABLE scans ADD CONSTRAINT scans_scan_type_check CHECK (scan_type IN
         ('email','sms','url','image','audio','video','login_behavior','log_upload','network_pcap','network_live'))`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_external_ref ON scans(user_id, source, external_ref) WHERE external_ref IS NOT NULL`,
      `CREATE TABLE IF NOT EXISTS gmail_connections (
         id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
         user_id            UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
         gmail_address      VARCHAR(255),
         refresh_token_enc  TEXT NOT NULL,
         scopes             TEXT,
         connected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
         last_sync_at       TIMESTAMPTZ,
         messages_scanned   INTEGER NOT NULL DEFAULT 0
       )`,
      `ALTER TABLE auth_events ADD COLUMN IF NOT EXISTS ml_result JSONB`,
    ],
  },
  {
    id: '2026-09-soft-delete-history',
    statements: [
      `ALTER TABLE scans ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
      `ALTER TABLE threats ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
      `CREATE INDEX IF NOT EXISTS idx_scans_deleted_at ON scans(deleted_at) WHERE deleted_at IS NOT NULL`,
      // A deleted Gmail scan must not block re-scanning the same message later.
      `DROP INDEX IF EXISTS idx_scans_external_ref`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_external_ref ON scans(user_id, source, external_ref) WHERE external_ref IS NOT NULL AND deleted_at IS NULL`,
    ],
  },
];

async function runMigrations() {
  await sequelize.query(`CREATE TABLE IF NOT EXISTS schema_migrations (id VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  for (const m of MIGRATIONS) {
    const [rows] = await sequelize.query('SELECT 1 FROM schema_migrations WHERE id = :id', { replacements: { id: m.id } });
    if (rows.length) continue;
    for (const sql of m.statements) await sequelize.query(sql);
    await sequelize.query('INSERT INTO schema_migrations (id) VALUES (:id)', { replacements: { id: m.id } });
    console.log(`[db] applied migration ${m.id}`);
  }
}

module.exports = { runMigrations };
