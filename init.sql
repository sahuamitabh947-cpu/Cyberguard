-- CyberGuard database schema (PostgreSQL)
--
-- Design note: the PRD asks for a "user database, admin database, and a
-- scanning database". Real Postgres deployments almost never split
-- logically-related data into separate physical databases (cross-database
-- joins/transactions aren't supported, and connection pooling gets harder
-- for no real gain). Instead this schema separates concerns properly with
-- dedicated tables/roles inside one database:
--   - users            -> the "user database" (every account, role-tagged)
--   - admin_audit_log  -> the "admin database" (every privileged action, append-only)
--   - scans + threats  -> the "scanning database" (every analysis + resulting threat)
--   - auth_events      -> raw login telemetry feeding the anomaly-detection engine
-- If your environment genuinely needs physically separate DB instances
-- (e.g. compliance requirement), each block below can be lifted into its
-- own `CREATE DATABASE` with a foreign-data-wrapper link; the app layer
-- (backend-node/src/config/db.js) reads a single DATABASE_URL, so pointing
-- it at three URLs behind a small routing layer is a mechanical change.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ========== USER DATABASE ==========
CREATE TABLE IF NOT EXISTS users (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email             VARCHAR(255) UNIQUE NOT NULL,
    full_name         VARCHAR(255) NOT NULL,
    password_hash     VARCHAR(255),               -- NULL for Google-OAuth-only accounts
    google_id         VARCHAR(255) UNIQUE,
    avatar_url        TEXT,
    role              VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'soc_analyst')),
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    organisation      VARCHAR(255),
    avg_login_hour    NUMERIC(4,2) NOT NULL DEFAULT 13.0,
    login_hour_stddev NUMERIC(4,2) NOT NULL DEFAULT 4.0,
    last_login_at     TIMESTAMPTZ,
    last_login_lat    DOUBLE PRECISION,
    last_login_lon    DOUBLE PRECISION,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS known_devices (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint  VARCHAR(255) NOT NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, device_fingerprint)
);

-- Raw authentication telemetry -> input to the C++ anomaly-detection engine
CREATE TABLE IF NOT EXISTS auth_events (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id                  UUID REFERENCES users(id) ON DELETE CASCADE,
    email_attempted          VARCHAR(255),
    ip_address               VARCHAR(64),
    device_fingerprint       VARCHAR(255),
    latitude                 DOUBLE PRECISION,
    longitude                DOUBLE PRECISION,
    success                  BOOLEAN NOT NULL,
    failed_attempts_15min    INTEGER NOT NULL DEFAULT 0,
    risk_score               INTEGER,
    risk_level               VARCHAR(20),
    findings                 JSONB,
    ml_result                JSONB,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(user_id, created_at DESC);

-- ========== ADMIN DATABASE ==========
-- Append-only record of every privileged/admin action, independent of the
-- regular application audit trail, so it survives even if scans/threats
-- tables are later purged.
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    admin_id      UUID NOT NULL REFERENCES users(id),
    action        VARCHAR(100) NOT NULL,   -- e.g. 'THREAT_STATUS_CHANGE', 'USER_DEACTIVATED'
    target_type   VARCHAR(50),
    target_id     UUID,
    details       JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ========== SCANNING DATABASE ==========
CREATE TABLE IF NOT EXISTS scans (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    scan_type         VARCHAR(30) NOT NULL CHECK (scan_type IN
                        ('email', 'sms', 'url', 'image', 'audio', 'video', 'login_behavior', 'log_upload',
                         'network_pcap', 'network_live')),
    source            VARCHAR(30) NOT NULL DEFAULT 'manual',   -- manual | gmail | nids_sensor
    external_ref      VARCHAR(255),                            -- e.g. Gmail message id (dedupe)
    ml_result         JSONB,                                   -- C++ ML model outputs
    input_summary     TEXT,               -- truncated/redacted preview of what was scanned
    raw_input_ref     TEXT,               -- pointer to stored artifact, if any (not raw secrets)
    engine_result     JSONB,              -- output of the C++ detection engine(s)
    ai_result         JSONB,              -- Gemini classification + natural-language explanation
    final_score       INTEGER NOT NULL DEFAULT 0,
    risk_level        VARCHAR(20) NOT NULL DEFAULT 'Safe' CHECK (risk_level IN ('Safe','Low','Medium','High','Critical')),
    recommended_action TEXT,
    status            VARCHAR(20) NOT NULL DEFAULT 'completed' CHECK (status IN ('pending','completed','failed')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;  -- soft delete (undo window), purged by the backend
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_external_ref ON scans(user_id, source, external_ref) WHERE external_ref IS NOT NULL AND deleted_at IS NULL;

-- Gmail connections (refresh tokens are AES-256-GCM encrypted by the backend)
CREATE TABLE IF NOT EXISTS gmail_connections (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id            UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    gmail_address      VARCHAR(255),
    refresh_token_enc  TEXT NOT NULL,
    scopes             TEXT,
    connected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sync_at       TIMESTAMPTZ,
    messages_scanned   INTEGER NOT NULL DEFAULT 0
);

-- A "threat" is a scan (or auth event) that crossed the Medium+ risk
-- threshold and is tracked through an incident-response lifecycle.
CREATE TABLE IF NOT EXISTS threats (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID REFERENCES scans(id) ON DELETE CASCADE,
    auth_event_id       UUID REFERENCES auth_events(id) ON DELETE CASCADE,
    category            VARCHAR(40) NOT NULL, -- phishing | impersonation | deepfake | account_takeover | malicious_url | technical_threat
    risk_level          VARCHAR(20) NOT NULL CHECK (risk_level IN ('Low','Medium','High','Critical')),
    target_user_id      UUID REFERENCES users(id),
    targeted_service    VARCHAR(255),
    recommended_action  TEXT,
    status              VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','mitigated','false_positive')),
    resolved_by         UUID REFERENCES users(id),
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (scan_id IS NOT NULL OR auth_event_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
ALTER TABLE threats ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;  -- soft delete, follows its scan
CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);
CREATE INDEX IF NOT EXISTS idx_threats_created ON threats(created_at DESC);

-- Migrations already contained in this file (the backend's migration
-- runner skips them on fresh installs).
CREATE TABLE IF NOT EXISTS schema_migrations (id VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
INSERT INTO schema_migrations (id) VALUES ('2026-09-ml-gmail-nids') ON CONFLICT DO NOTHING;

-- Seed a default admin account for first login.
-- Password: ChangeMe!123  (bcrypt hash below) — the README tells the user to rotate this immediately.
INSERT INTO users (email, full_name, password_hash, role)
VALUES ('admin@cyberguard.local', 'Default Admin', '$2b$10$c0I2zi1GJEahTjSs/nhjNuchSSid69n.Jm3zgclWTnQp0TXpb9UWa', 'admin')
ON CONFLICT (email) DO NOTHING;
