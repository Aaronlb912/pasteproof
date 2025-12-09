-- PasteProof Self-Hosted Backend Database Schema
-- This schema is for reference only - the self-hosted backend uses Cloudflare KV
-- If you want to use a traditional database instead of KV, you can adapt this schema

-- Note: Cloudflare Workers with KV doesn't require SQL, but this schema
-- can be used if you migrate to a different storage backend (e.g., PostgreSQL, SQLite)

-- Whitelist entries
CREATE TABLE IF NOT EXISTS site_whitelist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL DEFAULT 'single-user',
    domain VARCHAR(253) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_whitelist_user_id ON site_whitelist(user_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON site_whitelist(domain);

-- Custom patterns
CREATE TABLE IF NOT EXISTS custom_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL DEFAULT 'single-user',
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    pattern_type VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_patterns_user_id ON custom_patterns(user_id);
CREATE INDEX IF NOT EXISTS idx_patterns_active ON custom_patterns(user_id, is_active);

-- Detections log
CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL DEFAULT 'single-user',
    type VARCHAR(100) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL DEFAULT 'detected',
    metadata JSONB,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_detections_user_id ON detections(user_id);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detections_type ON detections(user_id, type);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL DEFAULT 'single-user',
    event_type VARCHAR(100) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    pii_type VARCHAR(100),
    was_anonymized BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(user_id, event_type);

