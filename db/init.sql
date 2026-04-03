-- CFO Dashboard Portal — Database Initialization
-- Run this once against Railway PostgreSQL after adding the plugin

-- Users table (admin + clients)
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(20) NOT NULL DEFAULT 'client' CHECK (role IN ('admin', 'client')),
  company_name  VARCHAR(255),
  is_active     BOOLEAN DEFAULT true,
  last_login    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- QBO connections (one per user, encrypted tokens)
CREATE TABLE IF NOT EXISTS qbo_connections (
  id               SERIAL PRIMARY KEY,
  user_id          INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  realm_id         VARCHAR(50) NOT NULL,
  access_token     TEXT NOT NULL,
  refresh_token    TEXT NOT NULL,
  token_expires_at TIMESTAMPTZ,
  connected_at     TIMESTAMPTZ DEFAULT NOW(),
  last_refreshed   TIMESTAMPTZ DEFAULT NOW()
);

-- Session table (managed by connect-pg-simple)
CREATE TABLE IF NOT EXISTS session (
  sid    VARCHAR NOT NULL COLLATE "default",
  sess   JSON NOT NULL,
  expire TIMESTAMP(6) NOT NULL,
  CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_qbo_user_id ON qbo_connections (user_id);
