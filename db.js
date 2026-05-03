// db.js — PostgreSQL pool, encryption, and all database operations
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// ── PostgreSQL Pool ───────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err.message);
});

module.exports.pool = pool;

// ── Auto-initialize tables on startup ─────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
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
      CREATE TABLE IF NOT EXISTS session (
        sid    VARCHAR NOT NULL COLLATE "default",
        sess   JSON NOT NULL,
        expire TIMESTAMP(6) NOT NULL,
        CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE
      );
      CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
      CREATE INDEX IF NOT EXISTS idx_qbo_user_id ON qbo_connections (user_id);
    `);
    console.log('Database tables initialized.');
    // Seed admin account if env vars provided and admin doesn't exist
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPass  = process.env.ADMIN_PASSWORD;
    if (adminEmail && adminPass) {
      const existing = await client.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(adminPass, 10);
        await client.query(
          `INSERT INTO users (email, password_hash, role, company_name) VALUES ($1, $2, 'admin', 'Clear Books Advisory')`,
          [adminEmail, hash]
        );
        console.log(`Admin account created: ${adminEmail}`);
      }
    }
  } catch (err) {
    console.error('DB init error:', err.message);
  } finally {
    client.release();
  }
}

module.exports.ready = initDB();

// ── Encryption (AES-256-GCM) ──────────────────────────────────────────────────
const ALGO = 'aes-256-gcm';
const KEY  = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY || '', 'hex');

function encrypt(plaintext) {
  if (!plaintext) return null;
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Store as: iv(hex):tag(hex):ciphertext(hex)
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(stored) {
  if (!stored) return null;
  const [ivHex, tagHex, ctHex] = stored.split(':');
  const iv         = Buffer.from(ivHex, 'hex');
  const tag        = Buffer.from(tagHex, 'hex');
  const ciphertext = Buffer.from(ctHex, 'hex');
  const decipher   = crypto.createDecipheriv(ALGO, KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
}

module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;

// ── User Operations ───────────────────────────────────────────────────────────

async function createUser(email, password, role = 'client', companyName = null) {
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    `INSERT INTO users (email, password_hash, role, company_name)
     VALUES ($1, $2, $3, $4)
     RETURNING id, email, role, company_name, is_active, created_at`,
    [email.toLowerCase().trim(), hash, role, companyName]
  );
  return rows[0];
}

async function getUserByEmail(email) {
  const { rows } = await pool.query(
    `SELECT id, email, password_hash, role, company_name, is_active, last_login
     FROM users WHERE email = $1`,
    [email.toLowerCase().trim()]
  );
  return rows[0] || null;
}

async function getUserById(id) {
  const { rows } = await pool.query(
    `SELECT id, email, role, company_name, is_active, last_login, created_at
     FROM users WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

async function updateUserLastLogin(id) {
  await pool.query(
    `UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = $1`,
    [id]
  );
}

async function getAllClients() {
  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.role, u.company_name, u.is_active, u.last_login, u.created_at,
            q.realm_id, q.connected_at, q.last_refreshed, q.token_expires_at
     FROM users u
     LEFT JOIN qbo_connections q ON q.user_id = u.id
     WHERE u.role = 'client'
     ORDER BY u.company_name ASC, u.created_at DESC`
  );
  return rows;
}

async function updateUser(id, { companyName, email, isActive }) {
  const { rows } = await pool.query(
    `UPDATE users
     SET company_name = COALESCE($2, company_name),
         email        = COALESCE($3, email),
         is_active    = COALESCE($4, is_active),
         updated_at   = NOW()
     WHERE id = $1
     RETURNING id, email, role, company_name, is_active`,
    [id, companyName || null, email ? email.toLowerCase().trim() : null, isActive !== undefined ? isActive : null]
  );
  return rows[0] || null;
}

async function resetUserPassword(id, newPassword) {
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query(
    `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`,
    [id, hash]
  );
}

module.exports.createUser     = createUser;
module.exports.getUserByEmail = getUserByEmail;
module.exports.getUserById    = getUserById;
module.exports.updateUserLastLogin = updateUserLastLogin;
module.exports.getAllClients  = getAllClients;
module.exports.updateUser     = updateUser;
module.exports.resetUserPassword = resetUserPassword;

// ── QBO Token Operations ──────────────────────────────────────────────────────

async function saveQboTokens(userId, realmId, accessToken, refreshToken, expiresIn = 3600) {
  const expiresAt = new Date(Date.now() + expiresIn * 1000);
  await pool.query(
    `INSERT INTO qbo_connections (user_id, realm_id, access_token, refresh_token, token_expires_at)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id) DO UPDATE
     SET realm_id         = EXCLUDED.realm_id,
         access_token     = EXCLUDED.access_token,
         refresh_token    = EXCLUDED.refresh_token,
         token_expires_at = EXCLUDED.token_expires_at,
         last_refreshed   = NOW()`,
    [userId, realmId, encrypt(accessToken), encrypt(refreshToken), expiresAt]
  );
}

async function getQboConnection(userId) {
  const { rows } = await pool.query(
    `SELECT id, user_id, realm_id, access_token, refresh_token, token_expires_at, connected_at, last_refreshed
     FROM qbo_connections WHERE user_id = $1`,
    [userId]
  );
  if (!rows[0]) return null;
  const conn = rows[0];
  conn.access_token  = decrypt(conn.access_token);
  conn.refresh_token = decrypt(conn.refresh_token);
  return conn;
}

async function updateQboTokens(userId, accessToken, refreshToken, expiresIn = 3600) {
  const expiresAt = new Date(Date.now() + expiresIn * 1000);
  await pool.query(
    `UPDATE qbo_connections
     SET access_token     = $2,
         refresh_token    = $3,
         token_expires_at = $4,
         last_refreshed   = NOW()
     WHERE user_id = $1`,
    [userId, encrypt(accessToken), encrypt(refreshToken), expiresAt]
  );
}

async function deleteQboConnection(userId) {
  await pool.query(`DELETE FROM qbo_connections WHERE user_id = $1`, [userId]);
}

module.exports.saveQboTokens     = saveQboTokens;
module.exports.getQboConnection  = getQboConnection;
module.exports.updateQboTokens   = updateQboTokens;
module.exports.deleteQboConnection = deleteQboConnection;
