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
      CREATE TABLE IF NOT EXISTS bank_recs (
        id                 SERIAL PRIMARY KEY,
        user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        realm_id           VARCHAR(50) NOT NULL,
        bank_account_id    VARCHAR(50) NOT NULL,
        bank_account_name  VARCHAR(255),
        period_start       DATE NOT NULL,
        period_end         DATE NOT NULL,
        beginning_balance  NUMERIC(14,2) NOT NULL DEFAULT 0,
        ending_balance     NUMERIC(14,2) NOT NULL DEFAULT 0,
        cleared_txn_ids    JSONB NOT NULL DEFAULT '[]'::jsonb,
        notes              TEXT NOT NULL DEFAULT '',
        status             VARCHAR(20) NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'finalized')),
        created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        finalized_at       TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS push_history (
        id              SERIAL PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        realm_id        VARCHAR(50) NOT NULL,
        hash            VARCHAR(32) NOT NULL,
        entity_type     VARCHAR(40) NOT NULL,
        entity_id       VARCHAR(50) NOT NULL,
        bank_account_id VARCHAR(50) NOT NULL,
        txn_date        DATE NOT NULL,
        amount          NUMERIC(14,2) NOT NULL,
        description     TEXT,
        pushed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
      CREATE INDEX IF NOT EXISTS idx_qbo_user_id ON qbo_connections (user_id);
      CREATE INDEX IF NOT EXISTS idx_bank_recs_user ON bank_recs (user_id);
      CREATE INDEX IF NOT EXISTS idx_bank_recs_period ON bank_recs (user_id, period_end DESC);
      CREATE INDEX IF NOT EXISTS idx_push_history_user_hash ON push_history (user_id, hash);
      CREATE INDEX IF NOT EXISTS idx_push_history_user_bank_date ON push_history (user_id, bank_account_id, txn_date);
    `);
    console.log('Database tables initialized.');
    // Seed or sync admin account from env vars
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPass  = process.env.ADMIN_PASSWORD;
    if (adminEmail && adminPass) {
      const existing = await client.query('SELECT id, password_hash FROM users WHERE email = $1', [adminEmail]);
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(adminPass, 10);
        await client.query(
          `INSERT INTO users (email, password_hash, role, company_name) VALUES ($1, $2, 'admin', 'Clear Books Advisory')`,
          [adminEmail, hash]
        );
        console.log(`Admin account created: ${adminEmail}`);
      } else {
        // Sync password if env var changed since last deploy
        const match = await bcrypt.compare(adminPass, existing.rows[0].password_hash);
        if (!match) {
          const hash = await bcrypt.hash(adminPass, 10);
          await client.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [hash, existing.rows[0].id]);
          console.log('Admin password synced from env var');
        }
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

// ── Bank Rec Operations ───────────────────────────────────────────────────────

function rowToBankRec(row) {
  if (!row) return null;
  return {
    id:               row.id,
    realmId:          row.realm_id,
    bankAccountId:    row.bank_account_id,
    bankAccountName:  row.bank_account_name,
    periodStart:      row.period_start instanceof Date ? row.period_start.toISOString().slice(0,10) : row.period_start,
    periodEnd:        row.period_end   instanceof Date ? row.period_end.toISOString().slice(0,10)   : row.period_end,
    beginningBalance: Number(row.beginning_balance),
    endingBalance:    Number(row.ending_balance),
    clearedTxnIds:    Array.isArray(row.cleared_txn_ids) ? row.cleared_txn_ids : (row.cleared_txn_ids || []),
    notes:            row.notes || '',
    status:           row.status,
    createdAt:        row.created_at,
    updatedAt:        row.updated_at,
    finalizedAt:      row.finalized_at
  };
}

async function listBankRecs(userId) {
  const { rows } = await pool.query(
    `SELECT * FROM bank_recs WHERE user_id = $1 ORDER BY period_end DESC, id DESC`,
    [userId]
  );
  return rows.map(rowToBankRec);
}

async function getBankRec(userId, id) {
  const { rows } = await pool.query(
    `SELECT * FROM bank_recs WHERE user_id = $1 AND id = $2`,
    [userId, id]
  );
  return rowToBankRec(rows[0]);
}

// Upsert: id present → update (rejects if row is finalized); id absent → insert.
// Sets finalized_at when status transitions to 'finalized'.
async function saveBankRec(userId, realmId, payload) {
  const {
    id, bankAccountId, bankAccountName, periodStart, periodEnd,
    beginningBalance, endingBalance, clearedTxnIds, notes, status
  } = payload;
  const cleared = JSON.stringify(Array.isArray(clearedTxnIds) ? clearedTxnIds : []);
  const safeStatus = status === 'finalized' ? 'finalized' : 'in_progress';

  if (id) {
    // Verify ownership + not finalized before updating
    const existing = await getBankRec(userId, id);
    if (!existing) return { error: 'Not found' };
    if (existing.status === 'finalized') {
      return { error: 'This reconciliation is finalized and read-only. Discard or create a new rec to make changes.' };
    }
    const finalizedClause = (safeStatus === 'finalized')
      ? 'finalized_at = COALESCE(finalized_at, NOW())'
      : 'finalized_at = finalized_at';
    const { rows } = await pool.query(
      `UPDATE bank_recs
       SET bank_account_id    = $3,
           bank_account_name  = $4,
           period_start       = $5,
           period_end         = $6,
           beginning_balance  = $7,
           ending_balance     = $8,
           cleared_txn_ids    = $9::jsonb,
           notes              = $10,
           status             = $11,
           updated_at         = NOW(),
           ${finalizedClause}
       WHERE user_id = $1 AND id = $2
       RETURNING *`,
      [userId, id, bankAccountId, bankAccountName || null, periodStart, periodEnd,
       Number(beginningBalance || 0), Number(endingBalance || 0), cleared,
       notes || '', safeStatus]
    );
    return { session: rowToBankRec(rows[0]) };
  } else {
    const { rows } = await pool.query(
      `INSERT INTO bank_recs
         (user_id, realm_id, bank_account_id, bank_account_name, period_start, period_end,
          beginning_balance, ending_balance, cleared_txn_ids, notes, status, finalized_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11,
               CASE WHEN $11 = 'finalized' THEN NOW() ELSE NULL END)
       RETURNING *`,
      [userId, realmId, bankAccountId, bankAccountName || null, periodStart, periodEnd,
       Number(beginningBalance || 0), Number(endingBalance || 0), cleared,
       notes || '', safeStatus]
    );
    return { session: rowToBankRec(rows[0]) };
  }
}

async function deleteBankRec(userId, id) {
  const existing = await getBankRec(userId, id);
  if (!existing) return { error: 'Not found' };
  if (existing.status === 'finalized') return { error: 'Cannot delete a finalized rec' };
  await pool.query(`DELETE FROM bank_recs WHERE user_id = $1 AND id = $2`, [userId, id]);
  return { success: true };
}

module.exports.listBankRecs  = listBankRecs;
module.exports.getBankRec    = getBankRec;
module.exports.saveBankRec   = saveBankRec;
module.exports.deleteBankRec = deleteBankRec;

// ── Push History Operations ───────────────────────────────────────────────────
// Used by Categorize Bank for layer-3 dedup + reconciliation against QBO actuals.

function txnHash(realmId, bankAccountId, txnDate, amount, description) {
  const normDesc = String(description || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const key = `${realmId}|${bankAccountId}|${txnDate}|${Math.abs(Number(amount)).toFixed(2)}|${normDesc}`;
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}

async function findPushedTxn(userId, realmId, bankAccountId, txnDate, amount, description) {
  const hash = txnHash(realmId, bankAccountId, txnDate, amount, description);
  const { rows } = await pool.query(
    `SELECT id, hash, entity_type, entity_id, bank_account_id, txn_date, amount, description, pushed_at
     FROM push_history WHERE user_id = $1 AND hash = $2 LIMIT 1`,
    [userId, hash]
  );
  if (!rows[0]) return null;
  const r = rows[0];
  return {
    hash: r.hash,
    entityType: r.entity_type,
    entityId: r.entity_id,
    bankAccountId: r.bank_account_id,
    txnDate: r.txn_date instanceof Date ? r.txn_date.toISOString().slice(0,10) : r.txn_date,
    amount: Number(r.amount),
    description: r.description,
    pushedAt: r.pushed_at
  };
}

async function recordPush(userId, realmId, { bankAccountId, entityType, entityId, txnDate, amount, description }) {
  const hash = txnHash(realmId, bankAccountId, txnDate, amount, description);
  await pool.query(
    `INSERT INTO push_history
       (user_id, realm_id, hash, entity_type, entity_id, bank_account_id, txn_date, amount, description)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [userId, realmId, hash, entityType, String(entityId), String(bankAccountId), txnDate, Number(amount), description || '']
  );
  return hash;
}

// List push history for a user in an optional bank/date window. Used by /api/reconcile.
async function listPushHistory(userId, bankAccountId, startDate, endDate) {
  const params = [userId];
  let where = `user_id = $1`;
  if (bankAccountId) { params.push(String(bankAccountId)); where += ` AND bank_account_id = $${params.length}`; }
  if (startDate)     { params.push(startDate);              where += ` AND txn_date >= $${params.length}`; }
  if (endDate)       { params.push(endDate);                where += ` AND txn_date <= $${params.length}`; }
  const { rows } = await pool.query(
    `SELECT hash, entity_type, entity_id, bank_account_id, txn_date, amount, description, pushed_at
     FROM push_history WHERE ${where} ORDER BY txn_date ASC`,
    params
  );
  return rows.map(r => ({
    hash: r.hash,
    entityType: r.entity_type,
    entityId: r.entity_id,
    bankAccountId: r.bank_account_id,
    txnDate: r.txn_date instanceof Date ? r.txn_date.toISOString().slice(0,10) : r.txn_date,
    amount: Number(r.amount),
    description: r.description,
    pushedAt: r.pushed_at
  }));
}

module.exports.txnHash         = txnHash;
module.exports.findPushedTxn   = findPushedTxn;
module.exports.recordPush      = recordPush;
module.exports.listPushHistory = listPushHistory;
