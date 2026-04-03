require('dotenv').config();
const express      = require('express');
const session      = require('express-session');
const pgSession    = require('connect-pg-simple')(session);
const axios        = require('axios');
const bcrypt       = require('bcrypt');
const path         = require('path');
const db           = require('./db');
const { requireAuth, requireAdmin, getTargetUserId } = require('./middleware');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Session (PostgreSQL-backed) ───────────────────────────────────────────────
app.use(session({
  store: new pgSession({
    pool: db.pool,
    tableName: 'session',
    createTableIfMissing: false
  }),
  secret:            process.env.SESSION_SECRET || 'cfo-portal-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

app.use(express.json());

// ── Protect HTML pages ────────────────────────────────────────────────────────
app.use('/dashboard.html', (req, res, next) => {
  if (!req.session.userId) return res.redirect('/login.html');
  next();
});
app.use('/admin.html', (req, res, next) => {
  if (!req.session.userId) return res.redirect('/login.html');
  if (req.session.userRole !== 'admin') return res.redirect('/dashboard.html');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── QBO Config ────────────────────────────────────────────────────────────────
const QBO_CLIENT_ID     = process.env.QBO_CLIENT_ID;
const QBO_CLIENT_SECRET = process.env.QBO_CLIENT_SECRET;
const REDIRECT_URI      = process.env.REDIRECT_URI;
const QBO_ENV           = process.env.QBO_ENVIRONMENT || 'sandbox';

const AUTH_ENDPOINT  = 'https://appcenter.intuit.com/connect/oauth2';
const TOKEN_ENDPOINT = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
const API_BASE       = QBO_ENV === 'production'
  ? 'https://quickbooks.api.intuit.com'
  : 'https://sandbox-quickbooks.api.intuit.com';

const SCOPES = 'com.intuit.quickbooks.accounting';

// ── Auth Routes ───────────────────────────────────────────────────────────────

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const user = await db.getUserByEmail(email);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (!user.is_active) return res.status(403).json({ error: 'Account is deactivated' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    // Store user info in session
    req.session.userId      = user.id;
    req.session.userRole    = user.role;
    req.session.userIsActive = user.is_active;

    await db.updateUserLastLogin(user.id);

    res.json({
      success: true,
      role: user.role,
      redirect: user.role === 'admin' ? '/admin.html' : '/dashboard.html'
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Current user info
app.get('/api/auth/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const conn = await db.getQboConnection(req.session.userId);
    const impersonating = req.session.userRole === 'admin' && !!req.session.viewingAsUserId;
    let viewingAs = null;
    if (impersonating) {
      viewingAs = await db.getUserById(req.session.viewingAsUserId);
      const viewingConn = await db.getQboConnection(req.session.viewingAsUserId);
      return res.json({
        id: user.id, email: user.email, role: user.role,
        companyName: user.company_name,
        qboConnected: !!conn,
        impersonating: true,
        viewingAs: {
          id: viewingAs.id,
          companyName: viewingAs.company_name,
          email: viewingAs.email,
          qboConnected: !!viewingConn
        }
      });
    }

    res.json({
      id: user.id, email: user.email, role: user.role,
      companyName: user.company_name,
      qboConnected: !!conn,
      impersonating: false
    });
  } catch (err) {
    console.error('Me error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── QBO OAuth ─────────────────────────────────────────────────────────────────

// Start OAuth — requires login, encodes userId + nonce in state
app.get('/auth', requireAuth, (req, res) => {
  const targetUserId = getTargetUserId(req);
  const nonce = require('crypto').randomBytes(16).toString('hex');
  req.session.oauthNonce = nonce;

  const state = Buffer.from(JSON.stringify({ userId: targetUserId, nonce })).toString('base64');
  const params = new URLSearchParams({
    client_id:     QBO_CLIENT_ID,
    response_type: 'code',
    scope:         SCOPES,
    redirect_uri:  REDIRECT_URI,
    state
  });
  res.redirect(`${AUTH_ENDPOINT}?${params.toString()}`);
});

// OAuth callback
app.get('/callback', async (req, res) => {
  const { code, realmId, state } = req.query;
  if (!code || !realmId || !state) return res.status(400).send('Missing OAuth parameters');

  try {
    // Decode and validate state
    const { userId, nonce } = JSON.parse(Buffer.from(state, 'base64').toString('utf8'));
    if (nonce !== req.session.oauthNonce) return res.status(400).send('Invalid OAuth state — please try again');
    delete req.session.oauthNonce;

    // Exchange code for tokens
    const credentials = Buffer.from(`${QBO_CLIENT_ID}:${QBO_CLIENT_SECRET}`).toString('base64');
    const response = await axios.post(TOKEN_ENDPOINT,
      new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI }),
      { headers: { 'Authorization': `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, expires_in } = response.data;
    await db.saveQboTokens(userId, realmId, access_token, refresh_token, expires_in || 3600);

    res.redirect('/dashboard.html');
  } catch (err) {
    console.error('OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('OAuth failed: ' + JSON.stringify(err.response?.data || err.message));
  }
});

// Disconnect QBO (removes connection for target user)
app.post('/api/disconnect', requireAuth, async (req, res) => {
  const targetUserId = getTargetUserId(req);
  await db.deleteQboConnection(targetUserId);
  res.json({ success: true });
});

// ── Token Refresh Helper ──────────────────────────────────────────────────────
async function getAccessToken(userId) {
  const conn = await db.getQboConnection(userId);
  if (!conn) throw new Error('No QBO connection for this user');

  const credentials = Buffer.from(`${QBO_CLIENT_ID}:${QBO_CLIENT_SECRET}`).toString('base64');
  try {
    const response = await axios.post(TOKEN_ENDPOINT,
      new URLSearchParams({ grant_type: 'refresh_token', refresh_token: conn.refresh_token }),
      { headers: { 'Authorization': `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = response.data;
    await db.updateQboTokens(userId, access_token, refresh_token, expires_in || 3600);
    return access_token;
  } catch {
    return conn.access_token; // Fall back to stored token if refresh fails
  }
}

// ── QBO Report Helper ─────────────────────────────────────────────────────────
async function fetchReport(userId, realmId, reportType, params) {
  const token = await getAccessToken(userId);
  const url = `${API_BASE}/v3/company/${realmId}/reports/${reportType}`;
  const response = await axios.get(url, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
    params
  });
  return response.data;
}

async function qboQuery(userId, realmId, query) {
  const token = await getAccessToken(userId);
  const url = `${API_BASE}/v3/company/${realmId}/query`;
  const response = await axios.get(url, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
    params: { query }
  });
  return response.data;
}

// ── Data API Routes (multi-tenant) ────────────────────────────────────────────

// Get connection for target user, return 401 if not connected
async function getConn(req, res) {
  const userId = getTargetUserId(req);
  const conn = await db.getQboConnection(userId);
  if (!conn) { res.status(401).json({ error: 'QBO not connected' }); return null; }
  return { userId, conn };
}

app.get('/api/company-info', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const { userId, conn } = target;
    const token = await getAccessToken(userId);
    const url = `${API_BASE}/v3/company/${conn.realm_id}/companyinfo/${conn.realm_id}`;
    const response = await axios.get(url, {
      headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
    });
    const info = response.data.CompanyInfo;
    res.json({
      companyName: info.CompanyName,
      legalName:   info.LegalName,
      country:     info.Country,
      email:       info.Email?.Address || null,
      phone:       info.PrimaryPhone?.FreeFormNumber || null
    });
  } catch (err) {
    console.error('Company info error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

app.get('/api/pnl', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const { start_date, end_date } = req.query;
    const data = await fetchReport(target.userId, target.conn.realm_id, 'ProfitAndLoss', {
      start_date: start_date || firstDayOfYear(),
      end_date:   end_date   || today(),
      summarize_column_by: 'Month',
      accounting_method: 'Accrual'
    });
    res.json(data);
  } catch (err) {
    console.error('P&L error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

app.get('/api/balance-sheet', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const { as_of_date } = req.query;
    const data = await fetchReport(target.userId, target.conn.realm_id, 'BalanceSheet', {
      start_date: firstDayOfYear(),
      end_date:   as_of_date || today(),
      summarize_column_by: 'Month',
      accounting_method: 'Accrual'
    });
    res.json(data);
  } catch (err) {
    console.error('Balance Sheet error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

app.get('/api/ar-aging', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const { as_of_date } = req.query;
    const data = await fetchReport(target.userId, target.conn.realm_id, 'AgedReceivables', {
      end_date:   as_of_date || today(),
      start_date: firstDayOfYear(),
      aging_period: 30, num_periods: 4, accounting_method: 'Accrual'
    });
    res.json(data);
  } catch (err) {
    console.error('AR Aging error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

app.get('/api/ap-aging', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const { as_of_date } = req.query;
    const data = await fetchReport(target.userId, target.conn.realm_id, 'AgedPayables', {
      end_date:   as_of_date || today(),
      start_date: firstDayOfYear(),
      aging_period: 30, num_periods: 4, accounting_method: 'Accrual'
    });
    res.json(data);
  } catch (err) {
    console.error('AP Aging error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

app.get('/api/vendor-spend', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const { start_date, end_date } = req.query;
    const data = await fetchReport(target.userId, target.conn.realm_id, 'PurchaseByVendor', {
      start_date: start_date || firstDayOfYear(),
      end_date:   end_date   || today(),
      summarize_column_by: 'Total'
    });
    res.json(data);
  } catch (err) {
    console.error('Vendor spend error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ── Admin Routes ──────────────────────────────────────────────────────────────

// List all clients
app.get('/api/admin/clients', requireAdmin, async (req, res) => {
  try {
    const clients = await db.getAllClients();
    // Strip out encrypted token fields, just expose metadata
    const safe = clients.map(c => ({
      id:           c.id,
      email:        c.email,
      companyName:  c.company_name,
      isActive:     c.is_active,
      lastLogin:    c.last_login,
      createdAt:    c.created_at,
      qboConnected: !!c.realm_id,
      qboRealmId:   c.realm_id || null,
      qboConnectedAt: c.connected_at || null,
      qboLastRefreshed: c.last_refreshed || null,
      qboTokenExpiresAt: c.token_expires_at || null
    }));
    res.json(safe);
  } catch (err) {
    console.error('List clients error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create client
app.post('/api/admin/clients', requireAdmin, async (req, res) => {
  const { email, password, companyName } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const user = await db.createUser(email, password, 'client', companyName || null);
    res.status(201).json({ success: true, user });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    console.error('Create client error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update client
app.put('/api/admin/clients/:id', requireAdmin, async (req, res) => {
  const { companyName, email, isActive } = req.body;
  try {
    const user = await db.updateUser(parseInt(req.params.id), { companyName, email, isActive });
    if (!user) return res.status(404).json({ error: 'Client not found' });
    res.json({ success: true, user });
  } catch (err) {
    console.error('Update client error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Reset client password
app.post('/api/admin/clients/:id/reset-password', requireAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    await db.resetUserPassword(parseInt(req.params.id), newPassword);
    res.json({ success: true });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Disconnect client's QBO (admin only)
app.delete('/api/admin/clients/:id/qbo', requireAdmin, async (req, res) => {
  try {
    await db.deleteQboConnection(parseInt(req.params.id));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Impersonate a client
app.post('/api/admin/impersonate/:id', requireAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    const client = await db.getUserById(clientId);
    if (!client) return res.status(404).json({ error: 'Client not found' });
    if (client.role === 'admin') return res.status(400).json({ error: 'Cannot impersonate admin' });
    req.session.viewingAsUserId = clientId;
    res.json({ success: true, redirect: '/dashboard.html' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stop impersonation
app.post('/api/admin/stop-impersonation', requireAdmin, (req, res) => {
  delete req.session.viewingAsUserId;
  res.json({ success: true, redirect: '/admin.html' });
});

// ── Date Helpers ──────────────────────────────────────────────────────────────
function today() { return new Date().toISOString().split('T')[0]; }
function firstDayOfYear() { return `${new Date().getFullYear()}-01-01`; }

// ── Start Server (wait for DB tables to be ready) ────────────────────────────
db.ready.then(() => {
  app.listen(PORT, () => {
    console.log(`CFO Dashboard Portal running on port ${PORT}`);
    console.log(`QBO Environment: ${QBO_ENV}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err.message);
  process.exit(1);
});
