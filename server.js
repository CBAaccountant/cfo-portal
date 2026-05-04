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

// Trust Railway's proxy so secure cookies work over HTTPS
app.set('trust proxy', 1);

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

async function qboCreate(userId, realmId, entityType, payload) {
  const token = await getAccessToken(userId);
  const url = `${API_BASE}/v3/company/${realmId}/${entityType}`;
  const response = await axios.post(url, payload, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept':        'application/json',
      'Content-Type':  'application/json'
    }
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

// ── Bank Rec ──────────────────────────────────────────────────────────────────

// Bank-type accounts for the dropdown (Bank + Credit Card)
app.get('/api/bank-accounts', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const data = await qboQuery(target.userId, target.conn.realm_id,
      `SELECT Id, Name, FullyQualifiedName, AccountType, AccountSubType, CurrentBalance FROM Account WHERE AccountType IN ('Bank', 'Credit Card') AND Active = true MAXRESULTS 200`
    );
    const accounts = (data.QueryResponse?.Account || []).map(a => ({
      Id:                 a.Id,
      Name:               a.Name,
      FullyQualifiedName: a.FullyQualifiedName,
      AccountType:        a.AccountType,
      AccountSubType:     a.AccountSubType,
      CurrentBalance:     Number(a.CurrentBalance || 0)
    }));
    res.json({ count: accounts.length, accounts });
  } catch (err) {
    console.error('Bank accounts error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Transactions hitting the chosen bank account in the period (Purchase + Deposit).
// Each row: { id, type, qboType, date, amount (signed), description, vendor, docNumber }
app.get('/api/bank-rec/transactions', requireAuth, async (req, res) => {
  const { bankAccountId, start, end } = req.query;
  if (!bankAccountId) return res.status(400).json({ error: 'bankAccountId required' });
  if (!start || !end) return res.status(400).json({ error: 'start + end (YYYY-MM-DD) required' });
  try {
    const target = await getConn(req, res); if (!target) return;
    const userId = target.userId;
    const realmId = target.conn.realm_id;

    const purchasesData = await qboQuery(userId, realmId,
      `SELECT * FROM Purchase WHERE TxnDate >= '${start}' AND TxnDate <= '${end}' MAXRESULTS 1000`
    );
    const depositsData = await qboQuery(userId, realmId,
      `SELECT * FROM Deposit WHERE TxnDate >= '${start}' AND TxnDate <= '${end}' MAXRESULTS 1000`
    );
    const purchases = purchasesData.QueryResponse?.Purchase || [];
    const deposits  = depositsData.QueryResponse?.Deposit  || [];

    const txns = [];
    for (const p of purchases) {
      if (String(p.AccountRef?.value) !== String(bankAccountId)) continue;
      txns.push({
        id: p.Id,
        type: p.PaymentType === 'Check' ? 'Check' : (p.PaymentType === 'CreditCard' ? 'CC Charge' : 'Expense'),
        qboType: 'Purchase',
        date: p.TxnDate,
        amount: -Math.abs(Number(p.TotalAmt || 0)),
        description: p.PrivateNote || '',
        vendor: p.EntityRef?.name || '',
        docNumber: p.DocNumber || ''
      });
    }
    for (const d of deposits) {
      if (String(d.DepositToAccountRef?.value) !== String(bankAccountId)) continue;
      const firstLine = (d.Line || [])[0];
      txns.push({
        id: d.Id,
        type: 'Deposit',
        qboType: 'Deposit',
        date: d.TxnDate,
        amount: +Math.abs(Number(d.TotalAmt || 0)),
        description: d.PrivateNote || firstLine?.Description || '',
        vendor: firstLine?.DepositLineDetail?.Entity?.name || '',
        docNumber: d.DocNumber || ''
      });
    }
    txns.sort((a, b) => a.date.localeCompare(b.date));
    res.json({ count: txns.length, transactions: txns });
  } catch (err) {
    console.error('Bank rec transactions error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// List saved rec sessions for the current target user
app.get('/api/bank-rec/sessions', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const sessions = await db.listBankRecs(target.userId);
    res.json({ count: sessions.length, sessions });
  } catch (err) {
    console.error('Bank rec list error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get a specific rec session (scoped to current target user)
app.get('/api/bank-rec/session/:id', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    const session = await db.getBankRec(target.userId, id);
    if (!session) return res.status(404).json({ error: 'Not found' });
    res.json(session);
  } catch (err) {
    console.error('Bank rec get error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create or update a rec session
// Body: { id?, bankAccountId, bankAccountName, periodStart, periodEnd, beginningBalance, endingBalance, clearedTxnIds, notes, status }
app.post('/api/bank-rec/session', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const body = req.body || {};
    if (!body.bankAccountId || !body.periodStart || !body.periodEnd) {
      return res.status(400).json({ error: 'bankAccountId, periodStart, periodEnd required' });
    }
    const payload = { ...body };
    if (payload.id != null) {
      const idNum = parseInt(payload.id, 10);
      if (!Number.isFinite(idNum)) return res.status(400).json({ error: 'Invalid id' });
      payload.id = idNum;
    }
    const result = await db.saveBankRec(target.userId, target.conn.realm_id, payload);
    if (result.error) return res.status(400).json({ error: result.error });
    res.json({ success: true, session: result.session });
  } catch (err) {
    console.error('Bank rec save error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Discard an in-progress rec (finalized recs are protected)
app.delete('/api/bank-rec/session/:id', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    const result = await db.deleteBankRec(target.userId, id);
    if (result.error) return res.status(result.error === 'Not found' ? 404 : 400).json({ error: result.error });
    res.json({ success: true });
  } catch (err) {
    console.error('Bank rec delete error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Categorize Bank ───────────────────────────────────────────────────────────

// All QBO accounts (full chart). Categorize uses this for the category dropdown.
app.get('/api/accounts', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const data = await qboQuery(target.userId, target.conn.realm_id,
      'SELECT * FROM Account MAXRESULTS 1000'
    );
    res.json(data);
  } catch (err) {
    console.error('Accounts error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// All vendors
app.get('/api/vendors', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const data = await qboQuery(target.userId, target.conn.realm_id,
      'SELECT * FROM Vendor MAXRESULTS 1000'
    );
    const vendors = (data.QueryResponse?.Vendor || []).map(v => ({
      id:          v.Id,
      displayName: v.DisplayName,
      companyName: v.CompanyName || null,
      active:      v.Active,
      balance:     Number(v.Balance || 0)
    }));
    res.json({ count: vendors.length, vendors });
  } catch (err) {
    console.error('Vendors error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Vendor history → per-vendor default account suggestion (drives AI auto-categorization)
app.get('/api/vendor-history', requireAuth, async (req, res) => {
  try {
    const target = await getConn(req, res); if (!target) return;
    const data = await qboQuery(target.userId, target.conn.realm_id,
      'SELECT * FROM Purchase ORDERBY TxnDate DESC MAXRESULTS 1000'
    );
    const purchases = data.QueryResponse?.Purchase || [];
    const byVendor = {};
    for (const p of purchases) {
      const vendorId   = p.EntityRef?.value;
      const vendorName = p.EntityRef?.name;
      if (!vendorId || p.EntityRef?.type !== 'Vendor') continue;
      if (!byVendor[vendorId]) {
        byVendor[vendorId] = { displayName: vendorName, count: 0, totalSpend: 0, accountCounts: {}, recentTxns: [] };
      }
      const v = byVendor[vendorId];
      v.count++;
      v.totalSpend += Number(p.TotalAmt || 0);
      if (v.recentTxns.length < 5) {
        const firstLine = (p.Line || []).find(l => l.AccountBasedExpenseLineDetail) || (p.Line || [])[0];
        v.recentTxns.push({
          id: p.Id,
          date: p.TxnDate,
          amount: Number(p.TotalAmt || 0),
          accountName: firstLine?.AccountBasedExpenseLineDetail?.AccountRef?.name || '(unknown)',
          docNumber: p.DocNumber || null,
          memo: p.PrivateNote || null
        });
      }
      for (const line of (p.Line || [])) {
        const acctRef = line.AccountBasedExpenseLineDetail?.AccountRef;
        if (!acctRef?.value) continue;
        const key = acctRef.value;
        if (!v.accountCounts[key]) v.accountCounts[key] = { id: key, name: acctRef.name, count: 0 };
        v.accountCounts[key].count++;
      }
    }
    for (const v of Object.values(byVendor)) {
      const accounts = Object.values(v.accountCounts).sort((a, b) => b.count - a.count);
      v.defaultAccountId         = accounts[0]?.id || null;
      v.defaultAccountName       = accounts[0]?.name || null;
      v.defaultAccountConfidence = accounts[0] && v.count > 0 ? Math.round((accounts[0].count / v.count) * 100) : 0;
      v.topAccounts = accounts.slice(0, 3).map(a => ({ ...a, pct: Math.round((a.count / v.count) * 100) }));
    }
    res.json({ vendorCount: Object.keys(byVendor).length, txnsAnalyzed: purchases.length, byVendor });
  } catch (err) {
    console.error('Vendor history error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Create vendor inline
app.post('/api/vendor', requireAuth, async (req, res) => {
  const { displayName, companyName, email, phone, notes } = req.body || {};
  if (!displayName) return res.status(400).json({ error: 'displayName is required' });
  try {
    const target = await getConn(req, res); if (!target) return;
    const vendorData = { DisplayName: displayName };
    if (companyName) vendorData.CompanyName = companyName;
    if (email)       vendorData.PrimaryEmailAddr = { Address: email };
    if (phone)       vendorData.PrimaryPhone    = { FreeFormNumber: phone };
    if (notes)       vendorData.Notes           = notes;
    const data = await qboCreate(target.userId, target.conn.realm_id, 'vendor', vendorData);
    const v = data.Vendor;
    res.json({
      success: true,
      vendor: { id: v.Id, displayName: v.DisplayName, companyName: v.CompanyName || null, active: v.Active, balance: Number(v.Balance || 0) }
    });
  } catch (err) {
    console.error('Create vendor error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Create account inline
app.post('/api/account', requireAuth, async (req, res) => {
  const { name, accountType, accountSubType, parentAccountId, description, acctNum } = req.body || {};
  if (!name)           return res.status(400).json({ error: 'name is required' });
  if (!accountType)    return res.status(400).json({ error: 'accountType is required' });
  if (!accountSubType) return res.status(400).json({ error: 'accountSubType is required' });
  try {
    const target = await getConn(req, res); if (!target) return;
    const accountData = { Name: name, AccountType: accountType, AccountSubType: accountSubType };
    if (parentAccountId) {
      accountData.SubAccount = true;
      accountData.ParentRef  = { value: String(parentAccountId) };
    }
    if (description) accountData.Description = description;
    if (acctNum)     accountData.AcctNum     = acctNum;
    const data = await qboCreate(target.userId, target.conn.realm_id, 'account', accountData);
    const a = data.Account;
    res.json({
      success: true,
      account: { id: a.Id, name: a.Name, fullyQualifiedName: a.FullyQualifiedName, accountType: a.AccountType, accountSubType: a.AccountSubType, active: a.Active }
    });
  } catch (err) {
    console.error('Create account error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Bulk push categorized transactions as Purchases (Cash / Check / CreditCard)
app.post('/api/purchase-batch', requireAuth, async (req, res) => {
  const { bankAccountId, bankAccountName, transactions } = req.body || {};
  if (!bankAccountId)            return res.status(400).json({ error: 'bankAccountId required' });
  if (!transactions || !transactions.length) return res.status(400).json({ error: 'transactions array required' });
  try {
    const target = await getConn(req, res); if (!target) return;
    const userId  = target.userId;
    const realmId = target.conn.realm_id;
    const results = { created: [], skipped: [], errors: [] };

    for (const txn of transactions) {
      const dateShort = (txn.date || '').replace(/-/g, '').substring(2);
      const amtStr    = Math.abs(txn.amount).toFixed(2);
      const slugLen   = 21 - dateShort.length - 1 - amtStr.length - 1;
      const slug      = (txn.description || '').toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, Math.max(slugLen, 1));
      const docNumber = `${dateShort}-${amtStr}-${slug}`;

      // Layer 3: local push-history dedup (per-user)
      const pastPush = await db.findPushedTxn(userId, realmId, bankAccountId, txn.date, txn.amount, txn.description);
      if (pastPush) {
        results.skipped.push({ docNumber, description: txn.description, reason: 'Already pushed locally', priorEntityId: pastPush.entityId });
        continue;
      }
      // Layer 1: QBO DocNumber dedup
      try {
        const existing = await qboQuery(userId, realmId, `SELECT Id FROM Purchase WHERE DocNumber = '${docNumber}'`);
        if (existing.QueryResponse?.Purchase && existing.QueryResponse.Purchase.length > 0) {
          results.skipped.push({ docNumber, description: txn.description, reason: 'Already exists in QBO' });
          continue;
        }
      } catch (_) { /* proceed if check fails */ }

      try {
        const purchaseData = {
          PaymentType: txn.paymentType || 'Cash',
          AccountRef:  { value: String(bankAccountId), name: bankAccountName },
          TxnDate:     txn.date,
          DocNumber:   docNumber,
          PrivateNote: txn.description,
          Line: [{
            Amount: Math.abs(Number(txn.amount)),
            DetailType: 'AccountBasedExpenseLineDetail',
            AccountBasedExpenseLineDetail: {
              AccountRef: { value: String(txn.categoryId), name: txn.categoryName }
            }
          }]
        };
        if (txn.vendorId) {
          purchaseData.EntityRef = { value: String(txn.vendorId), name: txn.vendorName || '', type: 'Vendor' };
        }
        const data = await qboCreate(userId, realmId, 'purchase', purchaseData);
        await db.recordPush(userId, realmId, {
          bankAccountId,
          entityType: purchaseData.PaymentType === 'Check' ? 'Check' : 'Purchase',
          entityId:   data.Purchase.Id,
          txnDate:    txn.date,
          amount:     txn.amount,
          description: txn.description
        });
        results.created.push({ docNumber, id: data.Purchase.Id, amount: txn.amount, description: txn.description });
      } catch (err) {
        results.errors.push({ docNumber, description: txn.description, error: err.response?.data || err.message });
      }
    }
    res.json(results);
  } catch (err) {
    console.error('Purchase batch error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Bulk push positive-amount inflows as Deposits
app.post('/api/deposit-batch', requireAuth, async (req, res) => {
  const { bankAccountId, bankAccountName, transactions } = req.body || {};
  if (!bankAccountId)            return res.status(400).json({ error: 'bankAccountId required' });
  if (!transactions || !transactions.length) return res.status(400).json({ error: 'transactions array required' });
  try {
    const target = await getConn(req, res); if (!target) return;
    const userId  = target.userId;
    const realmId = target.conn.realm_id;
    const results = { created: [], skipped: [], errors: [] };

    for (const txn of transactions) {
      if (!txn.categoryId) {
        results.errors.push({ description: txn.description, error: 'categoryId required for deposit' });
        continue;
      }
      const dateShort = (txn.date || '').replace(/-/g, '').substring(2);
      const amtStr    = Math.abs(txn.amount).toFixed(2);
      const slugLen   = 21 - dateShort.length - 1 - amtStr.length - 1 - 1;
      const slug      = (txn.description || '').toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, Math.max(slugLen, 1));
      const docNumber = `D${dateShort}-${amtStr}-${slug}`.substring(0, 21);

      const pastPush = await db.findPushedTxn(userId, realmId, bankAccountId, txn.date, txn.amount, txn.description);
      if (pastPush) {
        results.skipped.push({ docNumber, description: txn.description, reason: 'Already pushed locally', priorEntityId: pastPush.entityId });
        continue;
      }
      try {
        const existing = await qboQuery(userId, realmId, `SELECT Id FROM Deposit WHERE DocNumber = '${docNumber}'`);
        if (existing.QueryResponse?.Deposit && existing.QueryResponse.Deposit.length > 0) {
          results.skipped.push({ docNumber, description: txn.description, reason: 'Already exists in QBO' });
          continue;
        }
      } catch (_) { /* proceed if check fails */ }

      try {
        const line = {
          Amount: Math.abs(Number(txn.amount)),
          DetailType: 'DepositLineDetail',
          Description: txn.description || null,
          DepositLineDetail: { AccountRef: { value: String(txn.categoryId), name: txn.categoryName || '' } }
        };
        if (txn.customerId) {
          line.DepositLineDetail.Entity = { value: String(txn.customerId), name: txn.customerName || '', type: 'Customer' };
        } else if (txn.vendorId) {
          line.DepositLineDetail.Entity = { value: String(txn.vendorId), name: txn.vendorName || '', type: 'Vendor' };
        }
        const depositData = {
          DepositToAccountRef: { value: String(bankAccountId), name: bankAccountName },
          TxnDate:     txn.date,
          DocNumber:   docNumber,
          PrivateNote: txn.description || null,
          Line: [line]
        };
        const data = await qboCreate(userId, realmId, 'deposit', depositData);
        await db.recordPush(userId, realmId, {
          bankAccountId,
          entityType: 'Deposit',
          entityId:   data.Deposit.Id,
          txnDate:    txn.date,
          amount:     txn.amount,
          description: txn.description
        });
        results.created.push({ docNumber, id: data.Deposit.Id, amount: txn.amount, description: txn.description });
      } catch (err) {
        results.errors.push({ docNumber, description: txn.description, error: err.response?.data || err.message });
      }
    }
    res.json(results);
  } catch (err) {
    console.error('Deposit batch error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Reconcile local push history vs QBO actuals (for the Reconcile vs QBO modal)
app.get('/api/reconcile', requireAuth, async (req, res) => {
  const { bankAccountId, start, end } = req.query;
  if (!bankAccountId) return res.status(400).json({ error: 'bankAccountId required' });
  const startDate = start || `${new Date().getFullYear()}-01-01`;
  const endDate   = end   || new Date().toISOString().split('T')[0];
  try {
    const target = await getConn(req, res); if (!target) return;
    const userId  = target.userId;
    const realmId = target.conn.realm_id;

    const localPushed = await db.listPushHistory(userId, bankAccountId, startDate, endDate);

    const purchases = (await qboQuery(userId, realmId,
      `SELECT * FROM Purchase WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 500`
    )).QueryResponse?.Purchase || [];
    const deposits = (await qboQuery(userId, realmId,
      `SELECT * FROM Deposit WHERE TxnDate >= '${startDate}' AND TxnDate <= '${endDate}' MAXRESULTS 500`
    )).QueryResponse?.Deposit || [];

    const purchasesForBank = purchases.filter(p => String(p.AccountRef?.value)         === String(bankAccountId));
    const depositsForBank  = deposits.filter(d => String(d.DepositToAccountRef?.value) === String(bankAccountId));

    const qboByHash = new Map();
    for (const p of purchasesForBank) {
      const h = db.txnHash(realmId, bankAccountId, p.TxnDate, p.TotalAmt, p.PrivateNote || '');
      qboByHash.set(h, { type: p.PaymentType === 'Check' ? 'Check' : 'Purchase', id: p.Id, date: p.TxnDate, amount: Number(p.TotalAmt), vendor: p.EntityRef?.name, docNumber: p.DocNumber });
    }
    for (const d of depositsForBank) {
      const h = db.txnHash(realmId, bankAccountId, d.TxnDate, d.TotalAmt, d.PrivateNote || '');
      qboByHash.set(h, { type: 'Deposit', id: d.Id, date: d.TxnDate, amount: Number(d.TotalAmt), docNumber: d.DocNumber });
    }

    const localHashes  = new Set(localPushed.map(h => h.hash));
    const missingInQbo = localPushed.filter(h => !qboByHash.has(h.hash));
    const extraInQbo   = [...qboByHash.entries()].filter(([h]) => !localHashes.has(h)).map(([, v]) => v);
    const matched      = localPushed.filter(h => qboByHash.has(h.hash));

    res.json({
      bankAccountId,
      window:  { start: startDate, end: endDate },
      summary: { pushedLocally: localPushed.length, foundInQbo: matched.length, missingInQbo: missingInQbo.length, extraInQbo: extraInQbo.length },
      matched, missingInQbo, extraInQbo
    });
  } catch (err) {
    console.error('Reconcile error:', err.response?.data || err.message);
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
