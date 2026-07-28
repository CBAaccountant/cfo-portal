// middleware.js — Auth guards and tenant resolution
const db = require('./db');

// Require any authenticated user.
// Checks the database (not just the session cookie) so deactivating an
// account or changing a role takes effect immediately, not at cookie expiry.
async function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.accepts('html')) return res.redirect('/login.html');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user || !user.is_active) {
      return req.session.destroy(() => {
        if (req.accepts('html')) return res.redirect('/login.html');
        return res.status(403).json({ error: 'Account deactivated' });
      });
    }
    req.session.userRole = user.role;
    next();
  } catch (err) {
    console.error('Auth check error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
}

// Require admin role (also verified against the database)
async function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.accepts('html')) return res.redirect('/login.html');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const user = await db.getUserById(req.session.userId);
    if (!user || !user.is_active) {
      return req.session.destroy(() => {
        if (req.accepts('html')) return res.redirect('/login.html');
        return res.status(403).json({ error: 'Account deactivated' });
      });
    }
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.session.userRole = user.role;
    next();
  } catch (err) {
    console.error('Auth check error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
}

// Returns the user ID whose QBO data to query:
// - If admin is impersonating a client → return impersonated user ID
// - Otherwise → return own user ID
function getTargetUserId(req) {
  if (req.session.userRole === 'admin' && req.session.viewingAsUserId) {
    return req.session.viewingAsUserId;
  }
  return req.session.userId;
}

module.exports = { requireAuth, requireAdmin, getTargetUserId };
