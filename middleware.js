// middleware.js — Auth guards and tenant resolution

// Require any authenticated user
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.accepts('html')) return res.redirect('/login.html');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (req.session.userIsActive === false) {
    req.session.destroy();
    return res.status(403).json({ error: 'Account deactivated' });
  }
  next();
}

// Require admin role
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.accepts('html')) return res.redirect('/login.html');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (req.session.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
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
