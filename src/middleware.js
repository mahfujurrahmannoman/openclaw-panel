const jwt = require('jsonwebtoken');

const JWT_SECRET = () => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is required');
  }
  return process.env.JWT_SECRET;
};

// Generate JWT token
function signToken(payload, expiresIn = '24h') {
  return jwt.sign(payload, JWT_SECRET(), { expiresIn });
}

// Verify JWT and attach to req
function verifyToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    req.auth = jwt.verify(header.split(' ')[1], JWT_SECRET());
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Admin-only middleware
function adminOnly(req, res, next) {
  if (req.auth?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// User-only middleware
function userOnly(req, res, next) {
  if (req.auth?.role !== 'user') {
    return res.status(403).json({ error: 'User access required' });
  }
  next();
}

module.exports = { signToken, verifyToken, adminOnly, userOnly };
