const db      = require('./db');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const SECRET = 'your_jwt_secret_key';  // Store in .env in production

// ── Validate user against DB ──────────────────────────────────────────────────
function loginUser(identifier, password, callback) {
  // Allow login with username OR email
  const sql = `
    SELECT * FROM users
    WHERE username = ? OR email = ?
    LIMIT 1
  `;

  db.get(sql, [identifier, identifier], async (err, user) => {
    if (err) {
      return callback({ success: false, message: 'Database error.' });
    }

    // 1️⃣  User not found
    if (!user) {
      return callback({ success: false, message: 'Invalid username or password.' });
    }

    // 2️⃣  Compare hashed password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return callback({ success: false, message: 'Invalid username or password.' });
    }

    // 3️⃣  Issue JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET,
      { expiresIn: '1h' }
    );

    callback({
      success : true,
      message : 'Login successful!',
      token,
      user    : { id: user.id, username: user.username, role: user.role }
    });
  });
}

// ── Middleware: protect routes ────────────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  if (!token) return res.status(401).json({ message: 'Access denied. No token.' });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = decoded;
    next();
  });
}

module.exports = { loginUser, authenticate };
