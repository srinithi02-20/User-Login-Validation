const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcrypt');
const db       = require('./db');
const { loginUser, authenticate } = require('./auth');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('.'));      // Serve index.html

// ── POST /api/login ───────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;

  // Input validation
  if (!identifier || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  loginUser(identifier, password, (result) => {
    if (!result.success) {
      return res.status(401).json({ message: result.message });
    }
    res.json(result);
  });
});

// ── POST /api/register ────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  // Password strength check
  const strongPwd = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
  if (!strongPwd.test(password)) {
    return res.status(400).json({
      message: 'Password must be 8+ chars with uppercase, number & special char.'
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
      [username, email, hash],
      function (err) {
        if (err) {
          const msg = err.message.includes('UNIQUE')
            ? 'Username or email already exists.'
            : 'Registration failed.';
          return res.status(409).json({ message: msg });
        }
        res.status(201).json({ message: 'User registered successfully!' });
      }
    );
  } catch {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── GET /api/dashboard (protected) ───────────────────────────────────────────
app.get('/api/dashboard', authenticate, (req, res) => {
  res.json({
    message : `Welcome, ${req.user.username}!`,
    role    : req.user.role,
    data    : 'This is protected dashboard data.'
  });
});

app.listen(3000, () => console.log('Server running at http://localhost:3000'));
