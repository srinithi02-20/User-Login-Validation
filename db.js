const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./users.db');

// Create users table
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT    UNIQUE NOT NULL,
      email    TEXT    UNIQUE NOT NULL,
      password TEXT    NOT NULL,
      role     TEXT    DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Insert a sample user (password: "Admin@123")
  const hash = bcrypt.hashSync('Admin@123', 10);
  db.run(
    `INSERT OR IGNORE INTO users (username, email, password, role)
     VALUES (?, ?, ?, ?)`,
    ['admin', 'admin@example.com', hash, 'admin']
  );
});

module.exports = db;
