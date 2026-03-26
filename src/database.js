const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

class PanelDatabase {
  constructor(dbPath) {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.init();
  }

  init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        cpu_limit REAL NOT NULL,
        memory_limit INTEGER NOT NULL,
        price_monthly INTEGER NOT NULL,
        max_models INTEGER DEFAULT 5,
        description TEXT
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        project_name TEXT,
        service_name TEXT DEFAULT 'openclaw-gateway',
        domain TEXT,
        gateway_token TEXT,
        openclaw_url TEXT,
        status TEXT DEFAULT 'active' CHECK(status IN ('active','suspended')),
        plan TEXT DEFAULT 'unlimited',
        cpu_limit REAL DEFAULT 4,
        memory_limit INTEGER DEFAULT 4096,
        expires_at DATETIME,
        telegram_bot_token TEXT,
        telegram_chat_id TEXT,
        api_key_provider TEXT,
        api_key_encrypted TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      );
    `);

    // Migration: Remove UNIQUE constraint on email (allow same email, multiple services)
    try {
      const tableInfo = this.db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
      if (tableInfo && tableInfo.sql && tableInfo.sql.includes('email TEXT UNIQUE')) {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS users_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            project_name TEXT,
            service_name TEXT DEFAULT 'openclaw-gateway',
            domain TEXT,
            gateway_token TEXT,
            openclaw_url TEXT,
            status TEXT DEFAULT 'active' CHECK(status IN ('active','suspended')),
            plan TEXT DEFAULT 'unlimited',
            cpu_limit REAL DEFAULT 4,
            memory_limit INTEGER DEFAULT 4096,
            expires_at DATETIME,
            telegram_bot_token TEXT,
            telegram_chat_id TEXT,
            api_key_provider TEXT,
            api_key_encrypted TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
          );
          INSERT INTO users_new SELECT * FROM users;
          DROP TABLE users;
          ALTER TABLE users_new RENAME TO users;
        `);
      }
    } catch (e) { /* migration already done or no data */ }

    // Seed default plan if empty
    const planCount = this.db.prepare('SELECT COUNT(*) as cnt FROM plans').get();
    if (planCount.cnt === 0) {
      this.db.prepare(
        'INSERT INTO plans (name, cpu_limit, memory_limit, price_monthly, max_models, description) VALUES (?, ?, ?, ?, ?, ?)'
      ).run('unlimited', 4, 4096, 0, -1, 'Unlimited - 4 CPU, 4GB RAM, unlimited AI models, all channels, 24/7 uptime');
    }
  }

  // --- Admin ---
  createAdmin(email, password) {
    const hash = bcrypt.hashSync(password, 10);
    return this.db.prepare('INSERT INTO admins (email, password) VALUES (?, ?)').run(email, hash);
  }

  verifyAdmin(email, password) {
    const admin = this.db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
    if (!admin) return null;
    if (!bcrypt.compareSync(password, admin.password)) return null;
    return { id: admin.id, email: admin.email };
  }

  getAdminCount() {
    return this.db.prepare('SELECT COUNT(*) as cnt FROM admins').get().cnt;
  }

  // --- Users ---
  createUser(data) {
    const hash = bcrypt.hashSync(data.password, 10);
    const plan = this.getPlanByName('unlimited');
    return this.db.prepare(`
      INSERT INTO users (username, email, password, project_name, service_name, domain, gateway_token, openclaw_url, status, plan, cpu_limit, memory_limit, expires_at, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
    `).run(
      data.username, data.email, hash,
      data.project_name, data.service_name || 'openclaw-gateway',
      data.domain, data.gateway_token, data.openclaw_url,
      'unlimited',
      plan?.cpu_limit || data.cpu_limit || 4,
      plan?.memory_limit || data.memory_limit || 4096,
      data.expires_at || null,
      data.notes || null
    );
  }

  verifyUser(emailOrUsername, password) {
    const user = this.db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(emailOrUsername, emailOrUsername);
    if (!user) return null;
    if (!bcrypt.compareSync(password, user.password)) return null;
    const { password: _, api_key_encrypted: __, ...safe } = user;
    return safe;
  }

  getUserById(id) {
    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return null;
    const { password: _, api_key_encrypted: __, ...safe } = user;
    return safe;
  }

  getUserByUsername(username) {
    const user = this.db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return null;
    const { password: _, api_key_encrypted: __, ...safe } = user;
    return safe;
  }

  getAllUsers() {
    return this.db.prepare('SELECT id, username, email, project_name, service_name, domain, openclaw_url, status, plan, cpu_limit, memory_limit, expires_at, api_key_provider, notes, created_at, updated_at FROM users ORDER BY created_at DESC').all();
  }

  updateUser(id, fields) {
    // SECURITY: 'password' is intentionally excluded — never allow password update via generic update
    const allowed = [
      'email', 'plan', 'cpu_limit', 'memory_limit', 'expires_at',
      'status', 'notes', 'telegram_bot_token', 'telegram_chat_id',
      'api_key_provider', 'api_key_encrypted', 'domain', 'gateway_token',
      'openclaw_url', 'project_name', 'service_name',
    ];
    const updates = [];
    const values = [];
    for (const [key, val] of Object.entries(fields)) {
      if (allowed.includes(key)) {
        updates.push(`${key} = ?`);
        values.push(val);
      }
    }
    if (updates.length === 0) return;
    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);
    return this.db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  }

  updateUserPassword(id, newPassword) {
    const hashed = bcrypt.hashSync(newPassword, 10);
    return this.db.prepare('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hashed, id);
  }

  updateUserUsername(id, newUsername) {
    // Check uniqueness first
    const existing = this.db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(newUsername, id);
    if (existing) return { error: 'Username already taken' };
    return this.db.prepare('UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newUsername, id);
  }

  deleteUser(id) {
    return this.db.prepare('DELETE FROM users WHERE id = ?').run(id);
  }

  suspendUser(id) {
    return this.updateUser(id, { status: 'suspended' });
  }

  activateUser(id) {
    return this.updateUser(id, { status: 'active' });
  }

  // --- Plans ---
  getAllPlans() {
    return this.db.prepare('SELECT * FROM plans ORDER BY price_monthly ASC').all();
  }

  getPlanByName(name) {
    return this.db.prepare('SELECT * FROM plans WHERE name = ?').get(name);
  }

  // --- Activity Log ---
  logActivity(userId, action, details = '') {
    return this.db.prepare('INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)').run(userId, action, details);
  }

  getRecentActivity(limit = 50) {
    return this.db.prepare(`
      SELECT a.*, u.username FROM activity_log a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC LIMIT ?
    `).all(limit);
  }

  getUserActivity(userId, limit = 20) {
    return this.db.prepare('SELECT * FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(userId, limit);
  }

  // --- Dashboard Stats ---
  getDashboardStats() {
    const total = this.db.prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
    const active = this.db.prepare("SELECT COUNT(*) as cnt FROM users WHERE status = 'active'").get().cnt;
    const suspended = this.db.prepare("SELECT COUNT(*) as cnt FROM users WHERE status = 'suspended'").get().cnt;
    const plans = this.db.prepare('SELECT plan, COUNT(*) as cnt FROM users GROUP BY plan').all();
    const planDist = {};
    plans.forEach(p => { planDist[p.plan] = p.cnt; });
    return { total, active, suspended, planDistribution: planDist };
  }

  close() {
    this.db.close();
  }
}

module.exports = PanelDatabase;
