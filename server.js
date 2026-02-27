require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nagarseva_secret_key';
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, 'nagarseva.db');

// ─── Database ─────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT    NOT NULL,
      email         TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL DEFAULT 'citizen',
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS complaints (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      title        TEXT NOT NULL,
      category     TEXT NOT NULL DEFAULT 'other',
      description  TEXT NOT NULL,
      location     TEXT NOT NULL,
      priority     TEXT NOT NULL DEFAULT 'medium',
      status       TEXT NOT NULL DEFAULT 'pending',
      citizen_name TEXT NOT NULL,
      user_id      INTEGER REFERENCES users(id),
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS activity_logs (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER REFERENCES users(id),
      action       TEXT NOT NULL,
      complaint_id INTEGER,
      details      TEXT,
      timestamp    TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // ✅ Har restart pe default users ensure karo
  ensureDefaultUsers();

  // Seed complaints only if DB empty
  const count = db.prepare('SELECT COUNT(*) as c FROM complaints').get();
  if (count.c === 0) seedComplaints();
}

// ✅ Yeh function har restart pe chalta hai — demo users hamesha rahenge
function ensureDefaultUsers() {
  const existing = db.prepare("SELECT id FROM users WHERE email = 'admin@nagarseva.in'").get();
  if (!existing) {
    db.prepare(`INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`)
      .run('Admin NagarSeva', 'admin@nagarseva.in', bcrypt.hashSync('admin123', 10), 'admin');
    db.prepare(`INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`)
      .run('Ramesh Kumar', 'ramesh@gmail.com', bcrypt.hashSync('citizen123', 10), 'citizen');
    console.log('[SEED] Default users created');
  } else {
    console.log('[SEED] Default users already exist');
  }
}

function seedComplaints() {
  const citizen = db.prepare("SELECT id FROM users WHERE email='ramesh@gmail.com'").get();
  if (!citizen) return;

  const ins = db.prepare(`
    INSERT INTO complaints (title, category, description, location, priority, status, citizen_name, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  [
    ['Broken Street Light on MG Road', 'electricity', 'Three consecutive street lights near MG Road bus stop have been non-functional for 2 weeks causing safety issues at night.', 'MG Road, Near Bus Stop No. 14, Pune', 'high', 'pending', 'Ramesh Kumar', citizen.id],
    ['Overflowing Garbage Bin near Market', 'sanitation', 'The garbage bin near Laxmi Market has been overflowing for 3 days. Foul smell is spreading to nearby shops and homes.', 'Laxmi Market, Sector 7, Nagpur', 'high', 'inProgress', 'Priya Sharma', citizen.id],
    ['Pothole on NH-48 Causing Accidents', 'roads', 'Large pothole on NH-48 near Zomato office junction. Two bike accidents reported this week. Immediate repair needed.', 'NH-48, Near Zomato Office, Bengaluru', 'critical', 'pending', 'Suresh Nair', citizen.id],
    ['Water Supply Disruption for 5 Days', 'water', 'Our entire colony has not received municipal water supply for 5 days. Residents are forced to buy expensive tankers.', 'Shanti Nagar Colony, Block C, Jaipur', 'critical', 'inProgress', 'Meena Devi', citizen.id],
    ['Unauthorized Construction Blocking Road', 'infrastructure', 'Builder has placed construction material and machinery on the public road without permission, blocking traffic flow.', 'Gandhi Nagar Road, Near Park, Ahmedabad', 'medium', 'resolved', 'Ajay Patel', citizen.id],
    ['Sewage Overflow in Residential Area', 'sanitation', 'Sewage is overflowing from the drain on Main Street and entering homes. Health hazard for children and elderly.', 'Model Town, Sector 12, Ludhiana', 'critical', 'pending', 'Harpreet Singh', citizen.id],
    ['Damaged Park Benches and Broken Swings', 'parks', 'Most benches in the community park are broken and swing sets are damaged. Children are getting hurt while playing.', 'Central Park, Anna Nagar, Chennai', 'low', 'pending', 'Kavitha Rao', citizen.id],
    ['Stray Dogs Menace Near School', 'animal control', 'Pack of aggressive stray dogs near St. Mary School gates. Children afraid to walk. Three biting incidents last month.', 'St. Mary School Road, Bhopal', 'high', 'inProgress', 'Father Thomas', citizen.id],
  ].forEach(row => ins.run(...row));

  console.log('[SEED] Sample complaints inserted');
}

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();

// ✅ Railway ke liye zaroori
app.set('trust proxy', 1);

app.use(cors({ origin: '*' }));
app.use(express.json());

// Logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} | IP: ${req.ip}`);
  next();
});

// ─── JWT Helpers ──────────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function logActivity(userId, action, complaintId, details) {
  try {
    db.prepare(`INSERT INTO activity_logs (user_id, action, complaint_id, details) VALUES (?, ?, ?, ?)`)
      .run(userId, action, complaintId, details);
  } catch(e) { console.error('Log error:', e); }
}

// ─── Helper: value sanitize karo ─────────────────────────────────────────────
const VALID_PRIORITIES = ['low', 'medium', 'high', 'critical'];
const VALID_STATUSES   = ['pending', 'inProgress', 'resolved', 'rejected'];

function sanitizePriority(val) {
  if (!val) return 'medium';
  const v = String(val).toLowerCase().trim();
  return VALID_PRIORITIES.includes(v) ? v : 'medium';
}

function sanitizeStatus(val) {
  if (!val) return 'pending';
  const v = String(val).trim();
  return VALID_STATUSES.includes(v) ? v : 'pending';
}

function sanitizeCategory(val) {
  if (!val) return 'other';
  return String(val).toLowerCase().trim();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'NagarSeva API' });
});

// ── Register ──────────────────────────────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || !name.trim())     return res.status(400).json({ error: 'Name is required' });
  if (!email || !email.trim())   return res.status(400).json({ error: 'Email is required' });
  if (!password)                 return res.status(400).json({ error: 'Password is required' });
  if (password.length < 6)       return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const emailClean = email.trim().toLowerCase();
  const nameClean  = name.trim();

  // Basic email format check
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailClean))
    return res.status(400).json({ error: 'Please enter a valid email address' });

  // Check duplicate
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(emailClean);
  if (existing) return res.status(409).json({ error: 'Email already registered. Please sign in.' });

  // ✅ Hamesha citizen — koi admin self-register nahi kar sakta
  const role          = 'citizen';
  const password_hash = bcrypt.hashSync(password, 10);

  const result = db.prepare(`
    INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)
  `).run(nameClean, emailClean, password_hash, role);

  const user = { id: result.lastInsertRowid, name: nameClean, email: emailClean, role };
  logActivity(user.id, 'USER_REGISTER', null, `Registered: ${emailClean}`);

  console.log(`[AUTH] Registered: ${emailClean} (${role})`);
  res.status(201).json({ token: generateToken(user), user });
});

// ── Login ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !email.trim()) return res.status(400).json({ error: 'Email is required' });
  if (!password)               return res.status(400).json({ error: 'Password is required' });

  const emailClean = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(emailClean);

  if (!user) {
    return res.status(404).json({
      error: 'No account found with this email. Please register first.',
      code: 'USER_NOT_FOUND'
    });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: 'Wrong password. Please try again.',
      code: 'WRONG_PASSWORD'
    });
  }

  const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role };
  logActivity(user.id, 'USER_LOGIN', null, `Login from ${req.ip}`);

  console.log(`[AUTH] Login: ${emailClean} (${user.role})`);
  res.json({ token: generateToken(safeUser), user: safeUser });
});

// ── Get All Complaints (admin) ────────────────────────────────────────────────
app.get('/api/complaints', authenticate, (req, res) => {
  const { category, status } = req.query;
  let sql    = 'SELECT * FROM complaints WHERE 1=1';
  const params = [];

  if (category && category !== 'All') { sql += ' AND category = ?'; params.push(category.toLowerCase()); }
  if (status   && status   !== 'All') { sql += ' AND status = ?';   params.push(status); }

  sql += ' ORDER BY created_at DESC';
  const complaints = db.prepare(sql).all(...params);
  res.json({ count: complaints.length, complaints });
});

// ── Get My Complaints (citizen) ───────────────────────────────────────────────
app.get('/api/my-complaints', authenticate, (req, res) => {
  const complaints = db.prepare(
    'SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.user.id);
  res.json({ count: complaints.length, complaints });
});

// ── Submit Complaint ──────────────────────────────────────────────────────────
app.post('/api/complaints', authenticate, (req, res) => {
  const { title, category, description, location, priority } = req.body || {};

  // ✅ Simple manual validation — no express-validator strict checks
  if (!title || !title.trim())
    return res.status(400).json({ error: 'Title is required' });
  if (!description || !description.trim())
    return res.status(400).json({ error: 'Description is required' });
  if (description.trim().length < 10)
    return res.status(400).json({ error: 'Description must be at least 10 characters' });
  if (!location || !location.trim())
    return res.status(400).json({ error: 'Location is required' });

  // ✅ Sanitize karo — galat value aaye toh bhi crash nahi hoga
  const cleanCategory = sanitizeCategory(category);
  const cleanPriority = sanitizePriority(priority);

  const result = db.prepare(`
    INSERT INTO complaints (title, category, description, location, priority, citizen_name, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    title.trim(),
    cleanCategory,
    description.trim(),
    location.trim(),
    cleanPriority,
    req.user.name,
    req.user.id
  );

  const complaint = db.prepare('SELECT * FROM complaints WHERE id = ?').get(result.lastInsertRowid);
  logActivity(req.user.id, 'COMPLAINT_CREATED', complaint.id, `New: "${title}"`);

  console.log(`[COMPLAINT] #${complaint.id} created by ${req.user.name}: ${title}`);
  res.status(201).json(complaint);
});

// ── Update Status (admin) ─────────────────────────────────────────────────────
app.patch('/api/complaints/:id/status', authenticate, requireAdmin, (req, res) => {
  const id     = parseInt(req.params.id);
  const status = sanitizeStatus(req.body?.status);

  const complaint = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
  if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

  db.prepare(`UPDATE complaints SET status = ?, updated_at = datetime('now') WHERE id = ?`).run(status, id);

  logActivity(req.user.id, 'STATUS_UPDATED', id,
    `Status: ${complaint.status} → ${status}`);

  console.log(`[ADMIN] #${id} status: ${complaint.status} → ${status} by ${req.user.email}`);
  res.json({ message: 'Status updated', complaint: db.prepare('SELECT * FROM complaints WHERE id = ?').get(id) });
});

// ── Admin Stats ───────────────────────────────────────────────────────────────
app.get('/api/admin/stats', authenticate, requireAdmin, (_req, res) => {
  const row = db.prepare(`
    SELECT
      COUNT(*)                                             AS total,
      SUM(CASE WHEN status='pending'    THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status='inProgress' THEN 1 ELSE 0 END) AS inProgress,
      SUM(CASE WHEN status='resolved'   THEN 1 ELSE 0 END) AS resolved,
      SUM(CASE WHEN status='rejected'   THEN 1 ELSE 0 END) AS rejected
    FROM complaints
  `).get();

  const byCategory = db.prepare(
    `SELECT category, COUNT(*) as count FROM complaints GROUP BY category ORDER BY count DESC`
  ).all();

  res.json({
    total:      row.total      || 0,
    pending:    row.pending    || 0,
    inProgress: row.inProgress || 0,
    resolved:   row.resolved   || 0,
    rejected:   row.rejected   || 0,
    byCategory,
  });
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// ─── Error Handler ────────────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
initDB();
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   🏙️  NagarSeva - Smart City Portal API   ║');
  console.log(`║   Running on http://localhost:${PORT}        ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log('[DB]   Database:', DB_PATH);
  console.log('[INFO] Admin  → admin@nagarseva.in / admin123');
  console.log('[INFO] Citizen→ ramesh@gmail.com   / citizen123');
  console.log('');
});
