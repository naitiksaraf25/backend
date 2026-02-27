/**
 * NagarSeva - Smart City Complaint Portal
 * Single-file Express backend
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const path = require('path');

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nagarseva_super_secret_key_change_in_prod';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'nagarseva.db');

// ─── Database Setup ───────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      name      TEXT    NOT NULL,
      email     TEXT    UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role      TEXT    NOT NULL DEFAULT 'citizen',
      created_at TEXT   NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS complaints (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      title        TEXT NOT NULL,
      category     TEXT NOT NULL,
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
      complaint_id INTEGER REFERENCES complaints(id),
      details      TEXT,
      timestamp    TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // ✅ Hamesha default users ensure karo (Railway pe DB reset hota hai)
  ensureDefaultUsers();

  // Seed complaints only if empty
  const count = db.prepare('SELECT COUNT(*) as c FROM complaints').get();
  if (count.c === 0) {
    seedComplaints();
  }
}

// ✅ Yeh function har restart pe chalta hai — demo users hamesha rahenge
function ensureDefaultUsers() {
  const adminHash = bcrypt.hashSync('admin123', 10);
  const userHash  = bcrypt.hashSync('citizen123', 10);

  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `);
  insertUser.run('Admin NagarSeva', 'admin@nagarseva.in', adminHash, 'admin');
  insertUser.run('Ramesh Kumar',    'ramesh@gmail.com',   userHash,  'citizen');
  console.log('[SEED] Default users ensured: admin@nagarseva.in, ramesh@gmail.com');
}

function seedComplaints() {
  console.log('[SEED] Seeding initial complaints...');

  const citizenId = db.prepare("SELECT id FROM users WHERE email='ramesh@gmail.com'").get()?.id;
  if (!citizenId) return;

  const insertComplaint = db.prepare(`
    INSERT INTO complaints (title, category, description, location, priority, status, citizen_name, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seeds = [
    ['Broken Street Light on MG Road', 'electricity',
     'Three consecutive street lights near MG Road bus stop have been non-functional for 2 weeks causing safety issues at night.',
     'MG Road, Near Bus Stop No. 14, Pune', 'high', 'pending', 'Ramesh Kumar', citizenId],

    ['Overflowing Garbage Bin near Market', 'sanitation',
     'The garbage bin near Laxmi Market has been overflowing for 3 days. Foul smell is spreading to nearby shops and homes.',
     'Laxmi Market, Sector 7, Nagpur', 'high', 'inProgress', 'Priya Sharma', citizenId],

    ['Pothole on NH-48 Causing Accidents', 'roads',
     'Large pothole on NH-48 near Zomato office junction. Two bike accidents reported this week. Immediate repair needed.',
     'NH-48, Near Zomato Office, Bengaluru', 'critical', 'pending', 'Suresh Nair', citizenId],

    ['Water Supply Disruption for 5 Days', 'water',
     'Our entire colony has not received municipal water supply for 5 days. Residents are forced to buy expensive tankers.',
     'Shanti Nagar Colony, Block C, Jaipur', 'critical', 'inProgress', 'Meena Devi', citizenId],

    ['Unauthorized Construction Blocking Road', 'infrastructure',
     'Builder has placed construction material and machinery on the public road without permission, blocking traffic flow.',
     'Gandhi Nagar Road, Near Park, Ahmedabad', 'medium', 'resolved', 'Ajay Patel', citizenId],

    ['Sewage Overflow in Residential Area', 'sanitation',
     'Sewage is overflowing from the drain on Main Street and entering homes. Health hazard for children and elderly.',
     'Model Town, Sector 12, Ludhiana', 'critical', 'pending', 'Harpreet Singh', citizenId],

    ['Damaged Park Benches and Broken Swings', 'parks',
     'Most benches in the community park are broken and swing sets are damaged. Children are getting hurt while playing.',
     'Central Park, Anna Nagar, Chennai', 'low', 'pending', 'Kavitha Rao', citizenId],

    ['Stray Dogs Menace Near School', 'animal control',
     'Pack of aggressive stray dogs near St. Mary School gates. Children afraid to walk. Three biting incidents last month.',
     'St. Mary School Road, Bhopal', 'high', 'inProgress', 'Father Thomas', citizenId],
  ];

  for (const s of seeds) insertComplaint.run(...s);
  console.log(`[SEED] Inserted ${seeds.length} complaints.`);
}

// ─── Express App ──────────────────────────────────────────────────────────────
const app = express();

// ✅ BUG FIX 1: Railway proxy ke liye zaroori — bina iske server crash karta tha
app.set('trust proxy', 1);

app.use(cors({ origin: '*' }));
app.use(express.json());

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
}));

// ─── Request Logger ───────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  const now = new Date().toISOString();
  console.log(`[${now}] ${req.method} ${req.originalUrl} | IP: ${req.ip}`);
  next();
});

// ─── JWT Middleware ───────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });

  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ─── Validation Helper ────────────────────────────────────────────────────────
function validate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(422).json({ errors: errors.array() });
    return false;
  }
  return true;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function logActivity(userId, action, complaintId, details) {
  db.prepare(`
    INSERT INTO activity_logs (user_id, action, complaint_id, details)
    VALUES (?, ?, ?, ?)
  `).run(userId, action, complaintId, details);
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'NagarSeva API' });
});

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/register',
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  (req, res) => {
    if (!validate(req, res)) return;

    const { name, email, password } = req.body;

    // ✅ BUG FIX 2: Role hamesha 'citizen' — email se koi bhi admin nahi ban sakta
    // PURANA BUG THA: const role = email.includes('admin') ? 'admin' : 'citizen';
    const role = 'citizen';

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const password_hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)
    `).run(name, email, password_hash, role);

    const user = { id: result.lastInsertRowid, name, email, role };
    logActivity(user.id, 'USER_REGISTER', null, `New user registered: ${email}`);

    console.log(`[AUTH] Registered: ${email} (${role})`);
    res.status(201).json({ token: generateToken(user), user });
  }
);

app.post('/api/auth/login',
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password is required'),
  (req, res) => {
    if (!validate(req, res)) return;

    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // User exist nahi karta
    if (!user) {
      return res.status(404).json({
        error: 'No account found with this email. Please register first.',
        code: 'USER_NOT_FOUND'
      });
    }

    // Password galat hai
    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({
        error: 'Invalid email or password',
        code: 'WRONG_PASSWORD'
      });
    }

    const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role };
    logActivity(user.id, 'USER_LOGIN', null, `Login from ${req.ip}`);

    console.log(`[AUTH] Login: ${email} (${user.role})`);
    res.json({ token: generateToken(safeUser), user: safeUser });
  }
);

// ── Complaints ────────────────────────────────────────────────────────────────
app.get('/api/complaints',
  authenticate,
  query('category').optional().trim(),
  query('status').optional().trim(),
  (req, res) => {
    if (!validate(req, res)) return;

    const { category, status } = req.query;
    let sql = 'SELECT * FROM complaints WHERE 1=1';
    const params = [];

    if (category) { sql += ' AND category = ?'; params.push(category); }
    if (status)   { sql += ' AND status = ?';   params.push(status); }

    sql += ' ORDER BY created_at DESC';

    const complaints = db.prepare(sql).all(...params);
    res.json({ count: complaints.length, complaints });
  }
);

// Citizen ki apni complaints fetch karne ke liye
app.get('/api/my-complaints',
  authenticate,
  (req, res) => {
    const complaints = db.prepare(
      'SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC'
    ).all(req.user.id);
    res.json({ count: complaints.length, complaints });
  }
);

app.post('/api/complaints',
  authenticate,
  body('title').trim().notEmpty().withMessage('Title is required'),
  body('category').trim().notEmpty().withMessage('Category is required'),
  body('description').trim().isLength({ min: 10 }).withMessage('Description must be at least 10 characters'),
  body('location').trim().notEmpty().withMessage('Location is required'),
  body('priority').optional().isIn(['low','medium','high','critical']).withMessage('Invalid priority'),
  (req, res) => {
    if (!validate(req, res)) return;

    const { title, category, description, location, priority = 'medium' } = req.body;
    const citizen_name = req.user.name;
    const user_id = req.user.id;

    const result = db.prepare(`
      INSERT INTO complaints (title, category, description, location, priority, citizen_name, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(title, category, description, location, priority, citizen_name, user_id);

    const complaint = db.prepare('SELECT * FROM complaints WHERE id = ?').get(result.lastInsertRowid);
    logActivity(user_id, 'COMPLAINT_CREATED', complaint.id, `New complaint: "${title}"`);

    console.log(`[COMPLAINT] Created #${complaint.id}: ${title} by ${citizen_name}`);
    res.status(201).json(complaint);
  }
);

app.patch('/api/complaints/:id/status',
  authenticate,
  requireAdmin,
  body('status').isIn(['pending','inProgress','resolved','rejected']).withMessage('Invalid status'),
  (req, res) => {
    if (!validate(req, res)) return;

    const { id } = req.params;
    const { status, note } = req.body;

    const complaint = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
    if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

    db.prepare(`
      UPDATE complaints SET status = ?, updated_at = datetime('now') WHERE id = ?
    `).run(status, id);

    const details = `Status changed from ${complaint.status} → ${status}${note ? '. Note: ' + note : ''}`;
    logActivity(req.user.id, 'STATUS_UPDATED', parseInt(id), details);

    console.log(`[ADMIN] Complaint #${id} status: ${complaint.status} → ${status} by ${req.user.email}`);

    const updated = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
    res.json({ message: 'Status updated', complaint: updated });
  }
);

// ── Admin Stats ───────────────────────────────────────────────────────────────
app.get('/api/admin/stats',
  authenticate,
  requireAdmin,
  (_req, res) => {
    const row = db.prepare(`
      SELECT
        COUNT(*)                                        AS total,
        SUM(status = 'pending')                         AS pending,
        SUM(status = 'inProgress')                      AS inProgress,
        SUM(status = 'resolved')                        AS resolved,
        SUM(status = 'rejected')                        AS rejected,
        SUM(priority = 'critical' AND status != 'resolved') AS criticalOpen
      FROM complaints
    `).get();

    const categoryCounts = db.prepare(`
      SELECT category, COUNT(*) as count FROM complaints GROUP BY category ORDER BY count DESC
    `).all();

    const recentActivity = db.prepare(`
      SELECT al.*, u.name as user_name FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ORDER BY al.timestamp DESC LIMIT 10
    `).all();

    res.json({
      total:        row.total,
      pending:      row.pending      || 0,
      inProgress:   row.inProgress   || 0,
      resolved:     row.resolved     || 0,
      rejected:     row.rejected     || 0,
      criticalOpen: row.criticalOpen || 0,
      byCategory:   categoryCounts,
      recentActivity
    });
  }
);

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found` });
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
  console.log('[DB]   Database initialized:', DB_PATH);
  console.log('[INFO] Default credentials:');
  console.log('       Admin  → admin@nagarseva.in / admin123');
  console.log('       Citizen→ ramesh@gmail.com   / citizen123');
  console.log('');
});
