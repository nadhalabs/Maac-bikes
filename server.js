/**
 * Maac True Value Bikes — Backend Server
 * ----------------------------------------
 * Simple Node.js + Express backend
 * • Stores bikes in bikes.json (no database needed)
 * • Handles image uploads (saved to /uploads folder)
 * • REST API for the website and admin app
 * • Password-protected admin routes
 *
 * START: node server.js
 * DEFAULT PORT: 3001
 */

const express  = require('express');
const cors     = require('cors');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;

/* ─── PATHS ────────────────────────────────────────────── */
const DATA_FILE    = path.join(__dirname, 'data', 'bikes.json');
const UPLOADS_DIR  = path.join(__dirname, 'public', 'uploads');
const CONFIG_FILE  = path.join(__dirname, 'data', 'config.json');

/* ─── ENSURE FOLDERS EXIST ─────────────────────────────── */
[path.join(__dirname,'data'), UPLOADS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

/* ─── DEFAULT CONFIG ────────────────────────────────────── */
if (!fs.existsSync(CONFIG_FILE)) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({
    // SHA256 hash of default password "maac2024"
    passwordHash: crypto.createHash('sha256').update('maac2024').digest('hex')
  }, null, 2));
}

/* ─── DEFAULT BIKES DATA ────────────────────────────────── */
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify([
    {
      id: 1, brand: 'Royal Enfield', model: 'Classic 350',
      year: 2021, price: 135000, km: '18,500', engine: '349cc',
      type: 'Cruiser', color: 'Gunmetal Grey', owner: '1st Owner',
      condition: 'Excellent', badge: 'New', status: 'available',
      notes: 'Single owner, full service history.',
      imgs: []
    },
    {
      id: 2, brand: 'Honda', model: 'CB Shine SP',
      year: 2020, price: 52000, km: '24,200', engine: '125cc',
      type: 'Commuter', color: 'Matte Silver', owner: '1st Owner',
      condition: 'Good', badge: 'Hot Deal', status: 'available',
      notes: '', imgs: []
    },
    {
      id: 3, brand: 'Yamaha', model: 'FZ-S V3.0',
      year: 2022, price: 89000, km: '11,800', engine: '149cc',
      type: 'Sports', color: 'Midnight Black', owner: '1st Owner',
      condition: 'Excellent', badge: 'New', status: 'available',
      notes: '', imgs: []
    }
  ], null, 2));
}

/* ─── HELPERS ───────────────────────────────────────────── */
const readBikes  = () => JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
const writeBikes = (data) => fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
const readConfig = () => JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
const hashPass   = (p) => crypto.createHash('sha256').update(p).digest('hex');

/* ─── MULTER (IMAGE UPLOAD) ─────────────────────────────── */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext  = path.extname(file.originalname).toLowerCase();
    const name = Date.now() + '-' + Math.round(Math.random() * 1e6) + ext;
    cb(null, name);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB per image
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp/;
    cb(null, allowed.test(file.mimetype));
  }
});

/* ─── MIDDLEWARE ────────────────────────────────────────── */
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ─── AUTH MIDDLEWARE ───────────────────────────────────── */
function requireAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  const config = readConfig();
  // Token is SHA256(password) — admin sends it in every request header
  if (token && token === config.passwordHash) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

/* ═══════════════════════════════════════════════════════
   PUBLIC API ROUTES (no auth — website reads these)
═══════════════════════════════════════════════════════ */

// GET all available bikes (for website)
app.get('/api/bikes', (req, res) => {
  try {
    const bikes = readBikes();
    res.json({ success: true, bikes });
  } catch (e) {
    res.status(500).json({ error: 'Could not load bikes' });
  }
});

// GET single bike
app.get('/api/bikes/:id', (req, res) => {
  const bikes = readBikes();
  const bike  = bikes.find(b => b.id === Number(req.params.id));
  if (!bike) return res.status(404).json({ error: 'Bike not found' });
  res.json({ success: true, bike });
});

/* ═══════════════════════════════════════════════════════
   ADMIN API ROUTES (auth required)
═══════════════════════════════════════════════════════ */

// LOGIN — returns token (which is just the password hash)
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const config = readConfig();
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (hashPass(password) === config.passwordHash) {
    res.json({ success: true, token: config.passwordHash });
  } else {
    res.status(401).json({ error: 'Wrong password' });
  }
});

// CHANGE PASSWORD
app.post('/api/admin/change-password', requireAuth, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }
  const config = readConfig();
  config.passwordHash = hashPass(newPassword);
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  res.json({ success: true, token: config.passwordHash });
});

// GET all bikes (admin — includes sold)
app.get('/api/admin/bikes', requireAuth, (req, res) => {
  try {
    res.json({ success: true, bikes: readBikes() });
  } catch (e) {
    res.status(500).json({ error: 'Could not load bikes' });
  }
});

// ADD bike
app.post('/api/admin/bikes', requireAuth, (req, res) => {
  try {
    const bikes  = readBikes();
    const bike   = { ...req.body, id: Date.now() };
    bikes.unshift(bike);
    writeBikes(bikes);
    res.json({ success: true, bike });
  } catch (e) {
    res.status(500).json({ error: 'Could not save bike' });
  }
});

// UPDATE bike
app.put('/api/admin/bikes/:id', requireAuth, (req, res) => {
  try {
    const bikes = readBikes();
    const idx   = bikes.findIndex(b => b.id === Number(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'Bike not found' });
    bikes[idx] = { ...req.body, id: Number(req.params.id) };
    writeBikes(bikes);
    res.json({ success: true, bike: bikes[idx] });
  } catch (e) {
    res.status(500).json({ error: 'Could not update bike' });
  }
});

// DELETE bike
app.delete('/api/admin/bikes/:id', requireAuth, (req, res) => {
  try {
    const bikes   = readBikes();
    const updated = bikes.filter(b => b.id !== Number(req.params.id));
    writeBikes(updated);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Could not delete bike' });
  }
});

// UPLOAD images (up to 6)
app.post('/api/admin/upload', requireAuth, upload.array('images', 6), (req, res) => {
  try {
    const urls = req.files.map(f => `/uploads/${f.filename}`);
    res.json({ success: true, urls });
  } catch (e) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

// DELETE uploaded image
app.delete('/api/admin/upload', requireAuth, (req, res) => {
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ error: 'No filename' });
  const filepath = path.join(UPLOADS_DIR, path.basename(filename));
  try {
    if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Could not delete file' });
  }
});

/* ─── SERVE ADMIN PANEL ─────────────────────────────────── */
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

/* ─── SERVE WEBSITE ─────────────────────────────────────── */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ─── START ─────────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`\n✅ Maac True Value Bikes — Server running`);
  console.log(`   Website:   http://localhost:${PORT}`);
  console.log(`   Admin:     http://localhost:${PORT}/admin`);
  console.log(`   API:       http://localhost:${PORT}/api/bikes`);
  console.log(`\n   Default admin password: maac2024`);
  console.log(`   Change it at: POST /api/admin/change-password\n`);
});
