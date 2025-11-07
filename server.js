require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const JWT_SECRET = process.env.JWT_SECRET || 'cambia_esto';
const PORT = process.env.PORT || 3000;

async function initDb() {
  const db = await open({ filename: './lacustre.db', driver: sqlite3.Database });
  await db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      phone TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT CHECK(role IN ('patient','driver','admin')) NOT NULL DEFAULT 'patient',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS units (
      id TEXT PRIMARY KEY,
      name TEXT,
      plate TEXT,
      driver_id TEXT,
      lat REAL,
      lng REAL,
      status TEXT CHECK(status IN ('available','en_ruta','ocupada','offline')) DEFAULT 'available',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(driver_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS rides (
      id TEXT PRIMARY KEY,
      patient_id TEXT,
      unit_id TEXT,
      origin_lat REAL,
      origin_lng REAL,
      origin_address TEXT,
      dest_lat REAL,
      dest_lng REAL,
      dest_address TEXT,
      type TEXT CHECK(type IN ('normal','urgencia')) DEFAULT 'normal',
      status TEXT CHECK(status IN ('pendiente','asignada','en_ruta','en_lugar','embarcardo','finalizado','cancelado')) DEFAULT 'pendiente',
      notes TEXT,
      estimated_cost REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      started_at DATETIME,
      finished_at DATETIME,
      FOREIGN KEY(patient_id) REFERENCES users(id),
      FOREIGN KEY(unit_id) REFERENCES units(id)
    );
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      ride_id TEXT,
      type TEXT,
      meta TEXT,
      ts DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(ride_id) REFERENCES rides(id)
    );
  `);
  return db;
}

function haversine(lat1, lon1, lat2, lon2) {
  function toRad(x){ return x * Math.PI / 180; }
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat/2)*Math.sin(dLat/2) + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)*Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

(async () => {
  const db = await initDb();
  const app = express();
  const server = http.createServer(app);
  const io = new Server(server, { cors: { origin: '*' } });

  app.use(cors());
  app.use(express.json());

  const socketsByUser = {};
  io.on('connection', (socket) => {
    socket.on('register', ({ userId }) => {
      if (userId) socketsByUser[userId] = socket.id;
    });
    socket.on('disconnect', () => {
      for (const [uid, sid] of Object.entries(socketsByUser)) {
        if (sid === socket.id) delete socketsByUser[uid];
      }
    });
  });

  function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Cabecera de autorización faltante' });
    const token = auth.split(' ')[1];
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      return next();
    } catch (e) {
      return res.status(401).json({ error: 'Token inválido' });
    }
  }

  // --- Registro y login ---
  app.post('/auth/register', async (req, res) => {
    const { name, email, phone, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
    const existing = await db.get('SELECT id FROM users WHERE email = ?', email);
    if (existing) return res.status(400).json({ error: 'El email ya está registrado' });
    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)',
      id, name || '', phone || '', email, hashed, role || 'patient');
    const token = jwt.sign({ id, email, role: role || 'patient' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id, name, email, phone, role: role || 'patient' } });
  });

  app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
    const u = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (!u) return res.status(401).json({ error: 'Usuario no encontrado' });
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    const token = jwt.sign({ id: u.id, email: u.email, role: u.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role } });
  });

  // --- Crear unidad ---
  app.post('/units', authMiddleware, async (req, res) => {
    if (!['admin'].includes(req.user.role)) return res.status(403).json({ error: 'Solo admin' });
    const { name, plate, driver_id, lat, lng } = req.body;
    const id = uuidv4();
    await db.run(
      'INSERT INTO units (id,name,plate,driver_id,lat,lng,status) VALUES (?,?,?,?,?,?,?)',
      id, name || `Unidad ${id}`, plate || '', driver_id || null, lat || 0, lng || 0, 'available'
    );
    const unit = await db.get('SELECT * FROM units WHERE id = ?', id);
    res.json({ unit });
  });

  // --- Resto de endpoints y seed de prueba ---
  app.post('/seed/crear-prueba', async (req, res) => {
    try {
      const adminEmail = 'admin@lacustre.test';
      const existingAdmin = await db.get('SELECT * FROM users WHERE email = ?', adminEmail);
      if (!existingAdmin) {
        const adminId = uuidv4();
        const hashed = await bcrypt.hash('admin123', 10);
        await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)',
          adminId, 'Admin Lacustre', '+56900000000', adminEmail, hashed, 'admin');
      }
      const driverEmail = 'juan.driver@lacustre.test';
      let driver = await db.get('SELECT * FROM users WHERE email = ?', driverEmail);
      if (!driver) {
        const driverId = uuidv4();
        const hashed = await bcrypt.hash('conductor1', 10);
        await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)',
          driverId, 'Juan Conductor', '+56911111111', driverEmail, hashed, 'driver');
        await db.run('INSERT INTO units (id,name,plate,driver_id,lat,lng,status) VALUES (?,?,?,?,?,?,?)',
          uuidv4(), 'Unidad Puerto Varas', 'PV-001', driverId, -41.3195, -72.9974, 'available');
      }
      const patientEmail = 'paciente@lacustre.test';
      let patient = await db.get('SELECT * FROM users WHERE email = ?', patientEmail);
      if (!patient) {
        const pid = uuidv4();
        const hashed = await bcrypt.hash('paciente123', 10);
        await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)',
          pid, 'Paciente Prueba', '+56922222222', patientEmail, hashed, 'patient');
        patient = await db.get('SELECT * FROM users WHERE email = ?', patientEmail);
      }
      const existingRide = await db.get('SELECT * FROM rides WHERE origin_address = ? AND dest_address = ?', 'Puerto Varas', 'Frutillar');
      if (!existingRide) {
        const rideId = uuidv4();
        await db.run(`INSERT INTO rides (id, patient_id, origin_lat, origin_lng, origin_address, dest_lat, dest_lng, dest_address, type, notes) VALUES (?,?,?,?,?,?,?,?,?,?)`,
          rideId, patient.id, -41.3195, -72.9974, 'Puerto Varas', -41.1236, -73.0356, 'Frutillar', 'normal', 'Traslado de prueba: Varas -> Frutillar');
      }
      res.json({ message: 'Datos de prueba creados (Puerto Varas -> Frutillar).' });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Error al crear datos de prueba.' });
    }
  });

  app.get('/', (req,res) => res.send('Ambulancias Lacustre API OK - Español'));

  server.listen(PORT, () => console.log(`Servidor escuchando en http://localhost:${PORT}`));
})();