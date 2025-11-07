// server.js - Ambulancias Lacustre (ES) - listo para Railway
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

  app.post('/auth/register', async (req, res) => {
    const { name, email, phone, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email y password requeridos' });
    const existing = await db.get('SELECT id FROM users WHERE email = ?', email);
    if (existing) return res.status(400).json({ error: 'El email ya está registrado' });
    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)', id, name || '', phone || '', email, hashed, role || 'patient');
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

  app.post('/units', authMiddleware, async (req, res) => {
    if (!['admin'].includes(req.user.role)) return res.status(403).json({ error: 'Solo admin' });
    const { name, plate, driver_id, lat, lng } = req.body;
    const id = uuidv4();
    await db.run('INSERT INTO units (id,name,plate,driver_id,lat,lng,status) VALUES (?,?,?,?,?,?)', id, name || `Unidad ${id}`, plate || '', driver_id || null, lat || 0, lng || 0, 'available');
    const unit = await db.get('SELECT * FROM units WHERE id = ?', id);
    res.json({ unit });
  });

  app.get('/units/nearby', authMiddleware, async (req, res) => {
    const { lat, lng, radius = 10 } = req.query;
    if (!lat || !lng) return res.status(400).json({ error: 'lat y lng requeridos' });
    const rows = await db.all('SELECT * FROM units WHERE status = "available"');
    const nearby = rows.map(r => ({ ...r, distance_km: haversine(parseFloat(lat), parseFloat(lng), r.lat, r.lng)}))
                      .filter(r => r.distance_km <= Number(radius))
                      .sort((a,b) => a.distance_km - b.distance_km);
    res.json({ count: nearby.length, nearby });
  });

  app.post('/rides', authMiddleware, async (req, res) => {
    const { origin_lat, origin_lng, origin_address, dest_lat, dest_lng, dest_address, type, notes } = req.body;
    const id = uuidv4();
    await db.run(`
      INSERT INTO rides (id, patient_id, origin_lat, origin_lng, origin_address, dest_lat, dest_lng, dest_address, type, notes)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `, id, req.user.id, origin_lat, origin_lng, origin_address, dest_lat, dest_lng, dest_address, type || 'normal', notes || '');
    const ride = await db.get('SELECT * FROM rides WHERE id = ?', id);
    await db.run('INSERT INTO events (id,ride_id,type,meta) VALUES (?,?,?,?)', uuidv4(), id, 'created', JSON.stringify({ by: req.user.id }));
    setTimeout(() => autoAssignRide(id), 2000);
    res.json({ ride, message: 'Solicitud creada. Intentando asignar unidad...' });
  });

  app.get('/rides/:id', authMiddleware, async (req,res) => {
    const ride = await db.get('SELECT * FROM rides WHERE id = ?', req.params.id);
    if (!ride) return res.status(404).json({ error: 'Traslado no encontrado' });
    res.json({ ride });
  });

  app.get('/rides', authMiddleware, async (req,res) => {
    const { role, id: userId } = req.user;
    let rows;
    if (role === 'admin') rows = await db.all('SELECT * FROM rides ORDER BY created_at DESC');
    else rows = await db.all('SELECT * FROM rides WHERE patient_id = ? OR unit_id IN (SELECT id FROM units WHERE driver_id = ?) ORDER BY created_at DESC', userId, userId);
    res.json({ count: rows.length, rides: rows });
  });

  app.post('/rides/:id/assign', authMiddleware, async (req,res) => {
    if (!['admin'].includes(req.user.role)) return res.status(403).json({ error: 'Solo admin puede asignar manualmente' });
    const { unit_id } = req.body;
    const ride = await db.get('SELECT * FROM rides WHERE id = ?', req.params.id);
    if (!ride) return res.status(404).json({ error: 'Traslado no encontrado' });
    if (ride.status !== 'pendiente') return res.status(400).json({ error: 'Traslado no está en estado pendiente' });
    const unit = await db.get('SELECT * FROM units WHERE id = ?', unit_id);
    if (!unit) return res.status(404).json({ error: 'Unidad no encontrada' });
    await db.run('UPDATE rides SET unit_id = ?, status = ? WHERE id = ?', unit_id, 'asignada', ride.id);
    await db.run('UPDATE units SET status = ? WHERE id = ?', 'en_ruta', unit_id);
    await db.run('INSERT INTO events (id,ride_id,type,meta) VALUES (?,?,?,?)', uuidv4(), ride.id, 'assigned', JSON.stringify({ unit: unit_id }));
    if (unit.driver_id && socketsByUser[unit.driver_id]) {
      io.to(socketsByUser[unit.driver_id]).emit('ride_assigned', { rideId: ride.id, unit: unit });
    }
    res.json({ message: 'Asignado', rideId: ride.id, unit });
  });

  app.patch('/rides/:id/status', authMiddleware, async (req,res) => {
    const { status } = req.body;
    const ride = await db.get('SELECT * FROM rides WHERE id = ?', req.params.id);
    if (!ride) return res.status(404).json({ error: 'Traslado no encontrado' });
    if (req.user.role !== 'admin') {
      if (!ride.unit_id) return res.status(403).json({ error: 'Sin unidad asignada' });
      const unit = await db.get('SELECT * FROM units WHERE id = ?', ride.unit_id);
      if (!unit || unit.driver_id !== req.user.id) return res.status(403).json({ error: 'No autorizado' });
    }
    const allowed = ['asignada','en_ruta','en_lugar','embarcardo','finalizado','cancelado'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Estado inválido' });
    const updates = [];
    if (status === 'en_ruta') updates.push('started_at = CURRENT_TIMESTAMP');
    if (status === 'finalizado') updates.push('finished_at = CURRENT_TIMESTAMP');
    await db.run(`UPDATE rides SET status = ?, ${updates.join(', ')} WHERE id = ?`, status, ride.id);
    await db.run('INSERT INTO events (id,ride_id,type,meta) VALUES (?,?,?,?)', uuidv4(), ride.id, 'status_changed', JSON.stringify({ status, by: req.user.id }));
    if (status === 'finalizado' && ride.unit_id) {
      await db.run('UPDATE units SET status = ? WHERE id = ?', 'available', ride.unit_id);
    }
    const patient = await db.get('SELECT * FROM users WHERE id = ?', ride.patient_id);
    if (patient && socketsByUser[patient.id]) {
      io.to(socketsByUser[patient.id]).emit('ride_update', { rideId: ride.id, status });
    }
    res.json({ message: 'Estado actualizado', rideId: ride.id, status });
  });

  async function autoAssignRide(rideId) {
    const ride = await db.get('SELECT * FROM rides WHERE id = ?', rideId);
    if (!ride || ride.status !== 'pendiente') return;
    const units = await db.all('SELECT * FROM units WHERE status = "available"');
    if (!units || units.length === 0) {
      console.log(`[autoAssign] No hay unidades disponibles para ride ${rideId}`);
      return;
    }
    let nearest = null;
    let bestDist = Infinity;
    for (const u of units) {
      const d = haversine(ride.origin_lat, ride.origin_lng, u.lat, u.lng);
      if (d < bestDist) { bestDist = d; nearest = u; }
    }
    if (bestDist > 200) {
      console.log(`[autoAssign] Unidades muy lejos (${bestDist} km). No asigno.`);
      return;
    }
    await db.run('UPDATE rides SET unit_id = ?, status = ? WHERE id = ?', nearest.id, 'asignada', ride.id);
    await db.run('UPDATE units SET status = ? WHERE id = ?', 'en_ruta', nearest.id);
    await db.run('INSERT INTO events (id,ride_id,type,meta) VALUES (?,?,?,?)', uuidv4(), ride.id, 'auto_assigned', JSON.stringify({ unit: nearest.id, distance_km: bestDist }));
    if (nearest.driver_id && socketsByUser[nearest.driver_id]) {
      io.to(socketsByUser[nearest.driver_id]).emit('ride_assigned', { rideId: ride.id, unit: nearest });
    }
    if (ride.patient_id && socketsByUser[ride.patient_id]) {
      io.to(socketsByUser[ride.patient_id]).emit('ride_update', { rideId: ride.id, status: 'asignada', unit: nearest });
    }
    console.log(`[autoAssign] Ride ${rideId} asignado a unidad ${nearest.id} (dist ${bestDist.toFixed(2)} km)`);
  }

  # Endpoint for seed created omitted here to avoid syntax issues in python environment
  # We'll add a simple seed endpoint below using plain JS syntax

  app.post('/seed/crear-prueba', async (req, res) => {
    try {
      const adminEmail = 'admin@lacustre.test';
      const existingAdmin = await db.get('SELECT * FROM users WHERE email = ?', adminEmail);
      if (!existingAdmin) {
        const adminId = uuidv4();
        const hashed = await bcrypt.hash('admin123', 10);
        await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)', adminId, 'Admin Lacustre', '+56900000000', adminEmail, hashed, 'admin');
      }
      const driverEmail = 'juan.driver@lacustre.test';
      let driver = await db.get('SELECT * FROM users WHERE email = ?', driverEmail);
      if (!driver) {
        const driverId = uuidv4();
        const hashed = await bcrypt.hash('conductor1', 10);
        await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)', driverId, 'Juan Conductor', '+56911111111', driverEmail, hashed, 'driver');
        await db.run('INSERT INTO units (id,name,plate,driver_id,lat,lng,status) VALUES (?,?,?,?,?,?,?)', uuidv4(), 'Unidad Puerto Varas', 'PV-001', driverId, -41.3195, -72.9974, 'available');
      } else {
        const u = await db.get('SELECT * FROM units WHERE driver_id = ?', driver.id);
        if (!u) {
          await db.run('INSERT INTO units (id,name,plate,driver_id,lat,lng,status) VALUES (?,?,?,?,?,?,?)', uuidv4(), 'Unidad Puerto Varas', 'PV-001', driver.id, -41.3195, -72.9974, 'available');
        }
      }
      const patientEmail = 'paciente@lacustre.test';
      let patient = await db.get('SELECT * FROM users WHERE email = ?', patientEmail);
      if (!patient) {
        const pid = uuidv4();
        const hashed = await bcrypt.hash('paciente123', 10);
        await db.run('INSERT INTO users (id,name,phone,email,password,role) VALUES (?,?,?,?,?,?)', pid, 'Paciente Prueba', '+56922222222', patientEmail, hashed, 'patient');
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

  server.listen(PORT, () => {
    console.log(`Servidor Ambulancias Lacustre escuchando en http://localhost:${PORT}`);
  });

})();
