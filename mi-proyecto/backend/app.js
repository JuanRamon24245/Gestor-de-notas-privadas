const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto_cambiar_en_produccion';

// ── PostgreSQL ───────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Crear tablas si no existen
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id UUID PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notas (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES usuarios(id) ON DELETE CASCADE,
      titulo VARCHAR(200) NOT NULL,
      contenido TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('Base de datos lista');
}

// ── Middlewares ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Servir estáticos SOLO si no es /api
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  express.static(path.join(__dirname, 'frontend'))(req, res, next);
});

// ── Auth middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autenticado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;
    if (!email || !password || !confirmPassword)
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    if (!isValidEmail(email))
      return res.status(400).json({ error: 'Email no válido' });
    if (password.length < 6)
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    if (password !== confirmPassword)
      return res.status(400).json({ error: 'Las contraseñas no coinciden' });

    const exists = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length > 0)
      return res.status(409).json({ error: 'El email ya está registrado' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    await pool.query(
      'INSERT INTO usuarios (id, email, password) VALUES ($1, $2, $3)',
      [id, email.toLowerCase().trim(), hashedPassword]
    );

    const token = jwt.sign({ id, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id, email: email.toLowerCase() } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email y contraseña son obligatorios' });

    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email.toLowerCase().trim()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── NOTES ROUTES ─────────────────────────────────────────────────────────────

app.get('/api/notes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, titulo, contenido, created_at, updated_at FROM notas WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/notes', authMiddleware, async (req, res) => {
  try {
    const { titulo, contenido } = req.body;
    if (!titulo || !titulo.trim()) return res.status(400).json({ error: 'El título es obligatorio' });
    if (!contenido || !contenido.trim()) return res.status(400).json({ error: 'El contenido es obligatorio' });
    if (titulo.trim().length > 200) return res.status(400).json({ error: 'Título demasiado largo' });
    if (contenido.trim().length > 10000) return res.status(400).json({ error: 'Contenido demasiado largo' });

    const id = uuidv4();
    const result = await pool.query(
      'INSERT INTO notas (id, user_id, titulo, contenido) VALUES ($1, $2, $3, $4) RETURNING id, titulo, contenido, created_at, updated_at',
      [id, req.user.id, titulo.trim(), contenido.trim()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/notes/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notas WHERE id = $1', [req.params.id]);
    const note = result.rows[0];
    if (!note) return res.status(404).json({ error: 'Nota no encontrada' });
    if (note.user_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });

    const { user_id, ...safeNote } = note;
    res.json(safeNote);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.put('/api/notes/:id', authMiddleware, async (req, res) => {
  try {
    const { titulo, contenido } = req.body;
    if (!titulo || !titulo.trim()) return res.status(400).json({ error: 'El título es obligatorio' });
    if (!contenido || !contenido.trim()) return res.status(400).json({ error: 'El contenido es obligatorio' });
    if (titulo.trim().length > 200) return res.status(400).json({ error: 'Título demasiado largo' });
    if (contenido.trim().length > 10000) return res.status(400).json({ error: 'Contenido demasiado largo' });

    const check = await pool.query('SELECT user_id FROM notas WHERE id = $1', [req.params.id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Nota no encontrada' });
    if (check.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });

    const result = await pool.query(
      'UPDATE notas SET titulo = $1, contenido = $2, updated_at = NOW() WHERE id = $3 RETURNING id, titulo, contenido, created_at, updated_at',
      [titulo.trim(), contenido.trim(), req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.delete('/api/notes/:id', authMiddleware, async (req, res) => {
  try {
    const check = await pool.query('SELECT user_id FROM notas WHERE id = $1', [req.params.id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Nota no encontrada' });
    if (check.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });

    await pool.query('DELETE FROM notas WHERE id = $1', [req.params.id]);
    res.json({ message: 'Nota eliminada' });
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Ruta no encontrada' });
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// ── Arrancar ─────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));
}).catch(err => {
  console.error('Error conectando a la base de datos:', err);
  process.exit(1);
});
