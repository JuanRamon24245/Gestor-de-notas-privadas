const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto_cambiar_en_produccion';
const DB_PATH = path.join(__dirname, 'db.json');

// ── Middlewares ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

// ── DB helpers ───────────────────────────────────────────────────────────────
function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], notes: [] }));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

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

// ── Validation helpers ───────────────────────────────────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── AUTH ROUTES ──────────────────────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Email no válido' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Las contraseñas no coinciden' });
    }

    const db = readDB();
    if (db.users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuidv4(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      created_at: new Date().toISOString()
    };
    db.users.push(newUser);
    writeDB(db);

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: newUser.id, email: newUser.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
    }

    const db = readDB();
    const user = db.users.find(u => u.email === email.toLowerCase().trim());
    if (!user) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── NOTES ROUTES (all protected) ─────────────────────────────────────────────

// GET /api/notes
app.get('/api/notes', authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const notes = db.notes
      .filter(n => n.user_id === req.user.id)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .map(({ id, titulo, contenido, created_at, updated_at }) => ({ id, titulo, contenido, created_at, updated_at }));
    res.json(notes);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// POST /api/notes
app.post('/api/notes', authMiddleware, (req, res) => {
  try {
    const { titulo, contenido } = req.body;
    if (!titulo || !titulo.trim()) {
      return res.status(400).json({ error: 'El título es obligatorio' });
    }
    if (!contenido || !contenido.trim()) {
      return res.status(400).json({ error: 'El contenido es obligatorio' });
    }
    if (titulo.trim().length > 200) {
      return res.status(400).json({ error: 'El título es demasiado largo (máx. 200 caracteres)' });
    }
    if (contenido.trim().length > 10000) {
      return res.status(400).json({ error: 'El contenido es demasiado largo (máx. 10.000 caracteres)' });
    }

    const db = readDB();
    const note = {
      id: uuidv4(),
      user_id: req.user.id,
      titulo: titulo.trim(),
      contenido: contenido.trim(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    db.notes.push(note);
    writeDB(db);

    const { user_id, ...safeNote } = note;
    res.status(201).json(safeNote);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/notes/:id
app.get('/api/notes/:id', authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const note = db.notes.find(n => n.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'Nota no encontrada' });
    if (note.user_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });

    const { user_id, ...safeNote } = note;
    res.json(safeNote);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// PUT /api/notes/:id
app.put('/api/notes/:id', authMiddleware, (req, res) => {
  try {
    const { titulo, contenido } = req.body;
    if (!titulo || !titulo.trim()) {
      return res.status(400).json({ error: 'El título es obligatorio' });
    }
    if (!contenido || !contenido.trim()) {
      return res.status(400).json({ error: 'El contenido es obligatorio' });
    }
    if (titulo.trim().length > 200) {
      return res.status(400).json({ error: 'El título es demasiado largo' });
    }
    if (contenido.trim().length > 10000) {
      return res.status(400).json({ error: 'El contenido es demasiado largo' });
    }

    const db = readDB();
    const idx = db.notes.findIndex(n => n.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Nota no encontrada' });
    if (db.notes[idx].user_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });

    db.notes[idx] = { ...db.notes[idx], titulo: titulo.trim(), contenido: contenido.trim(), updated_at: new Date().toISOString() };
    writeDB(db);

    const { user_id, ...safeNote } = db.notes[idx];
    res.json(safeNote);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// DELETE /api/notes/:id
app.delete('/api/notes/:id', authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const note = db.notes.find(n => n.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'Nota no encontrada' });
    if (note.user_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });

    db.notes = db.notes.filter(n => n.id !== req.params.id);
    writeDB(db);
    res.json({ message: 'Nota eliminada' });
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── Catch-all → SPA ──────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
