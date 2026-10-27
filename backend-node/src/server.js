require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const { passport } = require('./config/passport');
const sequelize = require('./config/db');
const engineClient = require('./services/engineClient');
const systemMode = require('./services/systemMode');
const { purgeDeleted } = require('./controllers/scanController');

const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const adminRoutes = require('./routes/adminRoutes');
const nidsRoutes = require('./routes/nidsRoutes');
const gmailRoutes = require('./routes/gmailRoutes');
const mlRoutes = require('./routes/mlRoutes');
const { runMigrations } = require('./config/migrations');

const app = express();
const PORT = process.env.PORT || 4000;

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Session is only used to carry Passport's OAuth handshake state; the app
// itself is stateless and authenticates every request via the JWT issued
// after that handshake completes (see authController.googleCallback).
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-in-.env',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 10 * 60 * 1000 },
}));
app.use(passport.initialize());
app.use(passport.session());

const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false });
app.use(globalLimiter);

app.get('/api/health', async (req, res) => {
  let engineStatus = 'unreachable';
  let modelsLoaded = [];
  let livePcap = false;
  try {
    const h = await engineClient.healthCheck();
    engineStatus = 'ok';
    modelsLoaded = h.modelsLoaded || [];
    livePcap = Boolean(h.livePcapSupported);
  } catch (e) { /* leave as unreachable */ }
  let dbStatus = 'unreachable';
  try {
    await sequelize.authenticate();
    dbStatus = 'ok';
  } catch (e) { /* leave as unreachable */ }
  res.json({ status: 'ok', service: 'cyberguard-backend', detectionEngine: engineStatus, database: dbStatus, modelsLoaded, livePcapSupported: livePcap });
});

// Online / offline status for the UI badge and feature gating (no secrets exposed).
app.get('/api/system/status', (req, res) => res.json(systemMode.status()));

// Every analysis response states whether it ran online or offline, so a partial
// (offline) check is never mistaken for a full one.
app.use(['/api/scan', '/api/gmail', '/api/nids'], (req, res, next) => {
  const json = res.json.bind(res);
  res.json = (body) => json(body && typeof body === 'object' && !Array.isArray(body) && !body.error && req.method === 'POST' && body.riskLevel !== undefined
    ? { ...body, analysisMode: systemMode.effective() } : body);
  next();
});

app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/nids', nidsRoutes);
app.use('/api/gmail', gmailRoutes);
app.use('/api/ml', mlRoutes);

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

async function start() {
  try {
    await sequelize.authenticate();
    console.log('[db] Connected to PostgreSQL');
    await runMigrations();
  } catch (err) {
    console.error('[db] Could not connect to PostgreSQL — did you run database/init.sql and set DATABASE_URL?', err.message);
  }
  systemMode.start();
  console.log(`[mode] CYBERGUARD_MODE=${systemMode.MODE}`);
  // Permanently remove scans whose undo window has passed. Errors never crash the server.
  const purge = setInterval(() => { purgeDeleted().catch((e) => console.warn('[purge]', e.message)); }, 20000);
  if (purge.unref) purge.unref();
  app.listen(PORT, () => console.log(`CyberGuard backend listening on port ${PORT}`));
}

// A failed background task must never take the whole API down.
process.on('unhandledRejection', (reason) => console.error('[unhandledRejection]', reason));

start();

module.exports = app;
