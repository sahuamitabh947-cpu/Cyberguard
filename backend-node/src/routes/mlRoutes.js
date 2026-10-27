const express = require('express');
const { Op } = require('sequelize');
const engineClient = require('../services/engineClient');
const AuthEvent = require('../models/AuthEvent');
const User = require('../models/User');
const AdminAuditLog = require('../models/AdminAuditLog');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();
router.use(requireAuth);

// Model cards: algorithm, dataset, held-out evaluation metrics for every C++ model.
router.get('/models', async (req, res) => {
  try {
    res.json({ models: await engineClient.modelCards() });
  } catch (e) {
    res.status(502).json({ error: 'Detection engine unreachable', detail: e.message });
  }
});

// Retrain the login-anomaly Isolation Forest on this deployment's own
// successful logins (unsupervised: learns what normal looks like here).
router.post('/retrain/login', requireRole('admin'), async (req, res) => {
  try {
    const events = await AuthEvent.findAll({
      where: { success: true, createdAt: { [Op.gte]: new Date(Date.now() - 180 * 86400000) } },
      order: [['createdAt', 'ASC']], limit: 50000,
    });
    const users = new Map((await User.findAll({ attributes: ['id', 'avgLoginHour', 'loginHourStddev'] })).map((u) => [u.id, u]));
    const lastByUser = new Map();
    const rows = [];
    for (const e of events) {
      const u = users.get(e.userId);
      const prev = lastByUser.get(e.userId);
      const toRad = (d) => (d * Math.PI) / 180;
      let distanceKm = 0;
      if (prev && prev.latitude != null && e.latitude != null) {
        const dLat = toRad(e.latitude - prev.latitude), dLon = toRad(e.longitude - prev.longitude);
        const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(prev.latitude)) * Math.cos(toRad(e.latitude)) * Math.sin(dLon / 2) ** 2;
        distanceKm = 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      }
      rows.push({
        hourOfDay: new Date(e.createdAt).getHours(), failedAttemptsLast15Min: e.failedAttempts15min || 0, isKnownDevice: true,
        distanceKm, minutesSinceLastLogin: prev ? (new Date(e.createdAt) - new Date(prev.createdAt)) / 60000 : 1440,
        avgLoginHour: Number(u?.avgLoginHour) || 13, loginHourStdDev: Number(u?.loginHourStddev) || 4,
      });
      lastByUser.set(e.userId, e);
    }
    const result = await engineClient.retrainLogin(rows);
    await AdminAuditLog.create({ adminId: req.user.id, action: 'ML_RETRAIN_LOGIN_MODEL', targetType: 'model', details: { samples: rows.length, result } });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Retraining failed', detail: e.response?.data?.error || e.message });
  }
});

module.exports = router;
