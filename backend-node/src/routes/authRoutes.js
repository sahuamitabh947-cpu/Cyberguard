const express = require('express');
const rateLimit = require('express-rate-limit');
const { passport, hasGoogleCreds } = require('../config/passport');
const authController = require('../controllers/authController');
const { requireAuth } = require('../middleware/authMiddleware');

const router = express.Router();

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

router.post('/register', authController.register);
router.post('/login', loginLimiter, authController.login);
router.get('/me', requireAuth, authController.me);

router.get('/google', (req, res, next) => {
  if (!hasGoogleCreds) return res.status(503).json({ error: 'Google login is not configured on this server yet' });
  if (!require('../services/systemMode').isOnline()) return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=offline`);
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

router.get('/google/callback',
  (req, res, next) => {
    if (!hasGoogleCreds) return res.status(503).json({ error: 'Google login is not configured on this server yet' });
    passport.authenticate('google', { session: false, failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=google_auth_failed` })(req, res, next);
  },
  authController.googleCallback
);

module.exports = router;
