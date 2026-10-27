const express = require('express');
const rateLimit = require('express-rate-limit');
const gmailController = require('../controllers/gmailController');
const { requireAuth } = require('../middleware/authMiddleware');
const { requireOnline } = require('../services/systemMode');

const router = express.Router();
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 6, standardHeaders: true, legacyHeaders: false });

// Google redirects the browser here (no JWT header): the signed `state` identifies the user.
router.get('/callback', gmailController.callback);

router.use(requireAuth);
router.get('/status', gmailController.status);
router.post('/connect', requireOnline('Connecting Gmail'), gmailController.connect);
router.post('/disconnect', gmailController.disconnect);
router.post('/scan', requireOnline('Scanning the Gmail inbox'), scanLimiter, gmailController.scanInbox);
router.get('/messages', gmailController.messages);

module.exports = router;
