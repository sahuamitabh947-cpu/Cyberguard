const express = require('express');
const multer = require('multer');
const nidsController = require('../controllers/nidsController');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

// Sensor push is authenticated with the shared engine/sensor key, not a user JWT.
router.post('/ingest', express.json({ limit: '10mb' }), nidsController.ingest);

router.use(requireAuth);
router.post('/pcap', upload.single('capture'), nidsController.uploadPcap);
router.get('/events', nidsController.events);
// Live capture touches the host network, so it is limited to admins / SOC analysts.
router.get('/interfaces', requireRole('admin', 'soc_analyst'), nidsController.interfaces);
router.post('/live/start', requireRole('admin', 'soc_analyst'), nidsController.liveStart);
router.post('/live/stop', requireRole('admin', 'soc_analyst'), nidsController.liveStop);
router.get('/live/status', requireRole('admin', 'soc_analyst'), nidsController.liveStatus);

module.exports = router;
