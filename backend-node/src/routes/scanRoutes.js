const express = require('express');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const scanController = require('../controllers/scanController');
const { requireAuth } = require('../middleware/authMiddleware');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });        // images, 10MB
const uploadMedia = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });   // audio/video, 100MB
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

router.use(requireAuth);

// The scan limiter applies to analyses only, so browsing or managing history is never throttled.
router.post('/text', scanLimiter, scanController.scanText);       // phishing: email/SMS/message
router.post('/url', scanLimiter, scanController.scanUrl);          // malicious URL / website (+ live redirect/SSL/fake-login checks)
router.post('/image', scanLimiter, upload.single('image'), scanController.scanImage);       // deepfake / impersonation (+ QR-code phishing)
router.post('/audio', scanLimiter, uploadMedia.single('audio'), scanController.scanAudio);   // voice-clone / audio deepfake
router.post('/video', scanLimiter, uploadMedia.single('video'), scanController.scanVideo);   // deepfake video (frame sampling)
router.post('/logs', scanLimiter, scanController.scanLogs);        // technical threat: malware/network/API-abuse/insider-threat/log analysis
router.get('/history', scanController.history);
router.delete('/history', scanController.clearHistory);            // reset: clear all of my scans (undoable for 60 s)
router.post('/restore', scanController.restoreScans);              // undo a delete / reset
router.get('/:id', scanController.getOne);
router.delete('/:id', scanController.removeScan);                  // delete one scan (undoable for 60 s)

module.exports = router;

