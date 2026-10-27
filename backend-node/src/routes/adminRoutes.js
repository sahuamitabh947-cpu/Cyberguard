const express = require('express');
const adminController = require('../controllers/adminController');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

router.get('/users', adminController.listUsers);
router.patch('/users/:id/active', adminController.setUserActive);
router.patch('/users/:id/role', adminController.setUserRole);

router.get('/threats', adminController.listThreats);
router.patch('/threats/:id/status', adminController.updateThreatStatus);

router.get('/audit-log', adminController.auditLog);

module.exports = router;
