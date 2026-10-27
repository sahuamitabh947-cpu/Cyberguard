const express = require('express');
const dashboardController = require('../controllers/dashboardController');
const { requireAuth } = require('../middleware/authMiddleware');

const router = express.Router();
router.use(requireAuth);

router.get('/summary', dashboardController.summary);
router.get('/targeted-users', dashboardController.targetedUsers);

module.exports = router;
