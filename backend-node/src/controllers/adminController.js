const User = require('../models/User');
const Threat = require('../models/Threat');
const Scan = require('../models/Scan');
const AdminAuditLog = require('../models/AdminAuditLog');

async function listUsers(req, res) {
  const users = await User.findAll({
    attributes: ['id', 'email', 'fullName', 'role', 'isActive', 'organisation', 'lastLoginAt', 'createdAt'],
    order: [['createdAt', 'DESC']],
  });
  res.json({ users });
}

async function setUserActive(req, res) {
  const { id } = req.params;
  const { isActive } = req.body;
  const user = await User.findByPk(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.isActive = Boolean(isActive);
  await user.save();
  await AdminAuditLog.create({
    adminId: req.user.id, action: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
    targetType: 'user', targetId: user.id,
  });
  res.json({ user: { id: user.id, isActive: user.isActive } });
}

async function setUserRole(req, res) {
  const { id } = req.params;
  const { role } = req.body;
  if (!['user', 'admin', 'soc_analyst'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const user = await User.findByPk(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const previousRole = user.role;
  user.role = role;
  await user.save();
  await AdminAuditLog.create({
    adminId: req.user.id, action: 'USER_ROLE_CHANGE', targetType: 'user', targetId: user.id,
    details: { previousRole, newRole: role },
  });
  res.json({ user: { id: user.id, role: user.role } });
}

async function listThreats(req, res) {
  const { status } = req.query;
  const where = status ? { status } : {};
  const threats = await Threat.findAll({
    where, order: [['createdAt', 'DESC']], limit: 200,
    include: [{ model: Scan, as: 'scan' }],
  });
  res.json({ threats });
}

async function updateThreatStatus(req, res) {
  const { id } = req.params;
  const { status } = req.body;
  if (!['open', 'investigating', 'mitigated', 'false_positive'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  const threat = await Threat.findByPk(id);
  if (!threat) return res.status(404).json({ error: 'Threat not found' });
  const previousStatus = threat.status;
  threat.status = status;
  if (status === 'mitigated' || status === 'false_positive') {
    threat.resolvedBy = req.user.id;
    threat.resolvedAt = new Date();
  }
  await threat.save();
  await AdminAuditLog.create({
    adminId: req.user.id, action: 'THREAT_STATUS_CHANGE', targetType: 'threat', targetId: threat.id,
    details: { previousStatus, newStatus: status },
  });
  res.json({ threat });
}

async function auditLog(req, res) {
  const logs = await AdminAuditLog.findAll({ order: [['createdAt', 'DESC']], limit: 200 });
  res.json({ logs });
}

module.exports = { listUsers, setUserActive, setUserRole, listThreats, updateThreatStatus, auditLog };
