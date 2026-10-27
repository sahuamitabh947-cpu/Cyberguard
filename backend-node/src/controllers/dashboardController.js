const { Op, fn, col, literal } = require('sequelize');
const Scan = require('../models/Scan');
const Threat = require('../models/Threat');
const User = require('../models/User');

async function summary(req, res) {
  const isAdmin = req.user.role === 'admin';
  const scanWhere = isAdmin ? {} : { userId: req.user.id };
  const threatWhere = isAdmin ? {} : { targetUserId: req.user.id };

  const [totalEvents, riskCounts, categoryCounts, openThreats, recentThreats, timeline] = await Promise.all([
    Scan.count({ where: scanWhere }),
    Scan.findAll({ where: scanWhere, attributes: ['riskLevel', [fn('COUNT', col('id')), 'count']], group: ['riskLevel'] }),
    Threat.findAll({ where: threatWhere, attributes: ['category', [fn('COUNT', col('id')), 'count']], group: ['category'] }),
    Threat.count({ where: { ...threatWhere, status: 'open' } }),
    Threat.findAll({ where: threatWhere, order: [['createdAt', 'DESC']], limit: 10, include: [{ model: Scan, as: 'scan' }] }),
    Scan.findAll({
      where: { ...scanWhere, createdAt: { [Op.gte]: literal("NOW() - INTERVAL '14 days'") } },
      attributes: [[fn('DATE', col('created_at')), 'day'], [fn('COUNT', col('id')), 'count']],
      group: [literal('day')],
      order: [[literal('day'), 'ASC']],
    }),
  ]);

  const byScanType = await Scan.findAll({
    where: scanWhere,
    attributes: ['scanType', [fn('COUNT', col('id')), 'count']],
    group: ['scanType'],
  });

  res.json({
    totalEventsAnalysed: totalEvents,
    threatsDetected: await Threat.count({ where: threatWhere }),
    openThreats,
    riskBreakdown: riskCounts.map(r => ({ riskLevel: r.riskLevel, count: Number(r.get('count')) })),
    categoryBreakdown: categoryCounts.map(c => ({ category: c.category, count: Number(c.get('count')) })),
    scanTypeBreakdown: byScanType.map(s => ({ scanType: s.scanType, count: Number(s.get('count')) })),
    attackTimeline: timeline.map(t => ({ day: t.get('day'), count: Number(t.get('count')) })),
    recentThreats,
  });
}

async function targetedUsers(req, res) {
  const isAdmin = req.user.role === 'admin';
  if (!isAdmin) return res.status(403).json({ error: 'Admin access required' });

  const results = await Threat.findAll({
    attributes: ['targetUserId', [fn('COUNT', col('Threat.id')), 'count']],
    include: [{ model: User, as: 'targetUser', attributes: ['id', 'fullName', 'email'] }],
    group: ['targetUserId', 'targetUser.id'],
    order: [[literal('count'), 'DESC']],
    limit: 10,
  });
  res.json({ targetedUsers: results });
}

module.exports = { summary, targetedUsers };
