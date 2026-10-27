const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');
const Scan = require('./Scan');
const User = require('./User');

const Threat = sequelize.define('Threat', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  scanId: { type: DataTypes.UUID, field: 'scan_id' },
  authEventId: { type: DataTypes.UUID, field: 'auth_event_id' },
  category: { type: DataTypes.STRING }, // phishing | impersonation | deepfake | account_takeover | malicious_url | technical_threat
  riskLevel: { type: DataTypes.STRING, field: 'risk_level' },
  targetUserId: { type: DataTypes.UUID, field: 'target_user_id' },
  targetedService: { type: DataTypes.STRING, field: 'targeted_service' },
  recommendedAction: { type: DataTypes.TEXT, field: 'recommended_action' },
  status: { type: DataTypes.STRING, defaultValue: 'open' }, // open | investigating | mitigated | false_positive
  resolvedBy: { type: DataTypes.UUID, field: 'resolved_by' },
  resolvedAt: { type: DataTypes.DATE, field: 'resolved_at' },
  deletedAt: { type: DataTypes.DATE, field: 'deleted_at' },
}, {
  tableName: 'threats',
  underscored: true,
  timestamps: true,
  updatedAt: false,
  // Soft delete: destroy() sets deleted_at so a deletion can be undone for a short
  // time; every query ignores soft-deleted rows automatically. A purge job in
  // server.js removes them permanently after the undo window.
  paranoid: true,
  deletedAt: 'deletedAt',
});

Threat.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });
Threat.belongsTo(User, { foreignKey: 'targetUserId', as: 'targetUser' });

module.exports = Threat;
