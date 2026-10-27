const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');
const User = require('./User');

const Scan = sequelize.define('Scan', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  userId: { type: DataTypes.UUID, field: 'user_id' },
  scanType: { type: DataTypes.STRING, field: 'scan_type' }, // email | sms | url | image | audio | video | login_behavior | log_upload | network_pcap | network_live
  inputSummary: { type: DataTypes.TEXT, field: 'input_summary' },
  rawInputRef: { type: DataTypes.TEXT, field: 'raw_input_ref' },
  engineResult: { type: DataTypes.JSONB, field: 'engine_result' },
  aiResult: { type: DataTypes.JSONB, field: 'ai_result' },
  finalScore: { type: DataTypes.INTEGER, defaultValue: 0, field: 'final_score' },
  riskLevel: { type: DataTypes.STRING, defaultValue: 'Safe', field: 'risk_level' },
  recommendedAction: { type: DataTypes.TEXT, field: 'recommended_action' },
  status: { type: DataTypes.STRING, defaultValue: 'completed' },
  source: { type: DataTypes.STRING, defaultValue: 'manual' },           // manual | gmail | nids_sensor
  externalRef: { type: DataTypes.STRING, field: 'external_ref' },      // e.g. Gmail message id
  mlResult: { type: DataTypes.JSONB, field: 'ml_result' },             // C++ ML model outputs
  deletedAt: { type: DataTypes.DATE, field: 'deleted_at' },
}, {
  tableName: 'scans',
  underscored: true,
  timestamps: true,
  updatedAt: false,
  // Soft delete: destroy() sets deleted_at so a deletion can be undone for a short
  // time; every query ignores soft-deleted rows automatically. A purge job in
  // server.js removes them permanently after the undo window.
  paranoid: true,
  deletedAt: 'deletedAt',
});

Scan.belongsTo(User, { foreignKey: 'userId', as: 'user' });

module.exports = Scan;
