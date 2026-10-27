const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const AuthEvent = sequelize.define('AuthEvent', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  userId: { type: DataTypes.UUID, field: 'user_id' },
  emailAttempted: { type: DataTypes.STRING, field: 'email_attempted' },
  ipAddress: { type: DataTypes.STRING, field: 'ip_address' },
  deviceFingerprint: { type: DataTypes.STRING, field: 'device_fingerprint' },
  latitude: { type: DataTypes.DOUBLE },
  longitude: { type: DataTypes.DOUBLE },
  success: { type: DataTypes.BOOLEAN, allowNull: false },
  failedAttempts15min: { type: DataTypes.INTEGER, defaultValue: 0, field: 'failed_attempts_15min' },
  riskScore: { type: DataTypes.INTEGER, field: 'risk_score' },
  riskLevel: { type: DataTypes.STRING, field: 'risk_level' },
  findings: { type: DataTypes.JSONB },
  mlResult: { type: DataTypes.JSONB, field: 'ml_result' },
}, {
  tableName: 'auth_events',
  underscored: true,
  timestamps: true,
  updatedAt: false,
});

module.exports = AuthEvent;
