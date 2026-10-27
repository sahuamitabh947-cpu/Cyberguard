const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const AdminAuditLog = sequelize.define('AdminAuditLog', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  adminId: { type: DataTypes.UUID, field: 'admin_id' },
  action: { type: DataTypes.STRING, allowNull: false },
  targetType: { type: DataTypes.STRING, field: 'target_type' },
  targetId: { type: DataTypes.UUID, field: 'target_id' },
  details: { type: DataTypes.JSONB },
}, {
  tableName: 'admin_audit_log',
  underscored: true,
  timestamps: true,
  updatedAt: false,
});

module.exports = AdminAuditLog;
