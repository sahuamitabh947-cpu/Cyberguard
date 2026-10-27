const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const KnownDevice = sequelize.define('KnownDevice', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  userId: { type: DataTypes.UUID, field: 'user_id' },
  deviceFingerprint: { type: DataTypes.STRING, field: 'device_fingerprint' },
  firstSeenAt: { type: DataTypes.DATE, field: 'first_seen_at' },
}, {
  tableName: 'known_devices',
  underscored: true,
  timestamps: false,
});

module.exports = KnownDevice;
