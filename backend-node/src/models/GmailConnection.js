const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const GmailConnection = sequelize.define('GmailConnection', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  userId: { type: DataTypes.UUID, field: 'user_id', unique: true },
  gmailAddress: { type: DataTypes.STRING, field: 'gmail_address' },
  refreshTokenEnc: { type: DataTypes.TEXT, field: 'refresh_token_enc' },
  scopes: { type: DataTypes.TEXT },
  connectedAt: { type: DataTypes.DATE, field: 'connected_at' },
  lastSyncAt: { type: DataTypes.DATE, field: 'last_sync_at' },
  messagesScanned: { type: DataTypes.INTEGER, field: 'messages_scanned', defaultValue: 0 },
}, {
  tableName: 'gmail_connections',
  underscored: true,
  timestamps: false,
});

module.exports = GmailConnection;
