const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const User = sequelize.define('User', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  email: { type: DataTypes.STRING, unique: true, allowNull: false },
  fullName: { type: DataTypes.STRING, allowNull: false, field: 'full_name' },
  passwordHash: { type: DataTypes.STRING, field: 'password_hash' },
  googleId: { type: DataTypes.STRING, unique: true, field: 'google_id' },
  avatarUrl: { type: DataTypes.TEXT, field: 'avatar_url' },
  role: { type: DataTypes.STRING, defaultValue: 'user' }, // user | admin | soc_analyst
  isActive: { type: DataTypes.BOOLEAN, defaultValue: true, field: 'is_active' },
  organisation: { type: DataTypes.STRING },
  avgLoginHour: { type: DataTypes.DECIMAL, defaultValue: 13.0, field: 'avg_login_hour' },
  loginHourStddev: { type: DataTypes.DECIMAL, defaultValue: 4.0, field: 'login_hour_stddev' },
  lastLoginAt: { type: DataTypes.DATE, field: 'last_login_at' },
  lastLoginLat: { type: DataTypes.DOUBLE, field: 'last_login_lat' },
  lastLoginLon: { type: DataTypes.DOUBLE, field: 'last_login_lon' },
}, {
  tableName: 'users',
  underscored: true,
  timestamps: true,
});

module.exports = User;
