const bcrypt = require('bcryptjs');
const User = require('../models/User');
const KnownDevice = require('../models/KnownDevice');
const AuthEvent = require('../models/AuthEvent');
const { signToken } = require('../middleware/authMiddleware');
const engineClient = require('../services/engineClient');

async function register(req, res) {
  try {
    const { email, password, fullName, organisation } = req.body;
    if (!email || !password || !fullName) {
      return res.status(400).json({ error: 'email, password and fullName are required' });
    }
    const existing = await User.findOne({ where: { email } });
    if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, fullName, organisation, passwordHash, role: 'user' });
    const token = signToken(user);
    res.status(201).json({ token, user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed', detail: err.message });
  }
}

async function login(req, res) {
  try {
    const { email, password, deviceFingerprint, latitude, longitude } = req.body;
    const user = await User.findOne({ where: { email } });

    // Track failed attempts for brute-force detection regardless of outcome.
    const fifteenMinAgo = new Date(Date.now() - 15 * 60 * 1000);
    const recentFailures = await AuthEvent.count({
      where: { emailAttempted: email, success: false, createdAt: { [require('sequelize').Op.gte]: fifteenMinAgo } },
    });

    if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
      await AuthEvent.create({
        userId: user?.id || null, emailAttempted: email, ipAddress: req.ip,
        deviceFingerprint, latitude, longitude, success: false,
        failedAttempts15min: recentFailures + 1,
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.isActive) return res.status(403).json({ error: 'This account has been deactivated' });

    // Real-time login-anomaly analysis via the C++ engine.
    const knownDevice = deviceFingerprint
      ? await KnownDevice.findOne({ where: { userId: user.id, deviceFingerprint } })
      : null;

    let anomalyResult = null;
    try {
      anomalyResult = await engineClient.analyzeLogin({
        userId: user.id,
        failedAttemptsLast15Min: recentFailures,
        isKnownDevice: Boolean(knownDevice),
        latitude: latitude ?? 0,
        longitude: longitude ?? 0,
        lastKnownLatitude: user.lastLoginLat ?? latitude ?? 0,
        lastKnownLongitude: user.lastLoginLon ?? longitude ?? 0,
        minutesSinceLastLogin: user.lastLoginAt ? (Date.now() - new Date(user.lastLoginAt).getTime()) / 60000 : 999999,
        hourOfDay: new Date().getHours(),
        avgLoginHour: Number(user.avgLoginHour) || 13,
        loginHourStdDev: Number(user.loginHourStddev) || 4,
      });
    } catch (e) {
      console.warn('[auth] detection engine unreachable, proceeding without anomaly score:', e.message);
    }

    // Fuse the rule-based detector with the C++ Isolation Forest (ML) verdict.
    let loginRisk = null;
    if (anomalyResult) {
      const ml = anomalyResult.ml;
      const levels = ['Safe', 'Low', 'Medium', 'High', 'Critical'];
      const mlScore = ml?.available && ml.isAnomaly ? ml.score : 0;
      const score = Math.max(anomalyResult.score, mlScore);
      const riskLevel = levels[Math.max(levels.indexOf(anomalyResult.riskLevel), ml?.available ? levels.indexOf(ml.riskLevel) : 0)];
      const findings = [...(anomalyResult.findings || [])];
      if (ml?.available && ml.isAnomaly) {
        findings.push({ indicator: 'ml_login_anomaly', detail: `Isolation Forest: this login is unlike this account's normal behaviour (anomaly score ${ml.anomalyScore.toFixed(2)}; most unusual: ${[ml.outOfRangeFeature, ...(ml.topFeatures || []).map((t) => t.feature)].filter(Boolean).slice(0, 3).join(', ')})`, weight: Math.round(ml.score / 4) });
      }
      loginRisk = { score, riskLevel, findings, ml };
    }

    await AuthEvent.create({
      userId: user.id, emailAttempted: email, ipAddress: req.ip, deviceFingerprint,
      latitude, longitude, success: true, failedAttempts15min: recentFailures,
      riskScore: loginRisk?.score, riskLevel: loginRisk?.riskLevel,
      findings: loginRisk?.findings, mlResult: anomalyResult?.ml || null,
    });

    if (deviceFingerprint && !knownDevice) {
      await KnownDevice.create({ userId: user.id, deviceFingerprint });
    }

    user.lastLoginAt = new Date();
    if (latitude != null) user.lastLoginLat = latitude;
    if (longitude != null) user.lastLoginLon = longitude;
    await user.save();

    const token = signToken(user);
    res.json({
      token,
      user: publicUser(user),
      loginRisk,
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', detail: err.message });
  }
}

async function googleCallback(req, res) {
  const user = req.user;
  const token = signToken(user);
  const redirectBase = process.env.FRONTEND_URL || 'http://localhost:3000';
  res.redirect(`${redirectBase}/oauth-success?token=${token}`);
}

async function me(req, res) {
  const user = await User.findByPk(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
}

function publicUser(user) {
  return {
    id: user.id, email: user.email, fullName: user.fullName, role: user.role,
    avatarUrl: user.avatarUrl, organisation: user.organisation, createdAt: user.createdAt,
  };
}

module.exports = { register, login, googleCallback, me };
