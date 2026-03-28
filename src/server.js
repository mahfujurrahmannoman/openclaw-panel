require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const PanelDatabase = require('./database');
const EasypanelAPI = require('./easypanel');
const BackupService = require('./backup');
const { signToken, verifyToken, adminOnly, userOnly } = require('./middleware');

const app = express();

// Trust proxy (behind Traefik/Easypanel reverse proxy)
app.set('trust proxy', 1);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "wss:", "ws:"],
      imgSrc: ["'self'", "data:", "blob:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Request body size limit (prevent DoS)
app.use(express.json({ limit: '1mb' }));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const setupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { error: 'Too many setup attempts. Try again later.' },
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use(express.static(path.join(__dirname, '..', 'public')));

// Initialize database
const db = new PanelDatabase(path.join(__dirname, '..', 'data', 'panel.db'));

// Initialize Easypanel API
const easypanel = new EasypanelAPI(
  process.env.EASYPANEL_URL || 'https://panel.rarhost.store',
  process.env.EASYPANEL_TOKEN || ''
);

// Initialize Backup Service
const backupService = new BackupService(db, easypanel);
backupService.startAutoCron();

// ==================== SETUP ====================

app.get('/api/setup/status', (req, res) => {
  res.json({ needsSetup: db.getAdminCount() === 0 });
});

app.post('/api/setup', setupLimiter, (req, res) => {
  if (db.getAdminCount() > 0) {
    return res.status(400).json({ error: 'Admin already exists' });
  }
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Email and password (min 6 chars) required' });
  }
  try {
    db.createAdmin(email, password);
    db.logActivity(null, 'setup', 'Admin account created');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== AUTH ====================

app.post('/api/admin/login', authLimiter, (req, res) => {
  const { email, password } = req.body;
  const admin = db.verifyAdmin(email, password);
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({ id: admin.id, email: admin.email, role: 'admin' });
  res.json({ token, admin: { id: admin.id, email: admin.email } });
});

app.post('/api/user/login', authLimiter, (req, res) => {
  const { email, password } = req.body;
  const user = db.verifyUser(email, password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });
  const token = signToken({ id: user.id, username: user.username, role: 'user' });
  res.json({ token, user });
});

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/dashboard', verifyToken, adminOnly, async (req, res) => {
  try {
    const dbStats = db.getDashboardStats();
    let serverStats = null;
    let containerStats = null;
    try {
      serverStats = await easypanel.getSystemStats();
      containerStats = await easypanel.getMonitorTableData();
    } catch (_) {}
    res.json({ dbStats, serverStats, containerStats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Live dashboard — aggregates all monitoring data in one call
app.get('/api/admin/dashboard/live', verifyToken, adminOnly, async (req, res) => {
  try {
    const [system, containers, tasks] = await Promise.allSettled([
      easypanel.getSystemStats(),
      easypanel.getMonitorTableData(),
      easypanel.getDockerTaskStats(),
    ]);
    res.json({
      system: system.status === 'fulfilled' ? system.value : null,
      containers: containers.status === 'fulfilled' ? containers.value : [],
      tasks: tasks.status === 'fulfilled' ? tasks.value : {},
      dbStats: db.getDashboardStats(),
      users: db.getAllUsers(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/users', verifyToken, adminOnly, (req, res) => {
  res.json(db.getAllUsers());
});

app.post('/api/admin/users', verifyToken, adminOnly, async (req, res) => {
  const { username, email, password, notes, expires_at } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password required' });
  }
  // Validate username: alphanumeric + hyphens only, 3-30 chars (used in Docker project names & domains)
  if (!/^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-30 chars, lowercase letters, numbers, and hyphens only' });
  }
  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (db.getUserByUsername(username)) {
    return res.status(400).json({ error: 'Username already taken' });
  }

  const planData = db.getPlanByName('unlimited');
  try {
    // Deploy OpenClaw instance
    const deployment = await easypanel.deployOpenClawInstance(username, {
      cpuLimit: planData?.cpu_limit || 1,
      memoryLimit: planData?.memory_limit || 1024,
    });

    // Create user in DB
    db.createUser({
      username, email, password,
      project_name: deployment.projectName,
      service_name: deployment.serviceName,
      domain: deployment.domain,
      gateway_token: deployment.gatewayToken,
      openclaw_url: deployment.url,
      plan: 'unlimited',
      cpu_limit: planData?.cpu_limit || 4,
      memory_limit: planData?.memory_limit || 4096,
      expires_at: expires_at || null,
      notes: notes || null,
    });

    const user = db.getUserByUsername(username);
    db.logActivity(user.id, 'user_created', `User ${username} created with unlimited plan`);
    res.json({ success: true, user, deployment });
  } catch (err) {
    res.status(500).json({ error: `Deployment failed: ${err.message}` });
  }
});

app.put('/api/admin/users/:id', verifyToken, adminOnly, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid user ID' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Only allow safe fields — never accept password, project_name, gateway_token from this endpoint
  const { plan, status, notes, expires_at, email } = req.body;
  const fields = {};
  if (plan !== undefined) fields.plan = plan;
  if (status !== undefined) fields.status = status;
  if (notes !== undefined) fields.notes = String(notes).slice(0, 500);
  if (expires_at !== undefined) fields.expires_at = expires_at;
  if (email !== undefined) fields.email = email;

  // If plan changed, update Easypanel resource limits
  if (fields.plan && fields.plan !== user.plan) {
    const planData = db.getPlanByName(fields.plan);
    if (planData) {
      fields.cpu_limit = planData.cpu_limit;
      fields.memory_limit = planData.memory_limit;
      try {
        await easypanel.updateResources(user.project_name, user.service_name, {
          cpuLimit: planData.cpu_limit,
          cpuReservation: 0,
          memoryLimit: planData.memory_limit,
          memoryReservation: 0,
        });
        await easypanel.deployService(user.project_name, user.service_name);
      } catch (_) {}
    }
  }

  db.updateUser(user.id, fields);
  db.logActivity(user.id, 'user_updated', `User ${user.username} updated`);
  res.json({ success: true, user: db.getUserById(user.id) });
});

app.post('/api/admin/users/:id/suspend', verifyToken, adminOnly, async (req, res) => {
  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.disableService(user.project_name, user.service_name);
    db.suspendUser(user.id);
    db.logActivity(user.id, 'user_suspended', `User ${user.username} suspended`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/users/:id/activate', verifyToken, adminOnly, async (req, res) => {
  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.enableService(user.project_name, user.service_name);
    await easypanel.deployService(user.project_name, user.service_name);
    db.activateUser(user.id);
    db.logActivity(user.id, 'user_activated', `User ${user.username} activated`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/users/:id', verifyToken, adminOnly, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid user ID' });
  const user = db.getUserById(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.destroyProject(user.project_name);
  } catch (_) {}
  db.logActivity(user.id, 'user_deleted', `User ${user.username} deleted`);
  db.deleteUser(user.id);
  res.json({ success: true });
});

app.get('/api/admin/users/:id/stats', verifyToken, adminOnly, async (req, res) => {
  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const stats = await easypanel.getUserStats(user.project_name);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/users/:id/deploy', verifyToken, adminOnly, async (req, res) => {
  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.deployService(user.project_name, user.service_name);
    db.logActivity(user.id, 'service_redeployed', `Service redeployed for ${user.username}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin impersonate user - login as user
app.post('/api/admin/users/:id/impersonate', verifyToken, adminOnly, (req, res) => {
  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const token = signToken({ id: user.id, username: user.username, role: 'user', impersonated: true }, '4h');
  db.logActivity(user.id, 'admin_impersonate', `Admin logged in as ${user.username}`);
  res.json({ token, username: user.username, openclaw_url: user.openclaw_url });
});

app.get('/api/admin/server/stats', verifyToken, adminOnly, async (req, res) => {
  try {
    const [system, containers, tasks] = await Promise.all([
      easypanel.getSystemStats(),
      easypanel.getMonitorTableData(),
      easypanel.getDockerTaskStats(),
    ]);
    res.json({ system, containers, tasks });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Server actions (prune, restart)
app.post('/api/admin/server/action', verifyToken, adminOnly, async (req, res) => {
  const { action } = req.body;
  try {
    let result;
    switch (action) {
      case 'prune_images':
        result = await easypanel.post('settings.pruneDockerImages', {});
        break;
      case 'prune_builder':
        result = await easypanel.post('settings.pruneDockerBuilder', {});
        break;
      case 'restart_traefik':
        result = await easypanel.post('settings.restartTraefik', {});
        break;
      default:
        return res.status(400).json({ error: 'Unknown action' });
    }
    db.logActivity(null, `server_${action}`, `Admin executed ${action}`);
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/plans', verifyToken, adminOnly, (req, res) => {
  res.json(db.getAllPlans());
});

app.get('/api/admin/activity', verifyToken, adminOnly, (req, res) => {
  res.json(db.getRecentActivity(100));
});

// ==================== EXTERNAL API (WHMCS / Billing) ====================
// Uses API key from EXTERNAL_API_KEY env var — no JWT needed

const externalApiAuth = (req, res, next) => {
  const apiKey = process.env.EXTERNAL_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'External API not configured' });
  const provided = req.headers['x-api-key'] || req.query.api_key;
  if (!provided || provided !== apiKey) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
};

const externalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { error: 'Too many requests' },
});

// Create/Provision user — called by WHMCS on order activation
app.post('/api/external/provision', externalLimiter, externalApiAuth, async (req, res) => {
  const { username, email, password, notes, expires_at } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email, and password required' });
  }
  if (!/^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-30 chars, lowercase alphanumeric + hyphens' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (db.getUserByUsername(username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  const planData = db.getPlanByName('unlimited');
  try {
    const deployment = await easypanel.deployOpenClawInstance(username, {
      cpuLimit: planData?.cpu_limit || 4,
      memoryLimit: planData?.memory_limit || 4096,
    });

    db.createUser({
      username, email, password,
      project_name: deployment.projectName,
      service_name: deployment.serviceName,
      domain: deployment.domain,
      gateway_token: deployment.gatewayToken,
      openclaw_url: deployment.url,
      plan: 'unlimited',
      cpu_limit: planData?.cpu_limit || 4,
      memory_limit: planData?.memory_limit || 4096,
      expires_at: expires_at || null,
      notes: notes || null,
    });

    const user = db.getUserByUsername(username);
    db.logActivity(user.id, 'user_created', `User ${username} provisioned via WHMCS`);

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        domain: user.domain,
        openclaw_url: user.openclaw_url,
        gateway_token: user.gateway_token,
        status: user.status,
      },
      panel_url: `https://${req.headers.host}/panel`,
    });
  } catch (err) {
    res.status(500).json({ error: `Deployment failed: ${err.message}` });
  }
});

// Suspend user — called by WHMCS on suspend
app.post('/api/external/suspend', externalLimiter, externalApiAuth, async (req, res) => {
  const { username, email } = req.body;
  const user = username ? db.getUserByUsername(username) : null;
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.disableService(user.project_name, user.service_name);
    db.suspendUser(user.id);
    db.logActivity(user.id, 'user_suspended', `User ${user.username} suspended via WHMCS`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Unsuspend user — called by WHMCS on unsuspend
app.post('/api/external/unsuspend', externalLimiter, externalApiAuth, async (req, res) => {
  const { username, email } = req.body;
  const user = username ? db.getUserByUsername(username) : null;
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.enableService(user.project_name, user.service_name);
    await easypanel.deployService(user.project_name, user.service_name);
    db.activateUser(user.id);
    db.logActivity(user.id, 'user_activated', `User ${user.username} unsuspended via WHMCS`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Terminate user — called by WHMCS on terminate
app.post('/api/external/terminate', externalLimiter, externalApiAuth, async (req, res) => {
  const { username, email } = req.body;
  const user = username ? db.getUserByUsername(username) : null;
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.destroyProject(user.project_name);
  } catch (_) {}
  db.logActivity(user.id, 'user_deleted', `User ${user.username} terminated via WHMCS`);
  db.deleteUser(user.id);
  res.json({ success: true });
});

// Get user info — WHMCS can check user status
app.get('/api/external/user/:username', externalLimiter, externalApiAuth, (req, res) => {
  const user = db.getUserByUsername(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    domain: user.domain,
    openclaw_url: user.openclaw_url,
    status: user.status,
    plan: user.plan,
    created_at: user.created_at,
  });
});

// Change password — WHMCS password sync
app.post('/api/external/change-password', externalLimiter, externalApiAuth, (req, res) => {
  const { username, new_password } = req.body;
  const user = username ? db.getUserByUsername(username) : null;
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!new_password || new_password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  db.updateUserPassword(user.id, new_password);
  res.json({ success: true });
});

// Test connection — called by WHMCS to verify server config
app.get('/api/external/testconnection', externalLimiter, externalApiAuth, (req, res) => {
  res.json({ success: true, message: 'OpenClaw Panel API connected', version: '1.0.0' });
});

// ==================== USER ROUTES ====================

app.get('/api/user/profile', verifyToken, userOnly, (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.get('/api/user/stats', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const [containersRes, tasksRes] = await Promise.allSettled([
      easypanel.getUserStats(user.project_name),
      easypanel.getDockerTaskStats(),
    ]);
    const containers = containersRes.status === 'fulfilled' ? containersRes.value : [];
    const allTasks = tasksRes.status === 'fulfilled' ? tasksRes.value : {};
    const swarmName = `${user.project_name}_${user.service_name || 'openclaw-gateway'}`;
    const task = allTasks?.[swarmName] || null;
    res.json({ containers: containers || [], task });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/restart', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await easypanel.deployService(user.project_name, user.service_name);
    db.logActivity(user.id, 'service_restarted', `User ${user.username} restarted their service`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/telegram', verifyToken, userOnly, (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { botToken, chatId } = req.body;
  db.updateUser(user.id, { telegram_bot_token: botToken || '', telegram_chat_id: chatId || '' });
  db.logActivity(user.id, 'telegram_configured', 'Telegram settings updated');
  res.json({ success: true });
});

// ===== User Profile Update (name + password only, NOT email) =====
app.put('/api/user/profile', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { username, currentPassword, newPassword } = req.body;
  const results = [];

  // Update username if provided
  if (username && username !== user.username) {
    if (!/^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3-30 chars, lowercase letters, numbers, and hyphens only' });
    }
    const result = db.updateUserUsername(user.id, username);
    if (result && result.error) {
      return res.status(400).json({ error: result.error });
    }
    results.push('Username updated');
  }

  // Update password if provided
  if (newPassword) {
    if (!currentPassword) {
      return res.status(400).json({ error: 'Current password is required to change password' });
    }
    // Verify current password
    const verified = db.verifyUser(user.username, currentPassword);
    if (!verified) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    db.updateUserPassword(user.id, newPassword);
    results.push('Password updated');
  }

  if (results.length === 0) {
    return res.status(400).json({ error: 'No changes provided' });
  }

  db.logActivity(user.id, 'profile_updated', `User updated: ${results.join(', ')}`);
  const updated = db.getUserById(user.id);
  res.json({ success: true, message: results.join(', '), user: updated });
});

// ===== Version Check & Update =====
app.get('/api/user/version', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const serviceName = user.service_name || 'openclaw-gateway';
    const [current, latest] = await Promise.all([
      easypanel.getRunningImageTag(user.project_name, serviceName),
      easypanel.getLatestOpenClawVersion(),
    ]);
    const updateAvailable = current !== latest && current !== 'unknown';
    res.json({ current, latest, updateAvailable });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/update', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const serviceName = user.service_name || 'openclaw-gateway';
    const latest = await easypanel.getLatestOpenClawVersion();
    const newImage = `ghcr.io/openclaw/openclaw:${latest}`;
    await easypanel.updateSourceImage(user.project_name, serviceName, newImage);
    await easypanel.deployService(user.project_name, serviceName);
    db.logActivity(user.id, 'version_updated', `Updated OpenClaw to ${latest}`);
    res.json({ success: true, version: latest, message: `Updating to ${latest}. Service is restarting...` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/apikey', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { provider, apiKey } = req.body;
  if (!provider || !apiKey) return res.status(400).json({ error: 'Provider and API key required' });

  // Store provider and encrypt the API key before saving
  const encryptedKey = encryptApiKey(apiKey);
  db.updateUser(user.id, { api_key_provider: provider, api_key_encrypted: encryptedKey });

  // Update Easypanel env vars to include the API key
  try {
    const envLines = [
      `HOME=/home/node`,
      `TERM=xterm-256color`,
      `OPENCLAW_GATEWAY_TOKEN=${user.gateway_token}`,
    ];
    // Map provider to env var name
    const providerEnvMap = {
      deepseek: 'DEEPSEEK_API_KEY',
      openai: 'OPENAI_API_KEY',
      anthropic: 'ANTHROPIC_API_KEY',
      custom: 'CUSTOM_API_KEY',
    };
    const envKey = providerEnvMap[provider.toLowerCase()] || 'CUSTOM_API_KEY';
    envLines.push(`${envKey}=${apiKey}`);

    await easypanel.updateEnv(user.project_name, user.service_name, envLines.join('\n'));
    await easypanel.deployService(user.project_name, user.service_name);
    db.logActivity(user.id, 'apikey_configured', `API key set for ${provider}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/user/logs', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const logs = await easypanel.getServiceLogs(user.project_name, user.service_name);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== USER BACKUP ROUTES ====================

app.get('/api/user/backups', verifyToken, userOnly, (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const backups = db.getBackupsByUser(user.id);
  res.json({ backups, auto_backup: user.auto_backup || 0 });
});

app.post('/api/user/backups', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const result = await backupService.createBackup(user, 'manual');
    db.logActivity(user.id, 'backup_created', `Manual backup: ${result.filename}`);
    res.json({ success: true, backup: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/backups/:id/restore', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid backup ID' });
  try {
    await backupService.restoreBackup(user, id);
    db.logActivity(user.id, 'backup_restored', `Restored backup #${id}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/user/backups/:id', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const id = parseInt(req.params.id, 10);
  const backup = db.getBackupById(id);
  if (!backup || backup.user_id !== user.id) return res.status(404).json({ error: 'Backup not found' });
  try {
    await backupService.deleteBackup(id);
    db.logActivity(user.id, 'backup_deleted', `Deleted backup: ${backup.filename}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/user/backups/auto', verifyToken, userOnly, (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { enabled } = req.body;
  db.updateUser(user.id, { auto_backup: enabled ? 1 : 0 });
  db.logActivity(user.id, 'auto_backup_toggled', `Auto-backup ${enabled ? 'enabled' : 'disabled'}`);
  res.json({ success: true, auto_backup: enabled ? 1 : 0 });
});

// ==================== ADMIN BACKUP ROUTES ====================

app.get('/api/admin/backups', verifyToken, adminOnly, (req, res) => {
  res.json(db.getAllBackups());
});

app.post('/api/admin/backups/:userId', verifyToken, adminOnly, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const user = db.getUserById(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const result = await backupService.createBackup(user, 'manual');
    db.logActivity(user.id, 'backup_created', `Admin backup: ${result.filename}`);
    res.json({ success: true, backup: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/backups/:id', verifyToken, adminOnly, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    await backupService.deleteBackup(id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== STATIC ROUTES ====================

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'admin.html'));
});

app.get('/panel', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'user.html'));
});

// ==================== WEBSOCKET TERMINAL ====================

const http = require('http');
const { WebSocketServer } = require('ws');
const Docker = require('dockerode');

const server = http.createServer(app);

// Docker connection - works when panel runs on the same server as Easypanel
const docker = new Docker({ socketPath: process.env.DOCKER_SOCKET || '/var/run/docker.sock' });

// API key encryption helpers
function encryptApiKey(text) {
  const algorithm = 'aes-256-gcm';
  const key = crypto.scryptSync(process.env.JWT_SECRET || 'default-secret', 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

function decryptApiKey(encrypted) {
  try {
    const [ivHex, tagHex, data] = encrypted.split(':');
    if (!ivHex || !tagHex || !data) return encrypted; // fallback for old plaintext keys
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(process.env.JWT_SECRET || 'default-secret', 'salt', 32);
    const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    let decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return encrypted; // fallback for old plaintext keys
  }
}

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  // Only handle /ws/terminal path
  if (!request.url?.startsWith('/ws/terminal')) {
    socket.destroy();
    return;
  }

  // Extract token from query string
  const url = new URL(request.url, `http://${request.headers.host}`);
  const token = url.searchParams.get('token');
  if (!token) {
    socket.destroy();
    return;
  }

  // Verify JWT
  const jwt = require('jsonwebtoken');
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== 'user' && payload.role !== 'admin') {
      socket.destroy();
      return;
    }
    request.auth = payload;
  } catch {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Python PTY helper creates a real pseudo-terminal for docker exec.
// Python3's pty module is available on Alpine (no native build needed).
// This is far more reliable than the `script` wrapper.
const { spawn } = require('child_process');
const PTY_HELPER = path.join(__dirname, 'pty-helper.py');

function spawnContainerShell(containerId, cols = 120, rows = 30) {
  const shell = spawn('python3', [PTY_HELPER, containerId, String(cols), String(rows)], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
  });

  return {
    type: 'python-pty',
    shell,
    write: (data) => { try { shell.stdin.write(data); } catch(_){} },
    resize: (c, r) => {
      // Send resize command via special escape sequence
      try { shell.stdin.write(`\x1bRESIZE:${c}:${r}\n`); } catch(_){}
    },
    onData: (cb) => {
      shell.stdout.on('data', (d) => cb(d.toString()));
      shell.stderr.on('data', (d) => cb(d.toString()));
    },
    onExit: (cb) => shell.on('close', (code) => cb({ exitCode: code })),
    kill: () => { try { shell.kill('SIGTERM'); } catch(_){} },
    pid: shell.pid,
  };
}

// Find container ID by Swarm service label
async function findContainerId(projectName, serviceName) {
  const swarmServiceName = `${projectName}_${serviceName}`;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const containers = await docker.listContainers({
        all: false,
        filters: JSON.stringify({
          label: [`com.docker.swarm.service.name=${swarmServiceName}`],
          status: ['running'],
        }),
      });
      if (containers.length > 0) return containers[0].Id;

      // Fallback: match by name prefix
      const allContainers = await docker.listContainers({ all: false });
      const match = allContainers.find(c => {
        const names = (c.Names || []).map(n => n.replace(/^\//, ''));
        return names.some(n => n.startsWith(swarmServiceName));
      });
      if (match) return match.Id;
    } catch (_) {}
    if (attempt < 2) await new Promise(r => setTimeout(r, 2000));
  }
  return null;
}

wss.on('connection', async (ws, request) => {
  const user = db.getUserById(request.auth.id);
  if (!user || !user.project_name) {
    ws.send(JSON.stringify({ type: 'error', data: 'User or project not found' }));
    ws.close();
    return;
  }

  let sessionClosed = false;
  let currentWrapper = null;
  let lastActivity = Date.now();
  let reconnectCount = 0;
  let currentCols = 120, currentRows = 30;
  const MAX_RECONNECTS = 50;
  const SESSION_TIMEOUT = 60 * 60 * 1000;

  const send = (type, data) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type, data }));
  };

  // Connect (or reconnect) to the container
  async function connectToContainer() {
    if (sessionClosed) return;

    // Find container
    let containerId;
    try {
      containerId = await findContainerId(user.project_name, user.service_name || 'openclaw-gateway');
    } catch (err) {
      send('output', `\r\n\x1b[31mDocker error: ${err.message}\x1b[0m\r\n`);
      return false;
    }

    if (!containerId) {
      send('output', `\r\n\x1b[31mContainer not found for ${user.project_name}. Service may be stopped.\x1b[0m\r\n`);
      return false;
    }

    const wrapper = spawnContainerShell(containerId, currentCols, currentRows);
    if (!wrapper.pid) {
      send('output', '\r\n\x1b[31mFailed to start shell.\x1b[0m\r\n');
      return false;
    }

    currentWrapper = wrapper;

    // Container output → browser
    wrapper.onData((data) => {
      lastActivity = Date.now();
      send('output', data);
    });

    // When docker exec dies → auto-reconnect instead of closing
    wrapper.onExit(({ exitCode }) => {
      currentWrapper = null;
      if (sessionClosed) return;

      reconnectCount++;
      if (reconnectCount > MAX_RECONNECTS) {
        send('exit', 'Too many reconnects. Please click Connect again.');
        ws.close();
        return;
      }

      send('output', `\r\n\x1b[33m[Shell exited (code ${exitCode}). Reconnecting in 2s... (${reconnectCount}/${MAX_RECONNECTS})]\x1b[0m\r\n`);

      // Auto-reconnect after 2 seconds
      setTimeout(() => connectToContainer(), 2000);
    });

    return true;
  }

  // Initial connection
  send('output', '\x1b[90mConnecting to your container...\x1b[0m\r\n');
  const ok = await connectToContainer();
  if (!ok && !sessionClosed) {
    send('error', `Container not available for ${user.project_name}.`);
    ws.close();
    return;
  }

  // Browser → container stdin
  ws.on('message', (msg) => {
    if (sessionClosed) return;
    lastActivity = Date.now();
    try {
      const parsed = JSON.parse(msg);
      if (parsed.type === 'input') {
        if (currentWrapper) currentWrapper.write(parsed.data);
      } else if (parsed.type === 'resize' && parsed.cols && parsed.rows) {
        currentCols = parsed.cols;
        currentRows = parsed.rows;
        if (currentWrapper) currentWrapper.resize(parsed.cols, parsed.rows);
      } else if (parsed.type === 'ping') {
        send('pong', Date.now());
      }
    } catch {
      if (currentWrapper) currentWrapper.write(msg.toString());
    }
  });

  ws.on('close', () => {
    sessionClosed = true;
    clearInterval(heartbeatInterval);
    clearInterval(activityCheckInterval);
    if (currentWrapper) currentWrapper.kill();
  });

  ws.on('error', () => {});

  // Heartbeat every 8s
  const heartbeatInterval = setInterval(() => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ type: 'heartbeat', ts: Date.now() }));
      try { ws.ping(); } catch (_) {}
    } else {
      clearInterval(heartbeatInterval);
    }
  }, 8000);

  // 1 hour inactivity timeout
  const activityCheckInterval = setInterval(() => {
    if (Date.now() - lastActivity > SESSION_TIMEOUT) {
      send('output', '\r\n\x1b[33m[Session timed out after 1 hour of inactivity]\x1b[0m\r\n');
      sessionClosed = true;
      clearInterval(heartbeatInterval);
      clearInterval(activityCheckInterval);
      if (currentWrapper) currentWrapper.kill();
      ws.close();
    }
  }, 60000);

  send('connected', `Connected to ${user.project_name}`);
});

// ==================== SSH SERVER ====================
// Provides reliable terminal access via PuTTY/SSH clients.
// Users authenticate with their panel username + password.
// Auto-execs into their Docker container.

let ssh2;
try { ssh2 = require('ssh2'); } catch (e) { console.warn('ssh2 not available:', e.message); }
const fs = require('fs');
const crypto = require('crypto');

const SSH_PORT = parseInt(process.env.SSH_PORT || '2222');
const HOST_KEY_PATH = path.join(__dirname, '..', 'data', 'ssh_host_key');

// Generate host key if not exists
function generateHostKey() {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  fs.mkdirSync(path.dirname(HOST_KEY_PATH), { recursive: true });
  fs.writeFileSync(HOST_KEY_PATH, privateKey, { mode: 0o600 });
  console.log('SSH host key generated');
  return privateKey;
}

function getOrCreateHostKey() {
  try {
    const key = fs.readFileSync(HOST_KEY_PATH, 'utf8');
    // Validate it's PKCS1 format (RSA PRIVATE KEY), not PKCS8 (PRIVATE KEY)
    if (!key.includes('RSA PRIVATE KEY')) {
      console.log('SSH host key has wrong format, regenerating...');
      return generateHostKey();
    }
    return key;
  } catch {
    return generateHostKey();
  }
}

if (!ssh2) { console.warn('SSH server disabled — ssh2 module not available'); }
else try {
const sshServer = new ssh2.Server({
  hostKeys: [getOrCreateHostKey()],
  banner: 'OpenClaw Hosting Panel - RarHost\r\n',
}, (client) => {
  let authenticatedUser = null;

  let authAttempts = 0;
  client.on('authentication', (ctx) => {
    if (ctx.method === 'password') {
      authAttempts++;
      if (authAttempts > 5) {
        ctx.reject(['password']);
        client.end();
        return;
      }
      // verifyUser already checks both username and email
      const user = db.verifyUser(ctx.username, ctx.password);
      if (user && user.status !== 'suspended') {
        authenticatedUser = user;
        ctx.accept();
        return;
      }
    }
    ctx.reject(['password']);
  });

  client.on('ready', () => {
    client.on('session', (accept) => {
      const session = accept();

      session.on('pty', (accept, reject, info) => {
        accept();
      });

      session.on('shell', async (accept) => {
        const stream = accept();

        if (!authenticatedUser || !authenticatedUser.project_name) {
          stream.write('\r\nError: No OpenClaw instance found for your account.\r\n');
          stream.close();
          client.end();
          return;
        }

        if (authenticatedUser.status === 'suspended') {
          stream.write('\r\nError: Your account is suspended. Contact admin.\r\n');
          stream.close();
          client.end();
          return;
        }

        // Find container
        let containerId;
        try {
          containerId = await findContainerId(
            authenticatedUser.project_name,
            authenticatedUser.service_name || 'openclaw-gateway'
          );
        } catch (_) {}

        if (!containerId) {
          stream.write('\r\nError: Container not running. Try again in a few seconds.\r\n');
          stream.close();
          client.end();
          return;
        }

        stream.write(`\r\nConnecting to ${authenticatedUser.project_name}...\r\n\r\n`);

        let sshClosed = false;
        let currentShell = null;
        let sshReconnects = 0;
        let sshCols = 120, sshRows = 30;

        // Connect (or reconnect) to container
        function sshConnectShell() {
          if (sshClosed) return;
          const wrapper = spawnContainerShell(containerId, sshCols, sshRows);
          if (!wrapper.pid) {
            stream.write('\r\n\x1b[31mFailed to start shell.\x1b[0m\r\n');
            return;
          }
          currentShell = wrapper;

          // Container → SSH client
          wrapper.onData((data) => {
            try { stream.write(data); } catch (_) {}
          });

          // Auto-reconnect when docker exec dies
          wrapper.onExit(({ exitCode }) => {
            currentShell = null;
            if (sshClosed) return;
            sshReconnects++;
            if (sshReconnects > 50) {
              stream.write('\r\n\x1b[31mToo many reconnects. Disconnecting.\x1b[0m\r\n');
              try { stream.close(); } catch (_) {}
              try { client.end(); } catch (_) {}
              return;
            }
            stream.write(`\r\n\x1b[33m[Shell exited (${exitCode}). Reconnecting... ${sshReconnects}/50]\x1b[0m\r\n`);
            setTimeout(sshConnectShell, 2000);
          });
        }

        sshConnectShell();

        // SSH client → container
        stream.on('data', (data) => {
          if (currentShell) currentShell.write(data);
        });

        // Handle window resize
        session.on('window-change', (accept, reject, info) => {
          if (accept) accept();
          sshCols = info.cols;
          sshRows = info.rows;
          if (currentShell) currentShell.resize(info.cols, info.rows);
        });

        // Cleanup
        stream.on('close', () => {
          sshClosed = true;
          if (currentShell) currentShell.kill();
        });

        client.on('end', () => {
          sshClosed = true;
          if (currentShell) currentShell.kill();
        });

        db.logActivity(authenticatedUser.id, 'ssh_connected', `SSH session from ${authenticatedUser.username}`);
      });
    });
  });

  client.on('error', () => {});
});

sshServer.listen(SSH_PORT, '0.0.0.0', () => {
  console.log(`SSH Server running on port ${SSH_PORT}`);
});
} catch (sshErr) { console.error('SSH server failed to start:', sshErr.message); }

// ==================== START ====================

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`OpenClaw Panel running on http://localhost:${PORT}`);
  console.log(`Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`User Panel:  http://localhost:${PORT}/panel`);
  console.log(`SSH Access:  ssh <username>@<host> -p ${SSH_PORT}`);
});
