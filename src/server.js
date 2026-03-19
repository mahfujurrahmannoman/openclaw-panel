require('dotenv').config();

const express = require('express');
const path = require('path');
const PanelDatabase = require('./database');
const EasypanelAPI = require('./easypanel');
const { signToken, verifyToken, adminOnly, userOnly } = require('./middleware');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Initialize database
const db = new PanelDatabase(path.join(__dirname, '..', 'data', 'panel.db'));

// Initialize Easypanel API
const easypanel = new EasypanelAPI(
  process.env.EASYPANEL_URL || 'https://panel.rarhost.store',
  process.env.EASYPANEL_TOKEN || ''
);

// ==================== SETUP ====================

app.get('/api/setup/status', (req, res) => {
  res.json({ needsSetup: db.getAdminCount() === 0 });
});

app.post('/api/setup', (req, res) => {
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

app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.verifyAdmin(email, password);
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({ id: admin.id, email: admin.email, role: 'admin' });
  res.json({ token, admin: { id: admin.id, email: admin.email } });
});

app.post('/api/user/login', (req, res) => {
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

app.get('/api/admin/users', verifyToken, adminOnly, (req, res) => {
  res.json(db.getAllUsers());
});

app.post('/api/admin/users', verifyToken, adminOnly, async (req, res) => {
  const { username, email, password, notes, expires_at } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password required' });
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
  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const fields = req.body;

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
  const user = db.getUserById(req.params.id);
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

app.get('/api/admin/plans', verifyToken, adminOnly, (req, res) => {
  res.json(db.getAllPlans());
});

app.get('/api/admin/activity', verifyToken, adminOnly, (req, res) => {
  res.json(db.getRecentActivity(100));
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
    const stats = await easypanel.getUserStats(user.project_name);
    res.json(stats || []);
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

app.post('/api/user/apikey', verifyToken, userOnly, async (req, res) => {
  const user = db.getUserById(req.auth.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { provider, apiKey } = req.body;
  if (!provider || !apiKey) return res.status(400).json({ error: 'Provider and API key required' });

  // Store provider in DB (key stored encrypted-ish, or just the provider name)
  db.updateUser(user.id, { api_key_provider: provider, api_key_encrypted: apiKey });

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
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-change-me');
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

// Use child_process.spawn('docker', ['exec']) instead of dockerode exec API.
// Dockerode's exec hijack mode breaks stdin in Docker Swarm — the writable side
// of the stream dies immediately. Spawning `docker exec` via CLI works reliably.
const { spawn } = require('child_process');

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

  ws.send(JSON.stringify({ type: 'output', data: '\x1b[90mFinding your container...\x1b[0m\r\n' }));

  let containerId;
  try {
    containerId = await findContainerId(user.project_name, user.service_name || 'openclaw-gateway');
  } catch (err) {
    ws.send(JSON.stringify({ type: 'error', data: `Docker error: ${err.message}` }));
    ws.close();
    return;
  }

  if (!containerId) {
    ws.send(JSON.stringify({ type: 'error', data: `Container not found for ${user.project_name}. The service may be stopped or still deploying.` }));
    ws.close();
    return;
  }

  // Spawn `docker exec -it <container> /bin/bash` via child_process
  // This bypasses dockerode's broken hijack mode in Swarm
  // Use `script` to force PTY allocation for docker exec.
  // Without a PTY, bash runs silently (no prompt, no color, no interactive features).
  // `script -q /dev/null` creates a pseudo-terminal wrapper.
  const shell = spawn('script', [
    '-q', '/dev/null',
    'docker', 'exec', '-it',
    '-e', 'TERM=xterm-256color',
    '-e', 'COLUMNS=120',
    '-e', 'LINES=30',
    containerId,
    '/bin/bash',
  ]);

  if (!shell.pid) {
    ws.send(JSON.stringify({ type: 'error', data: 'Failed to start shell. Docker exec may not be available.' }));
    ws.close();
    return;
  }

  let closed = false;
  let lastActivity = Date.now();
  const SESSION_TIMEOUT = 60 * 60 * 1000;

  const cleanup = (reason) => {
    if (closed) return;
    closed = true;
    clearInterval(heartbeatInterval);
    clearInterval(activityCheckInterval);
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ type: 'exit', data: reason || 'Session ended.' }));
      ws.close();
    }
    try { shell.kill(); } catch (_) {}
  };

  // Container stdout → browser
  shell.stdout.on('data', (chunk) => {
    lastActivity = Date.now();
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ type: 'output', data: chunk.toString() }));
    }
  });

  // Container stderr → browser
  shell.stderr.on('data', (chunk) => {
    lastActivity = Date.now();
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ type: 'output', data: chunk.toString() }));
    }
  });

  // Shell process exited
  shell.on('close', (code) => {
    cleanup(`Shell exited (code ${code}).`);
  });

  shell.on('error', (err) => {
    cleanup(`Shell error: ${err.message}`);
  });

  // Browser → container stdin
  ws.on('message', (msg) => {
    if (closed) return;
    lastActivity = Date.now();
    try {
      const parsed = JSON.parse(msg);
      if (parsed.type === 'input') {
        shell.stdin.write(parsed.data);
      } else if (parsed.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
      }
      // Note: resize not supported via docker exec CLI — terminal uses initial size
    } catch {
      shell.stdin.write(msg.toString());
    }
  });

  ws.on('close', () => {
    closed = true;
    clearInterval(heartbeatInterval);
    clearInterval(activityCheckInterval);
    try { shell.kill(); } catch (_) {}
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
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({ type: 'output', data: '\r\n\x1b[33m[Session timed out after 1 hour of inactivity]\x1b[0m\r\n' }));
      }
      cleanup('Session timed out.');
    }
  }, 60000);

  ws.send(JSON.stringify({ type: 'connected', data: `Connected to ${user.project_name}` }));
});

// ==================== START ====================

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`OpenClaw Panel running on http://localhost:${PORT}`);
  console.log(`Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`User Panel:  http://localhost:${PORT}/panel`);
});
