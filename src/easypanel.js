const crypto = require('crypto');

class EasypanelAPI {
  constructor(endpoint, token) {
    this.endpoint = endpoint.replace(/\/$/, '');
    this.token = token;
  }

  // Generate random hex token
  generateToken(length = 64) {
    return crypto.randomBytes(length / 2).toString('hex');
  }

  // GET request to tRPC endpoint
  async get(route, input = null) {
    let url = `${this.endpoint}/api/trpc/${route}`;
    if (input) {
      url += `?input=${encodeURIComponent(JSON.stringify({ json: input }))}`;
    }
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Easypanel GET ${route} failed (${res.status}): ${text}`);
    }
    const data = await res.json();
    return data.result?.data?.json ?? data.result?.data ?? data;
  }

  // POST request to tRPC endpoint
  async post(route, body) {
    const res = await fetch(`${this.endpoint}/api/trpc/${route}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ json: body }),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Easypanel POST ${route} failed (${res.status}): ${text}`);
    }
    const data = await res.json();
    return data.result?.data?.json ?? data.result?.data ?? data;
  }

  // --- Project Methods ---
  async listProjects() {
    return this.get('projects.listProjects');
  }

  async inspectProject(projectName) {
    return this.get('projects.inspectProject', { projectName });
  }

  async createProject(name) {
    return this.post('projects.createProject', { name });
  }

  async destroyProject(name) {
    return this.post('projects.destroyProject', { name });
  }

  // --- Service Methods ---
  async createService(projectName, serviceName, options = {}) {
    return this.post('services.app.createService', {
      projectName,
      serviceName,
      ...options,
    });
  }

  async destroyService(projectName, serviceName) {
    return this.post('services.app.destroyService', { projectName, serviceName });
  }

  async deployService(projectName, serviceName) {
    return this.post('services.app.deployService', { projectName, serviceName });
  }

  async enableService(projectName, serviceName) {
    return this.post('services.app.enableService', { projectName, serviceName });
  }

  async disableService(projectName, serviceName) {
    return this.post('services.app.disableService', { projectName, serviceName });
  }

  async inspectService(projectName, serviceName) {
    return this.post('services.app.inspectService', { projectName, serviceName });
  }

  async updateSourceImage(projectName, serviceName, image) {
    return this.post('services.app.updateSourceImage', { projectName, serviceName, image });
  }

  async updateEnv(projectName, serviceName, env) {
    return this.post('services.app.updateEnv', { projectName, serviceName, env });
  }

  async updateMounts(projectName, serviceName, mounts) {
    return this.post('services.app.updateMounts', { projectName, serviceName, mounts });
  }

  async updateResources(projectName, serviceName, resources) {
    return this.post('services.app.updateResources', { projectName, serviceName, resources });
  }

  async updateDeploy(projectName, serviceName, options) {
    return this.post('services.app.updateDeploy', { projectName, serviceName, ...options });
  }

  async updateDomains(projectName, serviceName, domains) {
    return this.post('services.app.updateDomains', { projectName, serviceName, domains });
  }

  async updatePorts(projectName, serviceName, ports) {
    return this.post('services.app.updatePorts', { projectName, serviceName, ports });
  }

  // --- Monitoring ---
  async getSystemStats() {
    return this.get('monitor.getSystemStats');
  }

  async getMonitorTableData() {
    return this.get('monitor.getMonitorTableData');
  }

  async getAdvancedStats() {
    return this.get('monitor.getAdvancedStats');
  }

  async getDockerTaskStats() {
    return this.get('monitor.getDockerTaskStats');
  }

  // --- Logs ---
  async getServiceLogs(projectName, serviceName) {
    return this.get('logs.getServiceLogs', { projectName, serviceName });
  }

  // --- Auth / Settings ---
  async getUser() {
    return this.get('auth.getUser');
  }

  async getServerIp() {
    return this.get('settings.getServerIp');
  }

  // --- High-level: Deploy an OpenClaw instance ---
  async deployOpenClawInstance(username, config = {}) {
    const projectName = `oc-${username}`;
    const serviceName = 'openclaw-gateway';
    const baseDomain = config.baseDomain || process.env.BASE_DOMAIN || 'rarhost.store';
    const domain = `${username}-openclaw.${baseDomain.replace(/^openclaw\./, '')}`;
    const gatewayToken = this.generateToken(64);
    const image = config.image || process.env.OPENCLAW_IMAGE || 'ghcr.io/openclaw/openclaw:2026.2.3';
    const cpuLimit = config.cpuLimit || 4;
    const memoryLimit = config.memoryLimit || 4096;

    try {
      // 1. Create project
      await this.createProject(projectName);

      // 2. Create app service with domain, mounts, and deploy config bundled
      await this.createService(projectName, serviceName, {
        domains: [{ host: domain, https: true, port: 18789, path: '/' }],
        mounts: [
          { type: 'volume', name: 'config', mountPath: '/home/node/.openclaw' },
          { type: 'volume', name: 'workspace', mountPath: '/home/node/.openclaw/workspace' },
        ],
        deploy: {
          replicas: 1,
          command: 'node dist/index.js gateway --bind lan --port 18789 --allow-unconfigured',
          zeroDowntime: true,
        },
      });

      // 3. Set Docker image
      await this.updateSourceImage(projectName, serviceName, image);

      // 4. Set environment variables
      const envString = [
        `HOME=/home/node`,
        `TERM=xterm-256color`,
        `OPENCLAW_GATEWAY_TOKEN=${gatewayToken}`,
      ].join('\n');
      await this.updateEnv(projectName, serviceName, envString);

      // 5. Set resource limits
      try {
        await this.updateResources(projectName, serviceName, {
          cpuLimit,
          cpuReservation: 0,
          memoryLimit,
          memoryReservation: 0,
        });
      } catch (_) {}

      // 6. Deploy
      await this.deployService(projectName, serviceName);

      return {
        projectName,
        serviceName,
        domain,
        gatewayToken,
        url: `https://${domain}`,
      };
    } catch (err) {
      // Cleanup on failure
      try {
        await this.destroyProject(projectName);
      } catch (_) {}
      throw new Error(`Failed to deploy OpenClaw for ${username}: ${err.message}`);
    }
  }

  // Get container stats for a specific project
  async getUserStats(projectName) {
    const allStats = await this.getMonitorTableData();
    if (!Array.isArray(allStats)) return null;
    return allStats.filter(s =>
      s.serviceName?.includes(projectName) || s.projectName === projectName
    );
  }
}

module.exports = EasypanelAPI;
