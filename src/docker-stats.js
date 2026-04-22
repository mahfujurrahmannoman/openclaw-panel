'use strict';

/**
 * Direct Docker stats collector.
 *
 * Replaces the Easypanel `monitor.*` tRPC endpoints which were removed in a
 * recent Easypanel update (all return 404). Uses the Docker socket directly
 * via dockerode, which is already mounted for terminal and backup features.
 *
 * Exposes the same response shapes the existing admin/user dashboards expect,
 * so no frontend changes are needed.
 */

const fs = require('fs');

/**
 * Calculate CPU % from a single `stats({stream: false})` response. Docker's
 * one-shot call returns both the current `cpu_stats` and the previous
 * `precpu_stats` so we can compute a delta without a second request.
 *
 * Formula: (cpu_delta / system_delta) * num_cpus * 100
 */
function calculateCpuPercent(stats) {
  const cur = stats.cpu_stats || {};
  const pre = stats.precpu_stats || {};
  const cpuDelta = (cur.cpu_usage?.total_usage ?? 0) - (pre.cpu_usage?.total_usage ?? 0);
  const systemDelta = (cur.system_cpu_usage ?? 0) - (pre.system_cpu_usage ?? 0);
  const numCpus = cur.online_cpus
    ?? cur.cpu_usage?.percpu_usage?.length
    ?? 1;
  if (systemDelta > 0 && cpuDelta > 0) {
    return (cpuDelta / systemDelta) * numCpus * 100;
  }
  return 0;
}

/** Sum rx/tx bytes across all network interfaces reported for the container. */
function sumNetworks(stats) {
  let rx = 0, tx = 0;
  const nets = stats.networks || {};
  for (const iface of Object.values(nets)) {
    rx += iface.rx_bytes ?? 0;
    tx += iface.tx_bytes ?? 0;
  }
  return { rx, tx };
}

/**
 * Pull project/service names out of swarm container labels.
 *
 * Easypanel deploys each service as a Docker Swarm stack, so containers carry:
 *   - com.docker.stack.namespace      -> projectName (e.g. "oc-alice")
 *   - com.docker.swarm.service.name   -> "<projectName>_<serviceName>"
 */
function extractNames(container) {
  const labels = container.Labels || {};
  const swarmService = labels['com.docker.swarm.service.name'] || '';
  const namespace = labels['com.docker.stack.namespace'] || '';
  let projectName = namespace;
  let serviceName = '';
  if (swarmService) {
    if (namespace && swarmService.startsWith(namespace + '_')) {
      serviceName = swarmService.substring(namespace.length + 1);
    } else {
      const idx = swarmService.indexOf('_');
      if (idx > 0) {
        projectName = projectName || swarmService.substring(0, idx);
        serviceName = swarmService.substring(idx + 1);
      } else {
        serviceName = swarmService;
      }
    }
  }
  return { projectName, serviceName, swarmServiceName: swarmService };
}

/**
 * Snapshot of stats for every running swarm container.
 *
 * Returns an array in the shape the dashboards already consume:
 *   [{ projectName, serviceName, stats: { cpu: {percent},
 *                                         memory: {usage, limit, percent},
 *                                         network: {in, out} } }]
 */
async function getContainerStats(docker) {
  const containers = await docker.listContainers({ all: false });
  // Only include swarm-managed containers — plain standalone containers
  // don't carry the stack labels and aren't user services.
  const swarmContainers = containers.filter(c =>
    (c.Labels || {})['com.docker.swarm.service.name']
  );

  const results = await Promise.all(swarmContainers.map(async (c) => {
    try {
      const { projectName, serviceName } = extractNames(c);
      if (!projectName) return null;

      const dc = docker.getContainer(c.Id);
      const stats = await dc.stats({ stream: false });

      const cpuPct = calculateCpuPercent(stats);
      const memUsage = stats.memory_stats?.usage ?? 0;
      const memLimit = stats.memory_stats?.limit ?? 0;
      const memPct = memLimit > 0 ? (memUsage / memLimit) * 100 : 0;
      const net = sumNetworks(stats);

      return {
        projectName,
        serviceName,
        stats: {
          cpu: { percent: cpuPct },
          memory: { usage: memUsage, limit: memLimit, percent: memPct },
          network: { in: net.rx, out: net.tx },
        },
      };
    } catch {
      return null;
    }
  }));

  return results.filter(Boolean);
}

/**
 * Build the swarm task map the dashboards expect:
 *   { "<projectName>_<serviceName>": { actual, desired } }
 *
 * `actual` = count of tasks currently in "running" state for this service.
 * `desired` = replicas for replicated services, or 1 for global services.
 */
async function getSwarmTaskStats(docker) {
  try {
    const [services, tasks] = await Promise.all([
      docker.listServices(),
      docker.listTasks({}),
    ]);

    const map = {};
    services.forEach(svc => {
      const name = svc.Spec?.Name;
      if (!name) return;
      const desired = svc.Spec?.Mode?.Replicated?.Replicas
        ?? (svc.Spec?.Mode?.Global ? 1 : 0);
      const running = tasks.filter(t =>
        t.ServiceID === svc.ID && t.Status?.State === 'running'
      ).length;
      map[name] = { actual: running, desired };
    });
    return map;
  } catch {
    return {};
  }
}

/**
 * Server-level stats shaped to match the previous Easypanel response so the
 * existing admin gauges render without frontend changes.
 *
 * - CPU% is aggregated across all swarm containers, normalised to host cores.
 * - Memory is "used by containers / total host memory".
 * - Disk uses fs.statfsSync on /app/data (mounted as a host-backed volume),
 *   which reports the host filesystem that contains it.
 */
async function getSystemStats(docker) {
  try {
    const [info, containerStats] = await Promise.all([
      docker.info().catch(() => ({})),
      getContainerStats(docker),
    ]);

    const ncpu = info.NCPU || 1;
    const totalMemBytes = info.MemTotal || 0;

    let totalCpuPct = 0;
    let totalMemUsed = 0;
    for (const c of containerStats) {
      totalCpuPct += c.stats?.cpu?.percent ?? 0;
      totalMemUsed += c.stats?.memory?.usage ?? 0;
    }
    const aggCpuPct = ncpu > 0 ? Math.min(totalCpuPct / ncpu, 100) : totalCpuPct;

    const totalMemMb = totalMemBytes / (1024 * 1024);
    const usedMemMb = totalMemUsed / (1024 * 1024);
    const memPct = totalMemMb > 0 ? (usedMemMb / totalMemMb) * 100 : 0;

    // Disk from /app/data — that volume is backed by the host filesystem,
    // so its total/free reflect the underlying host disk.
    let totalGb = 0, usedGb = 0, diskPct = 0;
    try {
      const st = fs.statfsSync('/app/data');
      const total = st.blocks * st.bsize;
      const free = st.bavail * st.bsize;
      const used = total - free;
      totalGb = total / (1024 ** 3);
      usedGb = used / (1024 ** 3);
      diskPct = total > 0 ? (used / total) * 100 : 0;
    } catch {
      // swallow — the fallback zeros just produce empty gauges
    }

    return {
      cpuInfo: { usedPercentage: aggCpuPct, ncpu },
      memInfo: {
        usedMemMb,
        totalMemMb,
        usedMemPercentage: memPct,
      },
      diskInfo: {
        usedGb,
        totalGb,
        usedPercentage: diskPct,
      },
    };
  } catch {
    return null;
  }
}

/** Filter container stats down to a single project. */
async function getUserStats(docker, projectName) {
  const all = await getContainerStats(docker);
  return all.filter(s => s.projectName === projectName);
}

module.exports = {
  getContainerStats,
  getSwarmTaskStats,
  getSystemStats,
  getUserStats,
};
