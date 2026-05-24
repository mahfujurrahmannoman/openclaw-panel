'use strict';

/**
 * Surgically removes invalid keys from a user's OpenClaw config so the
 * gateway container can start.
 *
 * Background: OpenClaw 2026.2.3+ ships a stricter config schema that
 * rejects keys like `channels.whatsapp.enabled` and
 * `channels.telegram.streaming` (added by older onboarding wizards).
 * Containers exit with code 1 before reaching `gateway`, so the standard
 * `openclaw doctor --fix` can't be run inside them — they never stay up.
 *
 * Fix flow: spin up a one-shot `node:22-alpine` sidecar that mounts the
 * user's `<project>_config` Docker volume, deletes the bad keys from
 * openclaw.json, restores uid:gid 1000:1000 (the `node` user used by the
 * OpenClaw image), exits. Then the caller redeploys the swarm service.
 */

// Keys that OpenClaw 2026.2.3+ rejects. Add new ones here as they surface.
const BAD_KEY_PATHS = [
  'channels.whatsapp.enabled',
  'channels.telegram.streaming',
];

const FIXER_IMAGE = 'node:22-alpine';
const NODE_UID = 1000;
const NODE_GID = 1000;

/**
 * Container-side script. Runs inside `node:22-alpine` with the config
 * volume mounted at /data. Prints a single JSON line on stdout summarising
 * what changed; exits non-zero on parse failure.
 */
function buildFixerScript(badKeyPaths) {
  return `
    const fs = require('fs');
    const fsp = require('fs/promises');
    const path = require('path');

    // Recursively find openclaw.json — older containers stored it at /data/openclaw.json,
    // newer ones nest it under e.g. /data/state/openclaw.json. Walk a few levels deep.
    function findConfig(root, depth = 3) {
      const hits = [];
      function walk(dir, left) {
        if (left < 0) return;
        let ents;
        try { ents = fs.readdirSync(dir, { withFileTypes: true }); }
        catch { return; }
        for (const e of ents) {
          const p = path.join(dir, e.name);
          if (e.isFile() && e.name === 'openclaw.json') hits.push(p);
          else if (e.isDirectory() && !e.name.startsWith('.git')) walk(p, left - 1);
        }
      }
      walk(root, depth);
      return hits;
    }

    function listing(root, depth = 2) {
      const out = [];
      function walk(dir, left) {
        if (left < 0) return;
        let ents;
        try { ents = fs.readdirSync(dir, { withFileTypes: true }); }
        catch { return; }
        for (const e of ents) {
          const p = path.join(dir, e.name);
          out.push((e.isDirectory() ? '[d] ' : '    ') + p);
          if (e.isDirectory()) walk(p, left - 1);
        }
      }
      walk(root, depth);
      return out;
    }

    const candidates = findConfig('/data', 3);
    if (candidates.length === 0) {
      const ls = listing('/data', 2).slice(0, 80);
      console.log(JSON.stringify({ status: 'NO_CONFIG', listing: ls }));
      process.exit(0);
    }

    const badKeys = ${JSON.stringify(badKeyPaths)};
    const fixed = [];
    let totalRemoved = 0;
    let anyChanged = false;

    for (const target of candidates) {
      let cfg;
      try { cfg = JSON.parse(fs.readFileSync(target, 'utf8')); }
      catch (e) {
        fixed.push({ path: target, error: 'PARSE_ERROR: ' + e.message });
        continue;
      }
      const removed = [];
      for (const dotted of badKeys) {
        const parts = dotted.split('.');
        let obj = cfg;
        for (let i = 0; i < parts.length - 1; i++) {
          if (!obj || typeof obj !== 'object') { obj = null; break; }
          obj = obj[parts[i]];
        }
        const leaf = parts[parts.length - 1];
        if (obj && typeof obj === 'object' && leaf in obj) {
          delete obj[leaf];
          removed.push(dotted);
        }
      }
      if (removed.length > 0) {
        fs.writeFileSync(target, JSON.stringify(cfg, null, 2) + '\\n');
        try { fs.chownSync(target, ${NODE_UID}, ${NODE_GID}); } catch {}
        anyChanged = true;
        totalRemoved += removed.length;
      }
      fixed.push({ path: target, removed });
    }

    console.log(JSON.stringify({
      status: anyChanged ? 'FIXED' : 'NO_CHANGE',
      files: fixed,
      totalRemoved,
    }));
  `;
}

/**
 * Strip Docker's 8-byte stdout/stderr frame headers. Identical to the
 * helper in docker-stats.js — duplicated here to avoid a circular import.
 */
function stripDockerHeader(buf) {
  if (!Buffer.isBuffer(buf)) return String(buf || '');
  const out = [];
  let i = 0;
  while (i + 8 <= buf.length) {
    const size = buf.readUInt32BE(i + 4);
    const start = i + 8;
    const end = start + size;
    if (end > buf.length) break;
    out.push(buf.slice(start, end).toString('utf8'));
    i = end;
  }
  return out.length > 0 ? out.join('') : buf.toString('utf8');
}

/** Best-effort: pull the fixer image if it isn't already cached locally. */
async function ensureImage(docker, image) {
  try {
    await docker.getImage(image).inspect();
    return; // already cached
  } catch {
    // not cached — pull
  }
  await new Promise((resolve, reject) => {
    docker.pull(image, (err, stream) => {
      if (err) return reject(err);
      docker.modem.followProgress(stream, (e) => e ? reject(e) : resolve());
    });
  });
}

/**
 * Fix the config volume for one project.
 *
 * Returns: { status: 'FIXED'|'NO_CHANGE'|'NO_CONFIG', removed?: string[],
 *            exitCode: number, output: string }
 */
async function fixUserConfig(docker, projectName) {
  if (!projectName) throw new Error('projectName required');
  const volumeName = `${projectName}_config`;

  await ensureImage(docker, FIXER_IMAGE);

  const script = buildFixerScript(BAD_KEY_PATHS);

  const container = await docker.createContainer({
    Image: FIXER_IMAGE,
    Cmd: ['node', '-e', script],
    HostConfig: {
      Binds: [`${volumeName}:/data`],
      // Don't auto-remove — we need to read logs after exit.
      AutoRemove: false,
    },
    Tty: false,
    AttachStdout: true,
    AttachStderr: true,
  });

  let logs = '';
  let exitCode = -1;
  try {
    await container.start();
    const waitResult = await container.wait();
    exitCode = waitResult.StatusCode;
    const logBuf = await container.logs({ stdout: true, stderr: true, tail: 200 });
    logs = stripDockerHeader(logBuf);
  } finally {
    try { await container.remove({ force: true }); } catch {}
  }

  // Parse the last JSON line of the fixer's stdout, if any.
  let result = { status: 'UNKNOWN' };
  const lines = logs.split('\n').map(l => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].startsWith('{') && lines[i].endsWith('}')) {
      try { result = JSON.parse(lines[i]); break; } catch {}
    }
  }

  return { ...result, exitCode, output: logs, volumeName };
}

module.exports = {
  BAD_KEY_PATHS,
  fixUserConfig,
};
