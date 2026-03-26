const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

class BackupService {
  constructor(db, easypanel) {
    this.db = db;
    this.easypanel = easypanel;
    this.tmpDir = path.join(os.tmpdir(), 'openclaw-backups');
    if (!fs.existsSync(this.tmpDir)) fs.mkdirSync(this.tmpDir, { recursive: true });

    // S3 client for Vultr Object Storage
    const endpoint = process.env.S3_ENDPOINT;
    const accessKey = process.env.S3_ACCESS_KEY;
    const secretKey = process.env.S3_SECRET_KEY;
    this.bucket = process.env.S3_BUCKET;
    this.configured = !!(endpoint && accessKey && secretKey && this.bucket);

    if (this.configured) {
      this.s3 = new S3Client({
        endpoint,
        region: 'us-east-1', // Vultr ignores region but SDK requires it
        credentials: { accessKeyId: accessKey, secretAccessKey: secretKey },
        forcePathStyle: true, // Required for Vultr S3
      });
      console.log(`[Backup] S3 configured: ${endpoint} / ${this.bucket}`);
    } else {
      console.log('[Backup] S3 NOT configured - backup features disabled');
    }
  }

  /**
   * Find the Docker container for a user's OpenClaw service
   */
  findContainer(user) {
    const patterns = [
      `${user.project_name}_${user.service_name || 'openclaw-gateway'}`,
      `${user.project_name}_openclaw-gateway`,
    ];

    try {
      const allContainers = execSync('docker ps --format "{{.Names}}" 2>/dev/null', { timeout: 10000 })
        .toString().trim().split('\n').filter(Boolean);

      for (const pattern of patterns) {
        const match = allContainers.find(c => c.includes(pattern));
        if (match) return match;
      }
    } catch (e) {
      console.error('[Backup] Failed to list containers:', e.message);
    }
    return null;
  }

  /**
   * Create a backup for a user
   */
  async createBackup(user, type = 'manual') {
    if (!this.configured) throw new Error('Backup storage not configured');

    const container = this.findContainer(user);
    if (!container) throw new Error('Container not found. Service may not be running.');

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${user.username}-${timestamp}.tar.gz`;
    const localPath = path.join(this.tmpDir, filename);
    const s3Key = `backups/${user.username}/${filename}`;

    try {
      // Step 1: Check if .openclaw exists and create tar.gz
      console.log(`[Backup] Creating archive in container ${container}...`);
      execSync(
        `docker exec ${container} sh -c "test -d /home/node/.openclaw && tar czf /tmp/backup.tar.gz -C /home/node .openclaw || (mkdir -p /home/node/.openclaw && tar czf /tmp/backup.tar.gz -C /home/node .openclaw)"`,
        { timeout: 120000 }
      );

      // Step 2: Copy tar out of container
      console.log(`[Backup] Copying archive from container...`);
      execSync(`docker cp ${container}:/tmp/backup.tar.gz ${localPath}`, { timeout: 60000 });

      // Step 3: Clean up inside container
      try { execSync(`docker exec ${container} rm -f /tmp/backup.tar.gz`, { timeout: 5000 }); } catch (_) {}

      // Step 4: Get file size
      const stats = fs.statSync(localPath);
      const sizeBytes = stats.size;

      // Step 5: Upload to S3
      console.log(`[Backup] Uploading to S3: ${s3Key} (${(sizeBytes / 1024 / 1024).toFixed(1)} MB)...`);
      const fileStream = fs.readFileSync(localPath);
      await this.s3.send(new PutObjectCommand({
        Bucket: this.bucket,
        Key: s3Key,
        Body: fileStream,
        ContentType: 'application/gzip',
      }));

      // Step 6: Save to database
      const result = this.db.createBackupRecord({
        user_id: user.id,
        username: user.username,
        filename,
        s3_key: s3Key,
        size_bytes: sizeBytes,
        status: 'completed',
        type,
      });

      // Step 7: Clean up local file
      try { fs.unlinkSync(localPath); } catch (_) {}

      console.log(`[Backup] Backup completed: ${filename} (${(sizeBytes / 1024 / 1024).toFixed(1)} MB)`);

      return {
        id: result.lastInsertRowid,
        filename,
        s3_key: s3Key,
        size_bytes: sizeBytes,
      };
    } catch (err) {
      // Clean up on error
      try { fs.unlinkSync(localPath); } catch (_) {}
      throw err;
    }
  }

  /**
   * Restore a backup for a user
   */
  async restoreBackup(user, backupId) {
    if (!this.configured) throw new Error('Backup storage not configured');

    const backup = this.db.getBackupById(backupId);
    if (!backup) throw new Error('Backup not found');
    if (backup.user_id !== user.id) throw new Error('Backup does not belong to this user');

    const localPath = path.join(this.tmpDir, backup.filename);
    const serviceName = user.service_name || 'openclaw-gateway';

    try {
      // Step 1: Download from S3
      console.log(`[Backup] Downloading from S3: ${backup.s3_key}...`);
      const response = await this.s3.send(new GetObjectCommand({
        Bucket: this.bucket,
        Key: backup.s3_key,
      }));

      const chunks = [];
      for await (const chunk of response.Body) {
        chunks.push(chunk);
      }
      fs.writeFileSync(localPath, Buffer.concat(chunks));

      // Step 2: Find the running container and copy backup into it
      const container = this.findContainer(user);
      if (!container) throw new Error('Container not found. Service may not be running.');

      console.log(`[Backup] Copying backup into container...`);
      execSync(`docker cp ${localPath} ${container}:/tmp/backup.tar.gz`, { timeout: 60000 });

      // Step 3: Extract backup OVER existing data (without deleting mounted dirs)
      // Use --overwrite and extract on top of existing directory to avoid "device busy" errors
      console.log(`[Backup] Extracting backup over existing data...`);
      execSync(
        `docker exec ${container} sh -c "cd /home/node && tar xzf /tmp/backup.tar.gz --overwrite && rm -f /tmp/backup.tar.gz && chown -R node:node /home/node/.openclaw"`,
        { timeout: 120000 }
      );

      // Step 4: Clean up local file
      try { fs.unlinkSync(localPath); } catch (_) {}

      // Step 5: Restart the service to pick up restored config
      console.log(`[Backup] Restarting service...`);
      try {
        await this.easypanel.deployService(user.project_name, serviceName);
      } catch (e) {
        console.error('[Backup] Service restart failed:', e.message);
      }

      console.log(`[Backup] Restore completed for ${user.username}`);
      return { success: true };
    } catch (err) {
      // Clean up and try to restart service on failure
      try { fs.unlinkSync(localPath); } catch (_) {}
      try {
        await this.easypanel.deployService(user.project_name, serviceName);
      } catch (_) {}
      throw err;
    }
  }

  /**
   * Delete a backup from S3 and database
   */
  async deleteBackup(backupId) {
    const backup = this.db.getBackupById(backupId);
    if (!backup) throw new Error('Backup not found');

    // Delete from S3
    if (this.configured) {
      try {
        await this.s3.send(new DeleteObjectCommand({
          Bucket: this.bucket,
          Key: backup.s3_key,
        }));
      } catch (e) {
        console.error('[Backup] S3 delete failed:', e.message);
      }
    }

    // Delete from database
    this.db.deleteBackupRecord(backupId);
    console.log(`[Backup] Deleted: ${backup.filename}`);
    return { success: true };
  }

  /**
   * Clean up old backups (keep only keepCount most recent)
   */
  async cleanupOldBackups(userId, keepCount = 7) {
    const oldBackups = this.db.getOldBackups(userId, keepCount);
    for (const backup of oldBackups) {
      try {
        await this.deleteBackup(backup.id);
      } catch (e) {
        console.error(`[Backup] Cleanup failed for backup ${backup.id}:`, e.message);
      }
    }
    return oldBackups.length;
  }

  /**
   * Run auto-backups for all users with auto_backup enabled
   */
  async runAutoBackups() {
    if (!this.configured) return;

    const users = this.db.getUsersWithAutoBackup();
    console.log(`[Auto-Backup] Checking ${users.length} users with auto-backup enabled...`);

    for (const userData of users) {
      try {
        // Check if last backup was >24h ago
        const latest = this.db.getLatestBackup(userData.id);
        if (latest) {
          const lastTime = new Date(latest.created_at).getTime();
          const hoursSince = (Date.now() - lastTime) / (1000 * 60 * 60);
          if (hoursSince < 23.5) {
            continue; // Skip — backed up recently
          }
        }

        // Strip password from user object
        const { password: _, api_key_encrypted: __, ...user } = userData;

        console.log(`[Auto-Backup] Backing up ${user.username}...`);
        await this.createBackup(user, 'auto');

        // Clean up old backups (keep 7)
        await this.cleanupOldBackups(user.id, 7);

        this.db.logActivity(user.id, 'auto_backup', 'Automatic daily backup completed');
      } catch (e) {
        console.error(`[Auto-Backup] Failed for ${userData.username}:`, e.message);
      }
    }
  }

  /**
   * Start auto-backup cron (runs every 60 minutes)
   */
  startAutoCron() {
    if (!this.configured) {
      console.log('[Backup] Auto-backup cron not started (S3 not configured)');
      return;
    }

    console.log('[Backup] Auto-backup cron started (every 60 minutes)');
    setInterval(() => {
      this.runAutoBackups().catch(e => console.error('[Auto-Backup] Cron error:', e.message));
    }, 60 * 60 * 1000); // Every 60 minutes

    // Run once on startup after 2 minutes
    setTimeout(() => {
      this.runAutoBackups().catch(e => console.error('[Auto-Backup] Initial run error:', e.message));
    }, 2 * 60 * 1000);
  }
}

module.exports = BackupService;
