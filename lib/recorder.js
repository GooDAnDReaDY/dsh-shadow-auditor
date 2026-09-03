import { createGzip, createGunzip } from 'node:zlib';
import { createReadStream, createWriteStream } from 'node:fs';
import { appendFile, mkdir, readFile, readdir, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';

/**
 * Append-only JSONL audit store with serialized async write queue,
 * gzip rotation on file size threshold, and automated retention cleanup.
 */
export class AuditRecorder {
  constructor(options = {}) {
    this.dir = options.dir;
    this.maxBytes = (options.maxFileSizeMb ?? 50) * 1024 * 1024;
    this.retentionMs = (options.retentionDays ?? 30) * 24 * 60 * 60 * 1000;
    this.queue = Promise.resolve();
    this.cachedBytes = new Map();
    this.lastPrune = 0;
  }

  monthFile(time) {
    const d = new Date(time);
    const month = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    return join(this.dir, `${month}.jsonl`);
  }

  record(record) {
    if (!this.dir) return Promise.resolve();
    const line = `${JSON.stringify(record)}\n`;
    const file = this.monthFile(record.time || Date.now());
    const now = Date.now();

    if (now - this.lastPrune > 24 * 60 * 60 * 1000) {
      this.lastPrune = now;
      this.queue = this.queue
        .then(() => this.pruneArchives(now).then(() => undefined))
        .catch(() => undefined);
    }

    const operation = this.queue.then(async () => {
      await this.append(file, line);
    });
    this.queue = operation.catch(() => undefined);
    return operation;
  }

  async append(file, line) {
    await mkdir(this.dir, { recursive: true });
    let size = this.cachedBytes.get(file);
    if (size === undefined) {
      size = await stat(file).then(entry => entry.size).catch(() => 0);
    }
    const lineBytes = Buffer.byteLength(line);
    if (size > 0 && size + lineBytes > this.maxBytes) {
      await this.archive(file);
      size = 0;
    }
    await appendFile(file, line, 'utf8');
    this.cachedBytes.set(file, size + lineBytes);
  }

  async archive(file) {
    const archivePath = `${file}.${Date.now()}.gz`;
    try {
      await pipeline(createReadStream(file), createGzip(), createWriteStream(archivePath));
      await unlink(file).catch(() => undefined);
      this.cachedBytes.delete(file);
    } catch (_) {}
  }

  async pruneArchives(now = Date.now()) {
    try {
      const files = await readdir(this.dir).catch(() => []);
      let removed = 0;
      for (const file of files) {
        if (!file.endsWith('.gz')) continue;
        const timestamp = Number(file.slice(0, -'.gz'.length).split('.').pop());
        if (!Number.isFinite(timestamp)) continue;
        if (now - timestamp > this.retentionMs) {
          await unlink(join(this.dir, file)).catch(() => undefined);
          removed += 1;
        }
      }
      return removed;
    } catch (_) {
      return 0;
    }
  }

  async readAll() {
    if (!this.dir) return [];
    try {
      const files = await readdir(this.dir).catch(() => []);
      const records = [];
      for (const file of files.sort()) {
        if (!file.endsWith('.jsonl') && !file.endsWith('.gz')) continue;
        try {
          const content = file.endsWith('.gz')
            ? await this.readGzip(join(this.dir, file))
            : await readFile(join(this.dir, file), 'utf8');
          for (const line of content.split('\n')) {
            if (line.trim() === '') continue;
            try {
              records.push(JSON.parse(line));
            } catch (_) {}
          }
        } catch (_) {}
      }
      return records.sort((a, b) => String(a.time).localeCompare(String(b.time)));
    } catch (_) {
      return [];
    }
  }

  async readGzip(file) {
    const chunks = [];
    await pipeline(
      createReadStream(file),
      createGunzip(),
      async function* (source) {
        for await (const chunk of source) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
      }
    );
    return Buffer.concat(chunks).toString('utf8');
  }
}