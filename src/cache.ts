import { Database } from '@signalapp/sqlcipher';
import { mkdirSync, existsSync, chmodSync, openSync, readSync, closeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname } from 'node:path';
import { loadConfig } from './config.js';
import { deriveCacheKeyHex } from './cache-key.js';

export type CacheSource = 'resolver' | 'qr_card';

export interface CacheEntry {
  localPatientId: string;
  huuid: string;
  displayName: string | null;
  bloodType: string | null;
  criticalAllergies: string[];
  serviceEndpoints: string[];
  verifiedAt: number; // unix seconds
  source: CacheSource;
  tokenExpiresAt: number | null;
}

const TTL_SECONDS: Record<CacheSource, number> = {
  resolver: 86400, // 24 hours
  qr_card: 259200, // 72 hours
};

const MAX_ENTRIES = 50000;

/** Real SQLite files always start with this exact 16-byte ASCII header. An
 * SQLCipher-encrypted file's first page is fully encrypted, including this
 * region, so it never matches -- this is what npm run diagnostics uses to
 * prove encryption is active (Step 4). */
const SQLITE_MAGIC_HEADER = 'SQLite format 3\0';

let db: Database | null = null;

/**
 * Restricts the cache DB file to the current user only (Step 5). Best-effort
 * on both platforms -- a failure here is logged but does not stop the server,
 * since the encryption itself (not the filesystem ACL) is the actual
 * confidentiality boundary per P1.
 */
function restrictDbFilePermissions(path: string): void {
  try {
    if (process.platform === 'win32') {
      const user = process.env.USERNAME ?? process.env.USER;
      if (!user) return;
      execFileSync('icacls', [path, '/inheritance:r', '/grant:r', `${user}:F`], {
        stdio: 'ignore',
      });
    } else {
      chmodSync(path, 0o600);
    }
  } catch (err) {
    console.error(
      JSON.stringify({
        level: 'warn',
        event: 'cache_file_permission_restriction_failed',
        detail: err instanceof Error ? err.message : 'unknown',
        timestamp: new Date().toISOString(),
      })
    );
  }
}

async function getDb(): Promise<Database> {
  if (db) return db;
  const config = loadConfig();
  mkdirSync(dirname(config.HUUID_CACHE_DB_PATH), { recursive: true });

  const keyHex = await deriveCacheKeyHex(); // throws with a clear message if no facility private key is found anywhere

  db = new Database(config.HUUID_CACHE_DB_PATH);
  // Raw pre-derived key (Step 2's HKDF output) via SQLCipher's x'...' hex-key
  // syntax -- this bypasses SQLCipher's own passphrase KDF entirely.
  db.pragma(`key = "x'${keyHex}'"`);
  db.pragma('cipher_page_size = 4096');
  // kdf_iter is a no-op in raw-key mode (verified empirically: SQLCipher only
  // runs its internal PBKDF2 when deriving a key from a passphrase). Set for
  // fidelity with the spec anyway -- it does not weaken or strengthen
  // anything here, since HKDF already produced uniform 256-bit key material.
  db.pragma('kdf_iter = 256000');
  // NOTE: `PRAGMA cipher = 'aes-256-gcm'` is intentionally NOT set here.
  // SQLCipher has no GCM mode -- verified against the SQLCipher API docs and
  // empirically (the pragma is silently accepted but `PRAGMA cipher` still
  // reports aes-256-cbc afterward). SQLCipher's real authenticated encryption
  // is AES-256-CBC + HMAC-SHA512 (both defaults, left untouched below).

  db.exec(`
    CREATE TABLE IF NOT EXISTS huuid_local_cache (
      local_patient_id TEXT PRIMARY KEY,
      huuid TEXT NOT NULL,
      display_name TEXT,
      blood_type TEXT,
      critical_allergies TEXT NOT NULL DEFAULT '[]',
      service_endpoints TEXT NOT NULL DEFAULT '[]',
      verified_at INTEGER NOT NULL,
      source TEXT NOT NULL CHECK (source IN ('resolver', 'qr_card')),
      token_expires_at INTEGER
    );
  `);

  restrictDbFilePermissions(config.HUUID_CACHE_DB_PATH);
  return db;
}

/**
 * Eagerly opens (and if needed creates + encrypts) the cache DB, so startup
 * failures -- most importantly a missing facility private key -- surface as
 * one clear message before the server starts accepting requests, rather than
 * as an unhandled exception on the first request (Step 4/DoD item 8).
 */
export async function initializeCache(): Promise<void> {
  await getDb();
}

interface Row {
  local_patient_id: string;
  huuid: string;
  display_name: string | null;
  blood_type: string | null;
  critical_allergies: string;
  service_endpoints: string;
  verified_at: number;
  source: CacheSource;
  token_expires_at: number | null;
}

function rowToEntry(row: Row): CacheEntry {
  return {
    localPatientId: row.local_patient_id,
    huuid: row.huuid,
    displayName: row.display_name,
    bloodType: row.blood_type,
    criticalAllergies: JSON.parse(row.critical_allergies),
    serviceEndpoints: JSON.parse(row.service_endpoints),
    verifiedAt: row.verified_at,
    source: row.source,
    tokenExpiresAt: row.token_expires_at,
  };
}

export async function getCacheEntry(localPatientId: string): Promise<CacheEntry | null> {
  const database = await getDb();
  const row = database
    .prepare('SELECT * FROM huuid_local_cache WHERE local_patient_id = ?')
    .get([localPatientId]) as Row | undefined;
  return row ? rowToEntry(row) : null;
}

/**
 * Never deletes rows -- staleness is derived from (now - verified_at) vs TTL at
 * read time, per "never delete -- mark stale only." The MAX_ENTRIES cap is
 * therefore enforced as a write-side refusal for brand-new patient IDs once the
 * table is full, not as eviction: existing rows can still be refreshed. This
 * resolves a real tension in the spec (a hard cap + a no-delete rule can't both
 * hold via eviction) in the direction of "never delete" as the strict rule.
 */
export async function upsertCacheEntry(
  entry: Omit<CacheEntry, 'verifiedAt'> & { verifiedAt?: number }
): Promise<{ cached: boolean }> {
  const database = await getDb();
  const verifiedAt = entry.verifiedAt ?? Math.floor(Date.now() / 1000);

  const exists = database
    .prepare('SELECT 1 FROM huuid_local_cache WHERE local_patient_id = ?')
    .get([entry.localPatientId]);

  if (!exists) {
    const count = (database.prepare('SELECT COUNT(*) as n FROM huuid_local_cache').get([]) as { n: number }).n;
    if (count >= MAX_ENTRIES) {
      return { cached: false };
    }
  }

  database
    .prepare(
      `INSERT INTO huuid_local_cache
        (local_patient_id, huuid, display_name, blood_type, critical_allergies, service_endpoints, verified_at, source, token_expires_at)
       VALUES (@localPatientId, @huuid, @displayName, @bloodType, @criticalAllergies, @serviceEndpoints, @verifiedAt, @source, @tokenExpiresAt)
       ON CONFLICT(local_patient_id) DO UPDATE SET
         huuid = excluded.huuid,
         display_name = excluded.display_name,
         blood_type = excluded.blood_type,
         critical_allergies = excluded.critical_allergies,
         service_endpoints = excluded.service_endpoints,
         verified_at = excluded.verified_at,
         source = excluded.source,
         token_expires_at = excluded.token_expires_at`
    )
    .run({
      localPatientId: entry.localPatientId,
      huuid: entry.huuid,
      displayName: entry.displayName,
      bloodType: entry.bloodType,
      criticalAllergies: JSON.stringify(entry.criticalAllergies),
      serviceEndpoints: JSON.stringify(entry.serviceEndpoints),
      verifiedAt,
      source: entry.source,
      tokenExpiresAt: entry.tokenExpiresAt,
    });

  return { cached: true };
}

/**
 * Tier thresholds from Section 3.1's resolution priority table -- exported so
 * verify-patient.ts (the only place the actual tier decision tree lives) uses
 * the same numbers the cache TTLs are documented with, rather than duplicating
 * magic numbers.
 */
export const FRESH_WINDOW_SECONDS = 15 * 60; // "cache < 15 min" -- skip a redundant live call
export const CACHE_VALID_SECONDS = TTL_SECONDS.resolver; // "cache < 24 hours old" -- tier 2
export { TTL_SECONDS };

export function cacheAgeSeconds(entry: CacheEntry, nowSeconds = Math.floor(Date.now() / 1000)): number {
  return nowSeconds - entry.verifiedAt;
}

/** For the /debug/resolver page -- most recently verified first. */
export async function listCacheEntries(limit = 100): Promise<CacheEntry[]> {
  const database = await getDb();
  const rows = database
    .prepare('SELECT * FROM huuid_local_cache ORDER BY verified_at DESC LIMIT ?')
    .all([limit]) as unknown as Row[];
  return rows.map(rowToEntry);
}

export async function cacheStats(): Promise<{ totalEntries: number; dbPath: string }> {
  const config = loadConfig();
  const database = await getDb();
  const n = (database.prepare('SELECT COUNT(*) as n FROM huuid_local_cache').get([]) as { n: number }).n;
  return { totalEntries: n, dbPath: config.HUUID_CACHE_DB_PATH };
}

/**
 * Step 4's verification: proves the DB file is not a plain SQLite file by
 * checking for the standard 16-byte magic header every real SQLite file
 * starts with. An encrypted SQLCipher file's first page -- header included
 * -- is ciphertext, so it never matches.
 */
export function isDbFileEncrypted(path: string): { fileExists: boolean; encrypted: boolean } {
  if (!existsSync(path)) {
    return { fileExists: false, encrypted: false };
  }
  const header = Buffer.alloc(16);
  const fd = openSync(path, 'r');
  try {
    readSync(fd, header, 0, 16, 0);
  } finally {
    closeSync(fd);
  }
  const isPlainSqlite = header.toString('utf8') === SQLITE_MAGIC_HEADER;
  return { fileExists: true, encrypted: !isPlainSqlite };
}

export function closeDb(): void {
  db?.close();
  db = null;
}
