import { loadConfig } from './config.js';
import { cacheStats, isDbFileEncrypted } from './cache.js';
import { localAuthDiagnostics } from './local-auth.js';
import { getKeyStorageStatus } from './facility-key.js';
import { hasBaseline, getLastCheckStatus } from './integrity-check.js';

const INTEGRITY_CHECK_INTERVAL_HOURS = 6;

/**
 * Local-only status (no network calls) -- used by GET /health and
 * npm run diagnostics. Deliberately honest about what v0.1.2 hardening this
 * build has NOT implemented yet, rather than echoing the doc's
 * fully-hardened installer output verbatim.
 */
export async function getSystemStatus() {
  const config = loadConfig();
  const auth = localAuthDiagnostics();
  const cache = await cacheStats();
  const keyStorage = await getKeyStorageStatus();
  const encryption = isDbFileEncrypted(cache.dbPath);

  return {
    stubVersion: '0.1.2',
    cache: {
      encrypted: encryption.fileExists ? encryption.encrypted : null, // null: DB not created yet, nothing to verify
      totalEntries: cache.totalEntries,
      dbPath: cache.dbPath,
    },
    keys: {
      storage: keyStorage, // 'keystore' | 'file' | 'missing'
    },
    integrity: {
      baselineExists: hasBaseline(),
      lastCheckStatus: getLastCheckStatus(), // 'pass' | 'fail' | 'not_checked'
      checkIntervalHours: INTEGRITY_CHECK_INTERVAL_HOURS,
    },
    auth: {
      secretConfigured: auth.secretConfigured,
      lockedIps: auth.lockedIps,
    },
    facility: {
      did: config.HUUID_FACILITY_DID,
      code: config.HUUID_FACILITY_CODE,
    },
    resolver: {
      baseUrl: config.HUUID_RESOLVER_BASE_URL,
    },
  };
}
