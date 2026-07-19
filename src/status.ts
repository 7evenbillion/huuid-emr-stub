import { existsSync } from 'node:fs';
import { loadConfig } from './config.js';
import { cacheStats, isDbFileEncrypted } from './cache.js';
import { localAuthDiagnostics } from './local-auth.js';

/**
 * Local-only status (no network calls) -- used by GET /health and
 * npm run diagnostics. Deliberately honest about what v0.1.2 hardening this
 * base build has NOT implemented yet, rather than echoing the doc's
 * fully-hardened installer output verbatim.
 */
export function getSystemStatus() {
  const config = loadConfig();
  const auth = localAuthDiagnostics();
  const cache = cacheStats();
  const facilityKeyPresent = existsSync(config.HUUID_FACILITY_PRIVATE_KEY_PATH);
  const encryption = isDbFileEncrypted(cache.dbPath);

  return {
    stubVersion: '0.1.2',
    cache: {
      encrypted: encryption.fileExists ? encryption.encrypted : null, // null: DB not created yet, nothing to verify
      totalEntries: cache.totalEntries,
      dbPath: cache.dbPath,
    },
    keys: {
      storage: 'file' as const, // OS keystore not built yet -- explicitly deferred this step
      facilityPrivateKeyPresent: facilityKeyPresent,
    },
    integrity: {
      monitored: false, // HMAC baseline (P4) not built yet -- explicitly deferred this step
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
