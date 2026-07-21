import { cacheStats, isDbFileEncrypted } from './cache.js';
import { localAuthDiagnostics } from './local-auth.js';
import { getKeyStorageStatus } from './facility-key.js';
import { hasBaseline, getLastCheckStatus, isIntegrityOverrideActive } from './integrity-check.js';

const INTEGRITY_CHECK_INTERVAL_HOURS = 6;

/**
 * P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): this module receives
 * facilityDID, facilityCode, and resolverBaseUrl -- purely for display in
 * the status report (GET /health, npm run diagnostics), not for any
 * secret-touching operation. No apiKey, localSecret, or key-storage path.
 */
export interface StatusModuleConfig {
  facilityDID: string;
  facilityCode: string;
  resolverBaseUrl: string;
}

let moduleConfig: StatusModuleConfig | null = null;

/** Called once by the orchestrator before getSystemStatus() is used. */
export function initStatusModule(cfg: StatusModuleConfig): void {
  moduleConfig = cfg;
}

function requireInit(): StatusModuleConfig {
  if (!moduleConfig) {
    throw new Error('status module not initialized. Call initStatusModule() first.');
  }
  return moduleConfig;
}

/**
 * Local-only status (no network calls) -- used by GET /health and
 * npm run diagnostics. Deliberately honest about what v0.1.2 hardening this
 * build has NOT implemented yet, rather than echoing the doc's
 * fully-hardened installer output verbatim.
 */
export async function getSystemStatus() {
  const cfg = requireInit();
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
      overrideActive: isIntegrityOverrideActive(),
    },
    auth: {
      secretConfigured: auth.secretConfigured,
      lockedIps: auth.lockedIps,
    },
    facility: {
      did: cfg.facilityDID,
      code: cfg.facilityCode,
    },
    resolver: {
      baseUrl: cfg.resolverBaseUrl,
    },
  };
}
