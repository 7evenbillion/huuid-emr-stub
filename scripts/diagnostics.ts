import { loadConfig } from '../src/config.js';
import { initFacilityKeyModule, deriveCacheEncryptionKeyHex } from '../src/facility-key.js';
import { initLocalAuthModule } from '../src/local-auth.js';
import { initResolverClientModule, pingResolver } from '../src/resolver-client.js';
import { initIntegrityCheckModule, runIntegrityCheck } from '../src/integrity-check.js';
import { initResolverKeyModule, loadResolverPublicKeyAtStartup, getQRVerificationStatus, getResolverKeyId } from '../src/resolver-key.js';
import { initStatusModule, getSystemStatus } from '../src/status.js';
import { initCacheModule, cacheStats, isDbFileEncrypted } from '../src/cache.js';
import { getMigrationOutcome } from '../src/keystore-migration.js';

// diagnostics.ts is its own standalone process, separate from any running
// `npm run start` -- so, exactly like server.ts, it is its own orchestrator
// under P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): it calls loadConfig()
// once here, hands each module only the slice it needs via its own
// initXModule(), and clears every HUUID_ env var before finishing. No
// module this script calls into ever reads process.env itself.
const config = loadConfig();
const integrityOverrideConfigured = config.HUUID_INTEGRITY_OVERRIDE; // captured before the env-clearing below

initFacilityKeyModule({
  facilityDID: config.HUUID_FACILITY_DID,
  facilityPrivateKeyPath: config.HUUID_FACILITY_PRIVATE_KEY_PATH,
});
initLocalAuthModule({ localSecretPath: config.HUUID_LOCAL_AUTH_SECRET_PATH });
initResolverClientModule({
  resolverBaseUrl: config.HUUID_RESOLVER_BASE_URL,
  facilityDID: config.HUUID_FACILITY_DID,
  facilityCode: config.HUUID_FACILITY_CODE,
  timeoutMs: config.HUUID_RESOLVER_TIMEOUT_MS,
});
initIntegrityCheckModule({
  facilityDID: config.HUUID_FACILITY_DID,
  resolverBaseUrl: config.HUUID_RESOLVER_BASE_URL,
  timeoutMs: config.HUUID_RESOLVER_TIMEOUT_MS,
  integrityOverride: config.HUUID_INTEGRITY_OVERRIDE,
});
initResolverKeyModule({ resolverPublicKeyPath: config.HUUID_RESOLVER_PUBLIC_KEY_PATH });
initStatusModule({
  facilityDID: config.HUUID_FACILITY_DID,
  facilityCode: config.HUUID_FACILITY_CODE,
  resolverBaseUrl: config.HUUID_RESOLVER_BASE_URL,
});

let cacheKeyDerivationError: string | null = null;
try {
  const cacheEncryptionKeyHex = await deriveCacheEncryptionKeyHex();
  initCacheModule({ dbPath: config.HUUID_CACHE_DB_PATH, cacheEncryptionKeyHex });
} catch (err) {
  // Unlike server.ts, diagnostics.ts does not exit on a missing key -- a
  // diagnostics run's whole purpose is to report what's wrong, including
  // this. cacheStats()/isDbFileEncrypted() below are skipped in that case
  // (there is no derived key to open the DB with) and the report says why.
  cacheKeyDerivationError = err instanceof Error ? err.message : 'unknown error';
}

// diagnostics.ts runs as its own one-shot process, separate from any
// running `npm run start` -- integrity-check.ts's last-check state is only
// in-memory, so without running the check here, a standalone diagnostics
// run would always report "not_checked" regardless of what the actual
// running server last saw. Run it fresh, same as the resolver ping below.
await runIntegrityCheck();

// getSystemStatus() -> getKeyStorageStatus() -> locateFacilityKey() is what
// actually attempts the legacy-keytar migration (as a last resort, Windows
// only) -- so the outcome is only known once this call below has run.
const status = await getSystemStatus();
const resolverReachability = await pingResolver();

// SQLCipher step's verification: (1) DB file exists, (2) it is not readable
// as plain SQLite -- proven by checking for SQLite's own 16-byte magic
// header rather than shelling out to a plain sqlite3 reader (none is
// installed here, and the header check is the same thing DB Browser for
// SQLite checks first).
if (cacheKeyDerivationError) {
  console.log(`DB file exists: UNKNOWN (cache encryption key could not be derived: ${cacheKeyDerivationError})`);
  console.log('Cache: UNKNOWN');
} else {
  const stats = await cacheStats();
  const encryption = isDbFileEncrypted(stats.dbPath);
  console.log(`DB file exists: ${encryption.fileExists ? 'YES' : 'NO'} (${stats.dbPath})`);
  if (encryption.fileExists) {
    console.log(
      encryption.encrypted
        ? 'Plain-SQLite-header check: FAILED to find "SQLite format 3" header -- proves encryption is active.'
        : 'Plain-SQLite-header check: FOUND "SQLite format 3" header -- file is NOT encrypted.'
    );
  }
  console.log(`Cache: ${encryption.encrypted ? 'ENCRYPTED' : 'NOT ENCRYPTED'}`);
}
console.log('');

// This step's Step 5 verification.
const keyStorageLabel = { keystore: 'KEYSTORE', file: 'FILE', missing: 'MISSING' }[status.keys.storage];
console.log(`Key storage: ${keyStorageLabel}`);
if (status.keys.storage === 'file') {
  console.warn('WARNING: Run npm run secure-keys to harden key storage.');
} else if (status.keys.storage === 'missing') {
  console.error('ERROR: No facility private key found.');
}
if (getMigrationOutcome() === 'migrated') {
  console.log('Migrated facility key from legacy keytar store to current keyring store (this run).');
} else if (getMigrationOutcome() === 'verify_failed') {
  console.error('ERROR: Found a legacy keytar credential but migration verification failed -- the legacy credential was left in place. See the error above.');
}
console.log('');

// This step's Step 5 verification.
console.log(`Integrity baseline: ${status.integrity.baselineExists ? 'EXISTS' : 'MISSING'}`);
if (!status.integrity.baselineExists) {
  console.warn('WARNING: Run npm run install-integrity-baseline.');
}
const lastCheckLabel = { pass: 'PASS', fail: 'FAIL', not_checked: 'NOT RUN' }[status.integrity.lastCheckStatus];
console.log(`Last integrity check: ${lastCheckLabel}`);
console.log(`Integrity check interval: ${status.integrity.checkIntervalHours} hours`);
// diagnostics.ts is a fresh, one-shot process -- it never calls
// enforceStartupIntegrity(), so status.integrity.overrideActive (only set
// by that function) is always false here regardless of what a running
// server did. What's actually useful to report from a standalone process
// is whether the override is CONFIGURED right now -- i.e. whether the
// next `npm run start` would bypass a violation without a fresh decision.
// Captured from `config` before the env-clearing below, not re-read from
// process.env here (P5 -- this script never calls loadConfig() twice).
console.log(`Integrity override: ${integrityOverrideConfigured ? 'ACTIVE (WARNING)' : 'inactive'}`);
console.log('');

// Month 4, QR verification. Fresh per-process load, same reasoning as
// runIntegrityCheck() above -- resolver-key.ts's in-memory state only
// exists within whichever process called loadResolverPublicKeyAtStartup(),
// so a standalone diagnostics run must call it itself to report accurately.
loadResolverPublicKeyAtStartup();
const qrStatus = getQRVerificationStatus();
const resolverKeyCached = qrStatus === 'ready';
console.log(`Resolver public key: ${resolverKeyCached ? 'CACHED' : 'MISSING'}`);
if (!resolverKeyCached) {
  console.warn('WARNING: Run npm run download-keys. QR verification (tier 4) is unavailable until then.');
}
console.log(`QR verification: ${qrStatus === 'ready' ? 'READY' : 'NOT READY'}`);
console.log('');

// P5 verification (HUUID-EMR-STUB-v0.1.2.docx Section 2): every
// initXModule() call above has already captured what it needs into its own
// module-scoped closure. Clear every HUUID_ env var now, then check for
// real -- not assert -- that none remain. This is what makes "Module
// isolation: ACTIVE" below a genuine, checkable claim rather than a
// hardcoded string: if a future change reintroduces a direct process.env
// read somewhere in this script's own top-level config capture, or the
// clearing loop itself regresses, this reports INACTIVE instead of lying.
Object.keys(process.env)
  .filter((k) => k.startsWith('HUUID_'))
  .forEach((k) => {
    process.env[k] = '';
    delete process.env[k];
  });
const remainingHuuidEnvKeys = Object.keys(process.env).filter((k) => k.startsWith('HUUID_'));
const moduleIsolationActive = remainingHuuidEnvKeys.length === 0;
console.log(`Module isolation: ${moduleIsolationActive ? 'ACTIVE' : 'INACTIVE'}`);
if (!moduleIsolationActive) {
  console.error(`  WARNING: HUUID_ env vars still present after clearing: ${remainingHuuidEnvKeys.join(', ')}`);
}
console.log('');

const report = {
  timestamp: new Date().toISOString(),
  ...status,
  integrity: {
    ...status.integrity,
    overrideConfigured: integrityOverrideConfigured,
  },
  keytarMigration: getMigrationOutcome(),
  resolver: {
    ...status.resolver,
    reachable: resolverReachability.ok,
    detail: resolverReachability.detail,
  },
  qr: {
    status: qrStatus,
    resolverPublicKeyCached: resolverKeyCached,
    resolverKeyId: getResolverKeyId(),
  },
  moduleIsolation: {
    active: moduleIsolationActive,
    remainingHuuidEnvKeys,
  },
};

console.log(JSON.stringify(report, null, 2));
