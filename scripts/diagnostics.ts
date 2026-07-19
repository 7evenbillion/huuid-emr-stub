import { getSystemStatus } from '../src/status.js';
import { pingResolver } from '../src/resolver-client.js';
import { cacheStats, isDbFileEncrypted } from '../src/cache.js';
import { getMigrationOutcome } from '../src/keystore-migration.js';
import { runIntegrityCheck } from '../src/integrity-check.js';

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
console.log('');

const report = {
  timestamp: new Date().toISOString(),
  ...status,
  keytarMigration: getMigrationOutcome(),
  resolver: {
    ...status.resolver,
    reachable: resolverReachability.ok,
    detail: resolverReachability.detail,
  },
  hardeningNotStarted: ['QR card offline verification (resolution tier 4)'],
};

console.log(JSON.stringify(report, null, 2));
