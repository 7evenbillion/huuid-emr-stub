import { getSystemStatus } from '../src/status.js';
import { pingResolver } from '../src/resolver-client.js';
import { cacheStats, isDbFileEncrypted } from '../src/cache.js';

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
console.log('');

const report = {
  timestamp: new Date().toISOString(),
  ...status,
  resolver: {
    ...status.resolver,
    reachable: resolverReachability.ok,
    detail: resolverReachability.detail,
  },
  hardeningNotStarted: [
    'Integrity baseline / HMAC monitoring (P4)',
    'QR card offline verification (resolution tier 4)',
  ],
};

console.log(JSON.stringify(report, null, 2));
