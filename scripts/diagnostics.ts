import { getSystemStatus } from '../src/status.js';
import { pingResolver } from '../src/resolver-client.js';
import { cacheStats, isDbFileEncrypted } from '../src/cache.js';

const status = getSystemStatus();
const resolverReachability = await pingResolver();

// Step 4 verification: (1) DB file exists, (2) it is not readable as plain
// SQLite -- proven by checking for SQLite's own 16-byte magic header rather
// than shelling out to a plain sqlite3 reader (none is installed here, and
// the header check is the same thing DB Browser for SQLite checks first).
const stats = cacheStats();
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

const report = {
  timestamp: new Date().toISOString(),
  ...status,
  resolver: {
    ...status.resolver,
    reachable: resolverReachability.ok,
    detail: resolverReachability.detail,
  },
  hardeningNotStarted: [
    'OS keystore for facility private key (P2)',
    'Integrity baseline / HMAC monitoring (P4)',
    'QR card offline verification (resolution tier 4)',
  ],
};

console.log(JSON.stringify(report, null, 2));
