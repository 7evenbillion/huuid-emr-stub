import { getSystemStatus } from '../src/status.js';
import { pingResolver } from '../src/resolver-client.js';

const status = getSystemStatus();
const resolverReachability = await pingResolver();

const report = {
  timestamp: new Date().toISOString(),
  ...status,
  resolver: {
    ...status.resolver,
    reachable: resolverReachability.ok,
    detail: resolverReachability.detail,
  },
  hardeningNotStarted: [
    'SQLCipher cache encryption (P1)',
    'OS keystore for facility private key (P2)',
    'Integrity baseline / HMAC monitoring (P4)',
    'QR card offline verification (resolution tier 4)',
  ],
};

console.log(JSON.stringify(report, null, 2));
