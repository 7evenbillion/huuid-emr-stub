import { pingResolver, resolveViaLiveResolver } from '../src/resolver-client.js';
import { loadConfig } from '../src/config.js';

const config = loadConfig();
console.log(`Pinging ${config.HUUID_RESOLVER_BASE_URL} ...`);

const ping = await pingResolver();
if (!ping.ok) {
  console.error(`Connection FAILED. ${ping.detail}`);
  process.exit(1);
}
console.log(`Connection OK. ${ping.detail}`);

// The doc's install-checklist step 9 expects "Facility certificate valid" as
// part of this check. There is no dedicated cert-status endpoint on the live
// resolver, so this signs a real facility JWT and resolves a syntactically
// valid but almost-certainly-unregistered DID: a 404 notFound response still
// means the JWT/facility certificate was ACCEPTED (only the DID lookup
// missed) -- a 401/403 means the certificate itself was rejected.
console.log(`Verifying facility certificate for ${config.HUUID_FACILITY_DID} ...`);
const probe = await resolveViaLiveResolver(
  'did:huuid:gh:connection-test-probe-nonexistent',
  'Administrative'
);

if (probe.ok || probe.httpStatus === 404) {
  console.log('Facility certificate valid.');
  process.exit(0);
} else {
  console.error(
    `Facility certificate check FAILED (HTTP ${probe.httpStatus ?? 'n/a'}): ${probe.reason}`
  );
  process.exit(1);
}
