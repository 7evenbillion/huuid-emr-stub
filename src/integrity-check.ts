import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { computeManifest, verifyManifestSignature, signManifestHash } from './integrity-manifest.js';
import { loadConfig } from './config.js';

const BASELINE_PATH = join(process.cwd(), 'integrity', 'baseline.hmac');
const STUB_VERSION = '0.1.2';

export type IntegrityStatus = 'pass' | 'fail' | 'not_checked';

interface Baseline {
  manifestHash: string;
  signature: string;
  createdAt: string;
  fileCount: number;
}

let lastCheckStatus: IntegrityStatus = 'not_checked';
let integrityViolation = false;

export function getLastCheckStatus(): IntegrityStatus {
  return lastCheckStatus;
}

export function hasIntegrityViolation(): boolean {
  return integrityViolation;
}

export function hasBaseline(): boolean {
  return existsSync(BASELINE_PATH);
}

/**
 * Signs the CURRENT (violating) manifest hash fresh, rather than reusing
 * baseline.signature -- the baseline's signature is over the ORIGINAL
 * expected hash, a different value, so it would not cryptographically
 * correspond to the manifestHash actually being reported in the alert. A
 * fresh signature over the current hash is what a future server-side
 * verifier (not built this step -- see huuid-resolver's stub receiver)
 * would need: proof that the reporting facility's own key produced a
 * signature over exactly the hash value in this alert.
 */
async function sendViolationAlert(currentManifestHash: string): Promise<void> {
  const config = loadConfig();
  const timestamp = new Date().toISOString();
  const url = `${config.HUUID_RESOLVER_BASE_URL}/1.0/stub-integrity`;

  let signature: string;
  try {
    signature = await signManifestHash(currentManifestHash);
  } catch (err) {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'integrity_violation_alert_signing_failed',
        detail: err instanceof Error ? err.message : 'unknown',
        timestamp,
      })
    );
    return;
  }

  const body = {
    facilityDID: config.HUUID_FACILITY_DID,
    manifestHash: currentManifestHash,
    stubVersion: STUB_VERSION,
    timestamp,
    signature,
    violation: true,
  };

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), config.HUUID_RESOLVER_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    console.log(
      JSON.stringify({
        level: 'info',
        event: 'integrity_violation_alert_sent',
        httpStatus: res.status,
        timestamp,
      })
    );
  } catch (err) {
    // Resolver unreachable, timed out, or errored -- log locally. No
    // special retry queue: the manifest mismatch persists until the
    // underlying file change is investigated and resolved, so the same
    // violation is naturally re-detected (and a fresh alert attempted) on
    // the next startup or scheduled check (Step 5b: "retry on next startup").
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'integrity_violation_alert_failed',
        detail: err instanceof Error ? err.message : 'unknown',
        timestamp,
      })
    );
  } finally {
    clearTimeout(timeoutHandle);
  }
}

/**
 * Runs the check once (startup, and every 6h thereafter -- see server.ts).
 *
 * DEFERRED BY DESIGN: the doc says a mismatch should make the Stub refuse
 * to start. This deliberately does not do that yet -- refusing to start on
 * any manifest mismatch risks bricking a clinic machine if the baseline
 * itself becomes stale or corrupted (e.g. a legitimate dependency update
 * that wasn't followed by re-running install-integrity-baseline). The
 * alert to the Root Authority is the load-bearing piece for now; the
 * facility keeps running with `integrityViolation: true` set rather than
 * going offline. This is an intentional, documented gap, not an oversight.
 */
export async function runIntegrityCheck(): Promise<IntegrityStatus> {
  if (!existsSync(BASELINE_PATH)) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'integrity_baseline_missing',
        message: 'No integrity baseline found -- run npm run install-integrity-baseline. Startup continuing.',
        timestamp: new Date().toISOString(),
      })
    );
    lastCheckStatus = 'not_checked';
    return lastCheckStatus;
  }

  let baseline: Baseline;
  try {
    baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as Baseline;
  } catch (err) {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'integrity_baseline_unreadable',
        detail: err instanceof Error ? err.message : 'unknown',
        timestamp: new Date().toISOString(),
      })
    );
    lastCheckStatus = 'not_checked';
    return lastCheckStatus;
  }

  const manifest = await computeManifest();
  const hashMatches = manifest.manifestHash === baseline.manifestHash;
  const signatureValid = hashMatches && (await verifyManifestSignature(baseline.manifestHash, baseline.signature));

  if (hashMatches && signatureValid) {
    lastCheckStatus = 'pass';
    integrityViolation = false;
    console.log('Integrity check: PASS');
    return lastCheckStatus;
  }

  lastCheckStatus = 'fail';
  integrityViolation = true;
  const timestamp = new Date().toISOString();
  console.error(`INTEGRITY_VIOLATION at ${timestamp}`);
  console.error(
    JSON.stringify({
      level: 'error',
      event: 'integrity_violation',
      hashMatches,
      signatureValid,
      timestamp,
    })
  );

  await sendViolationAlert(manifest.manifestHash);

  return lastCheckStatus;
}
