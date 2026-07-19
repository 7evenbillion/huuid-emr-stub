import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { computeManifest, verifyManifestSignature, signManifestHash } from './integrity-manifest.js';
import { loadConfig } from './config.js';

const BASELINE_PATH = join(process.cwd(), 'integrity', 'baseline.hmac');
const STUB_VERSION = '0.1.2';

const GRACE_PERIOD_SECONDS = 60;
const COUNTDOWN_INTERVAL_SECONDS = 10;

export type IntegrityStatus = 'pass' | 'fail' | 'not_checked';

interface Baseline {
  manifestHash: string;
  signature: string;
  createdAt: string;
  fileCount: number;
}

let lastCheckStatus: IntegrityStatus = 'not_checked';
let integrityViolation = false;
let lastManifestHash: string | null = null;
let integrityOverrideActive = false;

export function getLastCheckStatus(): IntegrityStatus {
  return lastCheckStatus;
}

export function hasIntegrityViolation(): boolean {
  return integrityViolation;
}

export function hasBaseline(): boolean {
  return existsSync(BASELINE_PATH);
}

export function isIntegrityOverrideActive(): boolean {
  return integrityOverrideActive;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Signs the CURRENT (violating) manifest hash fresh, rather than reusing
 * baseline.signature -- the baseline's signature is over the ORIGINAL
 * expected hash, a different value, so it would not cryptographically
 * correspond to the manifestHash actually being reported in the alert. A
 * fresh signature over the current hash is what the resolver's signature
 * verification (Gap 2 closure) needs: proof that the reporting facility's
 * own key produced a signature over exactly the hash value in this alert.
 */
async function sendViolationAlert(currentManifestHash: string, override: boolean): Promise<void> {
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
        override,
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
    override,
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
        event: override ? 'integrity_override_alert_sent' : 'integrity_violation_alert_sent',
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
        event: override ? 'integrity_override_alert_failed' : 'integrity_violation_alert_failed',
        detail: err instanceof Error ? err.message : 'unknown',
        timestamp,
      })
    );
  } finally {
    clearTimeout(timeoutHandle);
  }
}

/**
 * Runs the check once. Called at startup (via enforceStartupIntegrity
 * below) and every 6h thereafter while the server is running (see
 * server.ts) -- the periodic recheck intentionally keeps this function's
 * original behavior (log + alert + keep running) rather than the
 * countdown/exit logic below, which is scoped to startup only: forcibly
 * killing a server that has been running fine and serving patients for
 * hours, on a periodic recheck, would be more disruptive than the startup
 * gate this was built to add, not less.
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
  lastManifestHash = manifest.manifestHash;
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

  await sendViolationAlert(manifest.manifestHash, false);

  return lastCheckStatus;
}

/**
 * Startup-only wrapper (Gap 1 closure). On PASS (or no baseline yet), does
 * nothing extra -- the server starts normally. On FAIL:
 *
 * - HUUID_INTEGRITY_OVERRIDE=1 already set at process launch: starts
 *   immediately with a logged warning and a second alert (override: true).
 *   No countdown -- the operator already made the call before restarting.
 * - Not set: prints the required warning every 10s for 60s, then exits(1).
 *   The override env var is read once here (matching "restart within 60
 *   seconds" -- a NEW process launch with the var set, not a live process
 *   somehow observing an external env change mid-countdown).
 *
 * Never called by the 6-hour periodic recheck -- see runIntegrityCheck's
 * doc comment for why that stays soft-fail.
 */
export async function enforceStartupIntegrity(): Promise<void> {
  const status = await runIntegrityCheck();
  if (status !== 'fail') return;

  const config = loadConfig();

  if (config.HUUID_INTEGRITY_OVERRIDE) {
    integrityOverrideActive = true;
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'integrity_override_used',
        message: 'Starting despite integrity violation -- HUUID_INTEGRITY_OVERRIDE=1 is set.',
        timestamp: new Date().toISOString(),
      })
    );
    if (lastManifestHash) {
      await sendViolationAlert(lastManifestHash, true);
    }
    return;
  }

  for (let remaining = GRACE_PERIOD_SECONDS; remaining > 0; remaining -= COUNTDOWN_INTERVAL_SECONDS) {
    console.error(
      `INTEGRITY VIOLATION DETECTED. \n` +
        `Server will refuse to start in ${remaining}s.\n` +
        `To override for emergency patient care,\n` +
        `set HUUID_INTEGRITY_OVERRIDE=1 in environment\n` +
        `and restart within 60 seconds.`
    );
    await sleep(COUNTDOWN_INTERVAL_SECONDS * 1000);
  }

  console.error('Integrity violation not overridden within the grace period. Refusing to start.');
  process.exit(1);
}
