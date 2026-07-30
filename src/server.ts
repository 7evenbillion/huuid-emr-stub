import express, { type Request, type Response } from 'express';
import { z } from 'zod';
import { loadConfig } from './config.js';
import { initFacilityKeyModule, deriveCacheEncryptionKeyHex } from './facility-key.js';
import { initLocalAuthModule, localAuthMiddleware } from './local-auth.js';
import { initResolverClientModule } from './resolver-client.js';
import { initIntegrityCheckModule, runIntegrityCheck, enforceStartupIntegrity } from './integrity-check.js';
import { initResolverKeyModule } from './resolver-key.js';
import { initStatusModule, getSystemStatus } from './status.js';
import { verifyPatient, recordQRVerification, type PurposeCode } from './verify-patient.js';
import { initCacheModule, listCacheEntries, cacheStats, isDbFileEncrypted, initializeCache } from './cache.js';
import { verifyQRToken } from './qr-verifier.js';
import {
  loadResolverPublicKeyAtStartup,
  getResolverPublicKeyBytes,
  getResolverKeyId,
  getQRVerificationStatus,
} from './resolver-key.js';
import { recordQRVerificationAttempt, getRecentQRVerifications } from './qr-verification-log.js';

const config = loadConfig();

// P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): server.ts is the ORCHESTRATOR --
// the only place in the running server process that ever reads
// process.env/loadConfig() for HUUID_ secrets. Every module below gets only
// the narrow slice it needs, via its own initXModule() call, never the full
// config object and never a live loadConfig() call of its own.
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

// Cache encryption key is derived once, here, by facility-key.ts (the only
// module that ever touches raw private-key bytes) -- cache.ts receives only
// the resulting hex string, never facilityDID or any key-derivation
// capability. Same "one clear message and a clean exit" behavior as before
// (Step 4/6 of the SQLCipher build step, DoD item 6 that step) -- the point
// where a missing facility private key surfaces just moved one call earlier.
let cacheEncryptionKeyHex: string;
try {
  cacheEncryptionKeyHex = await deriveCacheEncryptionKeyHex();
} catch (err) {
  console.error(`Cache initialization failed: ${err instanceof Error ? err.message : 'unknown error'}`);
  process.exit(1);
}
initCacheModule({ dbPath: config.HUUID_CACHE_DB_PATH, cacheEncryptionKeyHex });

// Open (and encrypt, if not already) the cache DB before accepting any
// requests (Step 4/6 of the SQLCipher step, DoD item 6 this step).
try {
  await initializeCache();
} catch (err) {
  console.error(`Cache initialization failed: ${err instanceof Error ? err.message : 'unknown error'}`);
  process.exit(1);
}

// Integrity check at startup -- Gap 1 closure: a violation now leads to a
// 60-second grace period and process.exit(1) unless HUUID_INTEGRITY_OVERRIDE
// is set (see integrity-check.ts's doc comment on enforceStartupIntegrity).
// This call can end the process; nothing after it should assume it always
// returns. The 6-hour periodic recheck below intentionally uses the softer
// runIntegrityCheck() directly, not this wrapper -- see that function's doc
// comment for why forcibly killing an already-running server on a later
// recheck is a different (and not requested) risk than gating startup.
await enforceStartupIntegrity();
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
setInterval(() => {
  void runIntegrityCheck();
}, SIX_HOURS_MS);

// QR verification (tier 4 offline fallback), Step 6. Best-effort and
// non-fatal by design -- this is a fallback tier, not a core requirement
// (HUUID-EMR-STUB-v0.1.2.docx Section 3.1). A missing or unreadable key
// leaves qr_verification as 'no_key'/'error' (surfaced on /health and
// diagnostics) but does not stop the Stub from serving tiers 1-3.
loadResolverPublicKeyAtStartup();

// P5, final step: every initXModule() call above has already captured the
// value it needs into its own module-scoped closure. Nothing downstream of
// this point reads process.env for an HUUID_ variable again -- config.ts's
// loadConfig() is memoized (see config.ts's `cached` variable) and is never
// called a second time in this process, so clearing these now cannot break
// anything that runs later.
Object.keys(process.env)
  .filter((k) => k.startsWith('HUUID_'))
  .forEach((k) => {
    process.env[k] = '';
    delete process.env[k];
  });

const app = express();
app.use(express.json());

const verifyBodySchema = z.object({
  localPatientId: z.string().min(1),
  purposeCode: z.enum(['Treatment', 'Administrative', 'Emergency']),
});

const qrVerifyBodySchema = z.object({
  payload: z.string().min(1),
});

// GET /health -- system status. Deliberately unauthenticated, matching the
// resolver's own /api/health: monitoring shouldn't require a credential.
app.get('/health', async (_req: Request, res: Response) => {
  const status = await getSystemStatus();
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    ...status,
    // Flat fields per the SQLCipher step's Step 6, the keystore step's Step
    // 6, and this step's Step 6, alongside the nested objects above (which
    // already carry the same info).
    cache_encrypted: status.cache.encrypted,
    cache_entries: status.cache.totalEntries,
    key_storage: status.keys.storage,
    integrity_baseline: status.integrity.baselineExists,
    integrity_status: status.integrity.lastCheckStatus,
    integrity_override_active: status.integrity.overrideActive,
    qr_verification: getQRVerificationStatus(),
    resolver_public_key_cached: getResolverPublicKeyBytes() !== null,
    // Gap 1 closure: printed on every /health response while override is
    // active, not just logged once at startup -- so anyone polling health
    // (a dashboard, a human curling it) sees the facility is running in a
    // degraded-trust state, not just whoever was watching the console when
    // it started.
    ...(status.integrity.overrideActive
      ? { warning: 'WARNING: Running with integrity override active' }
      : {}),
  });
});

// POST /verify -- the actual EMR-integration API surface. Requires
// X-Local-Auth ("every request to the Stub API must include X-Local-Auth").
app.post('/verify', localAuthMiddleware, async (req: Request, res: Response) => {
  const parsed = verifyBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ success: false, error: 'invalid_request', message: parsed.error.message });
    return;
  }
  const { localPatientId, purposeCode } = parsed.data;
  const authHeader = req.header('X-Local-Auth') ?? '';
  const result = await verifyPatient(localPatientId, purposeCode as PurposeCode, {
    headers: { 'X-Local-Auth': authHeader },
  });
  res.status(200).json(result);
});

// POST /qr/verify -- resolution tier 4 (offline QR card fallback), Step 4.
// Requires X-Local-Auth like /verify. Fully offline: no resolver call, no
// dependency on connectivity -- this is the whole point of the tier.
app.post('/qr/verify', localAuthMiddleware, async (req: Request, res: Response) => {
  const parsed = qrVerifyBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ success: false, error: 'invalid_request', message: parsed.error.message });
    return;
  }

  const keyBytes = getResolverPublicKeyBytes();
  if (!keyBytes) {
    res.status(503).json({
      valid: false,
      expired: false,
      warning: null,
      huuid: null,
      bloodType: null,
      criticalAllergies: [],
      doNotGive: [],
      expiresAt: null,
      generatedAt: null,
      source: 'qr_card',
      error: 'QR verification unavailable: no resolver public key cached. Run npm run download-keys.',
    });
    return;
  }

  const result = verifyQRToken(parsed.data.payload, keyBytes);
  recordQRVerificationAttempt(result);

  if (!result.valid) {
    // Do not return any health data on an invalid signature (Step 4).
    res.status(400).json({
      valid: false,
      expired: false,
      warning: null,
      huuid: null,
      bloodType: null,
      criticalAllergies: [],
      doNotGive: [],
      expiresAt: null,
      generatedAt: null,
      source: 'qr_card',
      error: result.error,
    });
    return;
  }

  // Cache key: the QR token's own huuid, not a separate EMR-local-patient-ID
  // -- the request body per spec carries only the token payload, no
  // localPatientId. This matches verify-patient.ts's already-documented gap
  // (localPatientId is currently just the did:huuid passed straight through,
  // there being no separate local-MRN-to-HUUID linkage mechanism yet) rather
  // than introducing a new, different simplification for this one path.
  await recordQRVerification(result.huuid as string, {
    huuid: result.huuid as string,
    bloodType: result.bloodType,
    criticalAllergies: result.criticalAllergies,
    expiresAtSeconds: result.expiresAt ? Math.floor(result.expiresAt.getTime() / 1000) : Math.floor(Date.now() / 1000),
  });

  // doNotGive/allergies/medications/etc. were added to verifyQRToken's
  // return shape when qr-verifier.ts was fixed to match the real resolver
  // signer, but this response was never updated to actually surface them --
  // an extra gap found while touching this block for the warning-text
  // change, fixed here rather than left silently incomplete. The SQLite
  // cache schema (cache.ts's QRCacheEntry) still only stores
  // bloodType/criticalAllergies; extending that is a real follow-up, not
  // done here.
  res.status(200).json({
    valid: true,
    expired: result.expired,
    warning: result.warning,
    huuid: result.huuid,
    bloodType: result.bloodType,
    criticalAllergies: result.criticalAllergies,
    allergies: result.allergies,
    medications: result.medications,
    chronicConditions: result.chronicConditions,
    organDonor: result.organDonor,
    implantedDevices: result.implantedDevices,
    pregnancyStatus: result.pregnancyStatus,
    primaryFacilityName: result.primaryFacilityName,
    doNotGive: result.doNotGive,
    generatedAt: result.generatedAt ? result.generatedAt.toISOString() : null,
    expiresAt: result.expiresAt ? result.expiresAt.toISOString() : null,
    source: 'qr_card',
  });
});

// GET /debug/resolver -- local developer page, not part of the EMR API
// surface. Left unauthenticated on purpose (mirrors the main resolver's own
// /debug/resolver page, which a human opens directly in a browser and can't
// easily attach a custom header to).
app.get('/debug/resolver', async (_req: Request, res: Response) => {
  const entries = await listCacheEntries(100);
  const stats = await cacheStats();
  const encryption = isDbFileEncrypted(stats.dbPath);
  const rows = entries
    .map(
      (e) => `<tr>
        <td>${escapeHtml(e.localPatientId)}</td>
        <td>${escapeHtml(e.huuid)}</td>
        <td>${e.bloodType ? escapeHtml(e.bloodType) : '-'}</td>
        <td>${escapeHtml(e.criticalAllergies.join(', ') || '-')}</td>
        <td>${e.source}</td>
        <td>${new Date(e.verifiedAt * 1000).toISOString()}</td>
      </tr>`
    )
    .join('\n');

  // Month 4, Step 8: resolver public key status + last 5 QR verifications.
  const qrStatus = getQRVerificationStatus();
  const resolverKeyId = getResolverKeyId();
  const qrLogRows = getRecentQRVerifications()
    .map(
      (v) => `<tr>
        <td>${escapeHtml(v.timestamp)}</td>
        <td>${v.valid ? 'valid' : 'INVALID'}</td>
        <td>${v.expired ? 'yes' : 'no'}</td>
        <td>${v.huuid ? escapeHtml(v.huuid) : '-'}</td>
        <td>${v.error ? escapeHtml(v.error) : '-'}</td>
      </tr>`
    )
    .join('\n');

  res.status(200).type('html').send(`<!doctype html>
<html><head><title>HUUID Stub -- Debug: Resolver Cache</title>
<style>body{font-family:monospace;margin:2rem}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:0.85rem}</style>
</head><body>
<h1>HUUID EMR Stub -- Local Cache</h1>
<p>Total entries: ${stats.totalEntries} | DB: ${escapeHtml(stats.dbPath)}</p>
<p>Encryption: ${encryption.fileExists ? (encryption.encrypted ? 'ENCRYPTED (SQLCipher, AES-256-CBC + HMAC-SHA512)' : 'NOT ENCRYPTED') : 'no DB file yet'}</p>
<table>
<tr><th>Local Patient ID</th><th>HUUID</th><th>Blood Type</th><th>Allergies</th><th>Source</th><th>Verified At</th></tr>
${rows || '<tr><td colspan="6">No cache entries yet -- call POST /verify first.</td></tr>'}
</table>

<h1>QR Verification (Tier 4)</h1>
<p>Status: ${qrStatus.toUpperCase()}${resolverKeyId ? ` | Key ID: ${escapeHtml(resolverKeyId)}` : ''}</p>
<p>Test scans at <a href="/debug/qr">/debug/qr</a>.</p>
<table>
<tr><th>Timestamp</th><th>Result</th><th>Expired</th><th>HUUID</th><th>Error</th></tr>
${qrLogRows || '<tr><td colspan="5">No QR verifications yet.</td></tr>'}
</table>
</body></html>`);
});

// GET/POST /debug/qr -- local developer test page for tier 4, Step 8.
// Unauthenticated on purpose, same reasoning as /debug/resolver: a human
// opens this directly in a browser and can't attach X-Local-Auth to a form
// submit. Calls verifyQRToken() directly (read-only -- never
// recordQRVerification(), since there is no real localPatientId context on
// this page, only a pasted test payload) so it can be used without the
// header POST /qr/verify requires. Shares the same in-memory verification
// log as the real endpoint, so a manual test here shows up in
// /debug/resolver's "last 5" table too.
app.get('/debug/qr', (_req: Request, res: Response) => {
  res.status(200).type('html').send(renderDebugQrPage());
});

app.post('/debug/qr', express.urlencoded({ extended: false }), (req: Request, res: Response) => {
  const payload = typeof req.body?.payload === 'string' ? req.body.payload.trim() : '';
  if (!payload) {
    res.status(200).type('html').send(renderDebugQrPage({ error: 'Paste a QR token payload first.' }));
    return;
  }

  const keyBytes = getResolverPublicKeyBytes();
  if (!keyBytes) {
    res.status(200).type('html').send(
      renderDebugQrPage({ error: 'No resolver public key cached. Run npm run download-keys.', payload })
    );
    return;
  }

  const result = verifyQRToken(payload, keyBytes);
  recordQRVerificationAttempt(result);
  res.status(200).type('html').send(renderDebugQrPage({ result, payload }));
});

function renderDebugQrPage(opts?: {
  result?: ReturnType<typeof verifyQRToken>;
  payload?: string;
  error?: string;
}): string {
  const { result, payload = '', error } = opts ?? {};
  const resultHtml = result
    ? `<h2>${result.valid ? 'VALID' : 'INVALID'}${result.expired ? ' (EXPIRED)' : ''}</h2>
       <pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`
    : '';
  const errorHtml = error ? `<p style="color:#b00">${escapeHtml(error)}</p>` : '';

  return `<!doctype html>
<html><head><title>HUUID Stub -- Debug: QR Scan</title>
<style>body{font-family:monospace;margin:2rem}textarea{width:100%;height:6rem}pre{background:#f4f4f4;padding:1rem;overflow-x:auto}</style>
</head><body>
<h1>QR Scan Test (Tier 4, offline)</h1>
<p>Paste a base64url-encoded QR token payload to verify it locally, with no
network call to the resolver. This is a developer test page, not the real
EMR-facing endpoint -- the real endpoint is <code>POST /qr/verify</code>
(requires <code>X-Local-Auth</code>).</p>
<form method="POST" action="/debug/qr">
<textarea name="payload" placeholder="base64url payload">${escapeHtml(payload)}</textarea><br>
<button type="submit">Verify</button>
</form>
${errorHtml}
${resultHtml}
</body></html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

app.listen(config.STUB_PORT, config.STUB_HOST, () => {
  console.log(
    JSON.stringify({
      level: 'info',
      event: 'stub_started',
      host: config.STUB_HOST,
      port: config.STUB_PORT,
      facilityDid: config.HUUID_FACILITY_DID,
      resolverBaseUrl: config.HUUID_RESOLVER_BASE_URL,
      timestamp: new Date().toISOString(),
    })
  );
});
