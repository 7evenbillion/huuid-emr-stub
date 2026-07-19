import express, { type Request, type Response } from 'express';
import { z } from 'zod';
import { loadConfig } from './config.js';
import { localAuthMiddleware } from './local-auth.js';
import { verifyPatient, type PurposeCode } from './verify-patient.js';
import { getSystemStatus } from './status.js';
import { listCacheEntries, cacheStats, isDbFileEncrypted, initializeCache } from './cache.js';
import { runIntegrityCheck } from './integrity-check.js';

const config = loadConfig();

// Open (and encrypt, if not already) the cache DB before accepting any
// requests, so a missing facility private key (in both the keystore and the
// file fallback) is one clear message and a clean exit -- not a crash on the
// first POST /verify (Step 4/6 of the SQLCipher step, DoD item 6 this step).
try {
  await initializeCache();
} catch (err) {
  console.error(`Cache initialization failed: ${err instanceof Error ? err.message : 'unknown error'}`);
  process.exit(1);
}

// Integrity check at startup -- deliberately does NOT block/exit on a
// violation (see integrity-check.ts's doc comment for why). Re-run every 6
// hours per Step 3 while the server is running; /health and diagnostics
// report whichever run (startup or scheduled) happened most recently rather
// than recomputing on every request, matching status.ts's "local-only, no
// expensive recomputation" design.
await runIntegrityCheck();
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
setInterval(() => {
  void runIntegrityCheck();
}, SIX_HOURS_MS);

const app = express();
app.use(express.json());

const verifyBodySchema = z.object({
  localPatientId: z.string().min(1),
  purposeCode: z.enum(['Treatment', 'Administrative', 'Emergency']),
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
</body></html>`);
});

// GET /debug/qr -- honest stub. QR verification is explicitly deferred for
// this build step ("Do not build QR verification yet").
app.get('/debug/qr', (_req: Request, res: Response) => {
  res.status(200).type('html').send(`<!doctype html>
<html><head><title>HUUID Stub -- Debug: QR Scan</title></head>
<body style="font-family:monospace;margin:2rem">
<h1>QR Scan -- Not Implemented Yet</h1>
<p>QR card verification (resolution tier 4, offline token signature check) is
scheduled for a later Month 4 build step, after integrity hashing. This page
exists so the route is present, but it does not perform a scan.</p>
</body></html>`);
});

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
