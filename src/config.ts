import 'dotenv/config';
import { z } from 'zod';

/**
 * config-template.env has no "Section 6" to copy from -- HUUID-EMR-STUB-v0.1.2.docx
 * only goes up to Section 5. HUUID_FACILITY_DID / HUUID_API_KEY / HUUID_FACILITY_CODE
 * are the only fields the doc names explicitly (Section 4, install step 3). Everything
 * else below exists because the code in this repo needs it, not because the spec named
 * it -- each is commented at its definition.
 */
const envSchema = z.object({
  // Doc-mandated (Section 4, step 3)
  HUUID_FACILITY_DID: z.string().min(1, 'HUUID_FACILITY_DID is required'),
  HUUID_API_KEY: z.string().min(1, 'HUUID_API_KEY is required'),
  HUUID_FACILITY_CODE: z.string().min(1, 'HUUID_FACILITY_CODE is required'),

  // Implementation-necessary: where the live resolver actually is. The spec's
  // canonical host is resolver.huuid.health, but the deployed Month 2/3 resolver
  // lives at huuid-resolver.vercel.app (see HANDOFF.md) -- no custom domain yet.
  HUUID_RESOLVER_BASE_URL: z.string().url().default('https://huuid-resolver.vercel.app'),
  HUUID_RESOLVER_TIMEOUT_MS: z.coerce.number().int().positive().default(3000),

  // Local Express server bind address (Step 7)
  STUB_PORT: z.coerce.number().int().positive().default(3741),
  STUB_HOST: z.string().default('localhost'),

  // Local-auth shared secret (Step 6) -- lives at a file path, not inline in .env,
  // because `generate-local-secret` writes it to disk with restrictive permissions.
  HUUID_LOCAL_AUTH_SECRET_PATH: z.string().default('./local-auth/emr-secret.key'),

  // Facility signing key used by resolver-client.ts to mint facility JWTs. In the
  // full spec this arrives via `download-keys` -- that endpoint does not exist yet
  // on the live resolver (see repo README), so for now this path is filled manually.
  HUUID_FACILITY_PRIVATE_KEY_PATH: z.string().default('./keys/facility-private-key.pem'),
  // QR verification (tier 4 offline fallback), Month 4. Path is .json, not
  // .pem -- a deliberate deviation from HUUID-EMR-STUB-v0.1.2.docx Section 4
  // step 5, which names resolver-public-key.pem. The resolver's
  // GET /1.0/resolver-public-key returns JSON (publicKeyMultibase, keyId,
  // validFrom, algorithm) -- keyId/validFrom have no natural home in a bare
  // PEM file, and the Stub needs them for /health and /debug/resolver
  // reporting, not just the raw key bytes. Documented in
  // docs/TECHNICAL-DECISIONS.md, same treatment as the AES-CBC-vs-GCM
  // spec/implementation variance.
  HUUID_RESOLVER_PUBLIC_KEY_PATH: z.string().default('./keys/resolver-public-key.json'),

  HUUID_CACHE_DB_PATH: z.string().default('./data/huuid-cache.db'),

  // Emergency override for a startup integrity-check failure (Gap 1
  // closure). '1' bypasses the 60-second grace-period exit; anything else
  // (including unset) does not.
  HUUID_INTEGRITY_OVERRIDE: z
    .enum(['0', '1'])
    .default('0')
    .transform((v) => v === '1'),
});

export type StubConfig = z.infer<typeof envSchema>;

let cached: StubConfig | null = null;

export function loadConfig(): StubConfig {
  if (cached) return cached;
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid or missing configuration:\n${issues}\n\nCopy config-template.env to .env and fill it in.`);
  }
  cached = parsed.data;
  return cached;
}
