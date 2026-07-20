import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { z } from 'zod';
import { loadConfig } from '../src/config.js';
import { setReadOnly } from '../src/file-permissions.js';

// Month 4, QR verification Step 2. HUUID-EMR-STUB-v0.1.2.docx Section 4 step 5
// names ./keys/resolver-public-key.pem; this Stub saves .json instead -- see
// config.ts's HUUID_RESOLVER_PUBLIC_KEY_PATH comment and
// docs/TECHNICAL-DECISIONS.md for why (keyId/validFrom need a home, PEM has
// none). Facility-private-key.pem download still has no endpoint (see
// README) -- this script only fetches the resolver's public key.

const resolverPublicKeySchema = z.object({
  publicKeyMultibase: z.string().min(1),
  keyId: z.string().min(1),
  validFrom: z.string().min(1),
  algorithm: z.literal('Ed25519'),
});

async function main(): Promise<void> {
  const config = loadConfig();
  const url = `${config.HUUID_RESOLVER_BASE_URL}/1.0/resolver-public-key`;
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), config.HUUID_RESOLVER_TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetch(url, { method: 'GET', signal: controller.signal });
  } catch (err) {
    const aborted = err instanceof Error && err.name === 'AbortError';
    console.error(
      aborted
        ? `download-keys: request to ${url} timed out after ${config.HUUID_RESOLVER_TIMEOUT_MS}ms.`
        : `download-keys: network error contacting ${url}: ${err instanceof Error ? err.message : 'unknown error'}`
    );
    process.exit(1);
  } finally {
    clearTimeout(timeoutHandle);
  }

  if (!res.ok) {
    console.error(`download-keys: resolver returned HTTP ${res.status} from ${url}.`);
    process.exit(1);
  }

  const parsed = resolverPublicKeySchema.safeParse(await res.json());
  if (!parsed.success) {
    console.error('download-keys: resolver response did not match the expected shape:');
    console.error(parsed.error.message);
    process.exit(1);
  }

  const destPath = config.HUUID_RESOLVER_PUBLIC_KEY_PATH;
  const destDir = dirname(destPath);
  if (!existsSync(destDir)) {
    mkdirSync(destDir, { recursive: true });
  }

  writeFileSync(destPath, JSON.stringify(parsed.data, null, 2) + '\n', { mode: 0o644 });
  setReadOnly(destPath);

  console.log('Resolver public key downloaded and cached.');
  console.log(` Key ID: ${parsed.data.keyId}`);
}

void main();
