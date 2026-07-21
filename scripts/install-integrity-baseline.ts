import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { join } from 'node:path';
import { computeManifest } from '../src/integrity-manifest.js';
import { initFacilityKeyModule, signManifestHash } from '../src/facility-key.js';
import { setReadOnly, clearReadOnly } from '../src/file-permissions.js';
import { loadConfig } from '../src/config.js';

// This script is its own standalone entry point/process (P5, HUUID-EMR-STUB-
// v0.1.2.docx Section 2) -- same orchestrator role server.ts plays for the
// running server, just for this one-shot baseline install.
const config = loadConfig();
initFacilityKeyModule({
  facilityDID: config.HUUID_FACILITY_DID,
  facilityPrivateKeyPath: config.HUUID_FACILITY_PRIVATE_KEY_PATH,
});

const BASELINE_PATH = join(process.cwd(), 'integrity', 'baseline.hmac');

interface Baseline {
  manifestHash: string;
  signature: string;
  createdAt: string;
  fileCount: number;
}

async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(question);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

if (existsSync(BASELINE_PATH)) {
  const existing = JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as Baseline;
  console.warn(
    `An integrity baseline already exists (created ${existing.createdAt}, ${existing.fileCount} files).`
  );
  console.warn('Overwriting should only be done for a legitimate code update, not to silence a real violation.');
  const proceed = await confirm('Overwrite the existing baseline? (y/N): ');
  if (!proceed) {
    console.log('Aborted. Existing baseline left unchanged.');
    process.exit(0);
  }
  clearReadOnly(BASELINE_PATH);
}

const manifest = await computeManifest();
const signature = await signManifestHash(manifest.manifestHash);

const baseline: Baseline = {
  manifestHash: manifest.manifestHash,
  signature,
  createdAt: new Date().toISOString(),
  fileCount: manifest.fileCount,
};

mkdirSync(join(process.cwd(), 'integrity'), { recursive: true });
writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2));
setReadOnly(BASELINE_PATH);

console.log(`Integrity baseline written. ${manifest.fileCount} files included.`);
console.log('File set to read-only.');
