import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { join } from 'node:path';
import { computeManifest, signManifestHash } from '../src/integrity-manifest.js';
import { setReadOnly, clearReadOnly } from '../src/file-permissions.js';

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
