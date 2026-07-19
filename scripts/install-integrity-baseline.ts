import { existsSync, mkdirSync, writeFileSync, readFileSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { join } from 'node:path';
import { computeManifest, signManifestHash } from '../src/integrity-manifest.js';

const BASELINE_PATH = join(process.cwd(), 'integrity', 'baseline.hmac');

interface Baseline {
  manifestHash: string;
  signature: string;
  createdAt: string;
  fileCount: number;
}

/**
 * Windows: the classic read-only file ATTRIBUTE (`attrib +r`), not an NTFS
 * ACL deny. Tested `icacls /deny Everyone:W` first (as literally specified)
 * and found it blocks READS too, not just writes -- Node's readFileSync
 * failed with EPERM even though the ACL only listed a WRITE deny. That
 * would have broken integrity-check.ts, which must read this file on every
 * startup. `attrib +r` is the standard Windows equivalent of chmod 444:
 * verified here to block writes while leaving reads fully intact.
 */
function setReadOnly(path: string): void {
  if (process.platform === 'win32') {
    execFileSync('attrib', ['+r', path], { stdio: 'ignore' });
  } else {
    chmodSync(path, 0o444);
  }
}

function clearReadOnly(path: string): void {
  if (process.platform === 'win32') {
    execFileSync('attrib', ['-r', path], { stdio: 'ignore' });
  } else {
    chmodSync(path, 0o644);
  }
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
