import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { createHmac } from 'node:crypto';
import { deriveManifestHmacKey } from './facility-key.js';

/**
 * P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): the HMAC key and the EdDSA
 * signing/verification of the manifest hash both moved to facility-key.ts
 * (the only module that ever touches raw private-key bytes) -- this file
 * keeps only the pure, non-secret file-walking/hashing logic. It imports
 * the derived key, never the private key itself, and no longer calls
 * loadConfig() at all.
 */

function walkFiles(dir: string, extensions: string[]): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const results: string[] = [];
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkFiles(fullPath, extensions));
    } else if (extensions.some((ext) => entry.name.endsWith(ext))) {
      results.push(fullPath);
    }
  }
  return results;
}

export interface ManifestResult {
  manifestHash: string; // hex
  fileCount: number;
  files: string[]; // relative POSIX-style paths, sorted
}

/**
 * Computes the deterministic manifest over every .ts/.js file in src/ and
 * scripts/, plus package-lock.json (Step 1.1/1.2). Sorted alphabetically by
 * relative path before hashing, and the path itself is hashed alongside the
 * content -- not just concatenated content -- so a rename or a swap between
 * two same-sized files changes the manifest, not only an edit.
 *
 * This is the ONLY place this computation happens -- both
 * install-integrity-baseline.ts and integrity-check.ts call this function,
 * so there is no way for the two to independently drift out of sync with
 * each other.
 */
export async function computeManifest(): Promise<ManifestResult> {
  const root = process.cwd();
  const candidatePaths = [
    ...walkFiles(join(root, 'src'), ['.ts', '.js']),
    ...walkFiles(join(root, 'scripts'), ['.ts', '.js']),
  ];
  const packageLockPath = join(root, 'package-lock.json');
  if (existsSync(packageLockPath)) {
    candidatePaths.push(packageLockPath);
  }

  const relativePaths = candidatePaths.map((p) => relative(root, p).split(sep).join('/')).sort();

  const key = await deriveManifestHmacKey();
  const hmac = createHmac('sha256', key);
  key.fill(0);

  for (const relPath of relativePaths) {
    const content = readFileSync(join(root, relPath));
    hmac.update(relPath, 'utf8');
    hmac.update(Buffer.from([0]));
    hmac.update(content);
    hmac.update(Buffer.from([0]));
  }

  return {
    manifestHash: hmac.digest('hex'),
    fileCount: relativePaths.length,
    files: relativePaths,
  };
}
