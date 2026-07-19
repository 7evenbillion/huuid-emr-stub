import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { createHmac, hkdfSync, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { loadConfig } from './config.js';
import { getFacilityPrivateKeyRaw, buildEd25519KeyObjectFromRaw } from './facility-key.js';

const HMAC_SALT_SUFFIX = ':integrity-baseline-v1';
const HMAC_INFO = 'huuid-integrity-key';

/**
 * Domain-separated from cache-key.ts's encryption key (different salt
 * suffix, different info string) via the same HKDF-over-facility-private-key
 * pattern -- one root secret, two independent derived keys for two
 * unrelated purposes.
 *
 * P4 in the doc says "HMAC-SHA256 of all Stub files," which needs a key to
 * actually be an HMAC rather than a plain hash. The manifest's real
 * tamper-evidence comes from the EdDSA signature layered on top (see
 * signManifestHash/verifyManifestSignature below) -- an attacker who
 * modifies files can recompute a new manifest hash, but cannot produce a
 * valid signature over it without the facility private key. Keying the
 * HMAC itself with facility-derived material is an additional (not
 * load-bearing) layer: it also ties the manifest fingerprint to this
 * specific facility rather than being a public, comparable-across-facilities
 * plain hash.
 */
async function deriveManifestHmacKey(): Promise<Buffer> {
  const config = loadConfig();
  const { bytes: rawPrivateKey } = await getFacilityPrivateKeyRaw();
  try {
    const salt = Buffer.from(config.HUUID_FACILITY_DID + HMAC_SALT_SUFFIX, 'utf8');
    const info = Buffer.from(HMAC_INFO, 'utf8');
    return Buffer.from(hkdfSync('sha256', rawPrivateKey, salt, info, 32));
  } finally {
    rawPrivateKey.fill(0);
  }
}

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

/** EdDSA-signs the manifest hash with the facility private key (Step 1.3). */
export async function signManifestHash(manifestHash: string): Promise<string> {
  const { bytes: rawPrivateKey } = await getFacilityPrivateKeyRaw();
  try {
    const privateKeyObj = buildEd25519KeyObjectFromRaw(rawPrivateKey);
    const signature = cryptoSign(null, Buffer.from(manifestHash, 'utf8'), privateKeyObj);
    return signature.toString('base64url');
  } finally {
    rawPrivateKey.fill(0);
  }
}

/**
 * Verifies against the facility's OWN public key, derived from the same
 * private key bytes this process already holds -- Ed25519 public keys are
 * always deterministically derivable from the private seed, so this needs
 * no external fetch (e.g. from huuid_facilities.public_key_multibase on the
 * resolver). This is a self-consistency check: it confirms the signature on
 * disk was produced by whichever key this process currently has access to,
 * which is exactly what "did this facility's own Stub sign this baseline"
 * needs to mean here.
 */
export async function verifyManifestSignature(manifestHash: string, signatureB64url: string): Promise<boolean> {
  const { bytes: rawPrivateKey } = await getFacilityPrivateKeyRaw();
  try {
    const privateKeyObj = buildEd25519KeyObjectFromRaw(rawPrivateKey);
    const publicKeyObj = createPublicKey(privateKeyObj);
    const signature = Buffer.from(signatureB64url, 'base64url');
    return cryptoVerify(null, Buffer.from(manifestHash, 'utf8'), publicKeyObj, signature);
  } finally {
    rawPrivateKey.fill(0);
  }
}
