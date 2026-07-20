import { readFileSync, existsSync } from 'node:fs';
import bs58 from 'bs58';
import { loadConfig } from './config.js';

const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

/**
 * Decodes a multibase base58btc ('z...') Ed25519 public key to its raw 32
 * bytes. Identical algorithm to huuid-resolver's lib/multibase.ts
 * (decodeEd25519PublicKeyMultibase) -- duplicated rather than shared across
 * repos (this is a standalone Node service, not a package in the same
 * workspace as huuid-resolver), but must stay byte-for-byte consistent with
 * it since this Stub decodes keys that resolver produced.
 */
function decodeEd25519PublicKeyMultibase(multibase: string): Buffer | null {
  if (!multibase.startsWith('z')) return null;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(bs58.decode(multibase.slice(1)));
  } catch {
    return null;
  }
  if (decoded.length !== 34) return null;
  if (decoded[0] !== ED25519_MULTICODEC_PREFIX[0] || decoded[1] !== ED25519_MULTICODEC_PREFIX[1]) {
    return null;
  }
  return decoded.subarray(2);
}

export type QRVerificationStatus = 'ready' | 'no_key' | 'error';

interface CachedResolverKeyFile {
  publicKeyMultibase: string;
  keyId: string;
  validFrom: string;
  algorithm: string;
}

let resolverPublicKeyBytes: Buffer | null = null;
let resolverKeyId: string | null = null;
let status: QRVerificationStatus = 'no_key';

export function getResolverPublicKeyBytes(): Buffer | null {
  return resolverPublicKeyBytes;
}

export function getResolverKeyId(): string | null {
  return resolverKeyId;
}

export function getQRVerificationStatus(): QRVerificationStatus {
  return status;
}

/**
 * Startup-only (Step 6). QR verification is a fallback tier, not a core
 * requirement (HUUID-EMR-STUB-v0.1.2.docx Section 3.1) -- a missing or
 * unreadable key file logs a warning and leaves status as 'no_key'/'error'
 * rather than exiting. The Stub must still start and serve tiers 1-3
 * normally with no resolver public key present at all.
 */
export function loadResolverPublicKeyAtStartup(): void {
  const config = loadConfig();
  const path = config.HUUID_RESOLVER_PUBLIC_KEY_PATH;

  if (!existsSync(path)) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'resolver_public_key_missing',
        message: `No resolver public key cached at ${path}. Run "npm run download-keys". QR verification (tier 4) is unavailable until then.`,
        timestamp: new Date().toISOString(),
      })
    );
    status = 'no_key';
    return;
  }

  let parsed: CachedResolverKeyFile;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'resolver_public_key_unreadable',
        message: `Could not read or parse ${path}: ${err instanceof Error ? err.message : 'unknown error'}. QR verification unavailable.`,
        timestamp: new Date().toISOString(),
      })
    );
    status = 'error';
    return;
  }

  const rawBytes = decodeEd25519PublicKeyMultibase(parsed.publicKeyMultibase ?? '');
  if (!rawBytes) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'resolver_public_key_malformed',
        message: `${path} does not contain a valid Ed25519 multibase public key. QR verification unavailable.`,
        timestamp: new Date().toISOString(),
      })
    );
    status = 'error';
    return;
  }

  resolverPublicKeyBytes = rawBytes;
  resolverKeyId = parsed.keyId ?? null;
  status = 'ready';
  console.log(
    JSON.stringify({
      level: 'info',
      event: 'resolver_public_key_loaded',
      keyId: resolverKeyId,
      timestamp: new Date().toISOString(),
    })
  );
}
