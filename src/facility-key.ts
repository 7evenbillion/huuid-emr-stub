import keytar from 'keytar';
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, type KeyObject } from 'node:crypto';
import { loadConfig } from './config.js';

export const KEYTAR_SERVICE = 'huuid-emr-stub';
export const KEYTAR_ACCOUNT = 'facility-private-key';

export type KeyStorageStatus = 'keystore' | 'file' | 'missing';

/**
 * RFC 8410 PKCS8 DER prefix for an unencrypted Ed25519 private key
 * (OneAsymmetricKey, no public-key field, no attributes) -- fixed and
 * identical for every Ed25519 key. Appending the raw 32-byte seed
 * reconstructs a complete, valid PKCS8 key, so a signing key can be built
 * straight from raw bytes without also needing the public key (which Node's
 * JWK importer would otherwise require) or an intermediate PEM string
 * (which, being an immutable JS string, cannot be zeroed -- see Step 7 notes
 * below).
 */
const PKCS8_ED25519_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * Node's private-key export has no "give me the raw bytes" mode, but
 * exporting an OKP key as JWK yields `d` (base64url) -- which *is* the raw
 * 32-byte private key, no ASN.1 parsing needed.
 */
export function rawKeyFromPem(pem: string): Buffer {
  const keyObject = createPrivateKey(pem);
  const jwk = keyObject.export({ format: 'jwk' }) as { kty?: string; crv?: string; d?: string };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d) {
    throw new Error('Key is not an Ed25519 key.');
  }
  return Buffer.from(jwk.d, 'base64url');
}

/** Reconstructs a usable signing KeyObject from just the raw 32-byte seed. */
export function buildEd25519KeyObjectFromRaw(rawBytes: Buffer): KeyObject {
  if (rawBytes.length !== 32) {
    throw new Error(`Expected a 32-byte Ed25519 private key, got ${rawBytes.length} bytes.`);
  }
  const der = Buffer.concat([PKCS8_ED25519_DER_PREFIX, rawBytes]);
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } finally {
    der.fill(0);
  }
}

/**
 * Keystore-first, file-fallback (Step 3/4) -- lets the system keep working
 * during the transition period before `npm run secure-keys` has been run.
 * Throws with a clear message if neither source has a key.
 *
 * MEMORY NOTE (Step 7): the caller owns zeroing the returned `bytes` buffer
 * immediately after use. This function cannot also zero the base64url
 * string keytar.getPassword() returns (or the PEM string read from file) --
 * JS strings are immutable, so nothing can zero their backing memory from
 * JS code. Buffers are the only representation that can actually be wiped;
 * keeping the string-typed intermediates as short-lived and few as possible
 * is the practical mitigation here, not a claim of true secure erasure.
 */
export async function getFacilityPrivateKeyRaw(): Promise<{ bytes: Buffer; source: 'keystore' | 'file' }> {
  const fromKeystore = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
  if (fromKeystore) {
    return { bytes: Buffer.from(fromKeystore, 'base64url'), source: 'keystore' };
  }

  const config = loadConfig();
  if (existsSync(config.HUUID_FACILITY_PRIVATE_KEY_PATH)) {
    const pem = readFileSync(config.HUUID_FACILITY_PRIVATE_KEY_PATH, 'utf8');
    return { bytes: rawKeyFromPem(pem), source: 'file' };
  }

  throw new Error(
    'No facility private key found in the OS keystore or at HUUID_FACILITY_PRIVATE_KEY_PATH. ' +
      'Place a PKCS8 PEM Ed25519 key at that path (see README), then optionally run npm run secure-keys.'
  );
}

/** For diagnostics/health -- reports where the key currently lives without building a signing key. */
export async function getKeyStorageStatus(): Promise<KeyStorageStatus> {
  const fromKeystore = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
  if (fromKeystore) return 'keystore';
  const config = loadConfig();
  return existsSync(config.HUUID_FACILITY_PRIVATE_KEY_PATH) ? 'file' : 'missing';
}
