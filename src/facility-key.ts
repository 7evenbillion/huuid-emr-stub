import { Entry } from '@napi-rs/keyring';
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, type KeyObject } from 'node:crypto';
import { loadConfig } from './config.js';
import { attemptKeytarMigration } from './keystore-migration.js';

export const KEYRING_SERVICE = 'huuid-emr-stub';
export const KEYRING_ACCOUNT = 'facility-private-key';

function keyringEntry(): Entry {
  return new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);
}

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

type LocatedKey = { bytes: Buffer; source: 'keystore' | 'file' } | null;

/**
 * Keystore -> file -> (Windows only) legacy-keytar migration, in that
 * order -- the single lookup chain both getFacilityPrivateKeyRaw() and
 * getKeyStorageStatus() build on, so the two functions can never disagree
 * about where the key is. The migration attempt is deliberately the LAST
 * resort, right before giving up: it is only reached when neither the
 * current keystore nor the file has a key, so a facility that has already
 * migrated (or never used keytar) never pays for a PowerShell spawn.
 *
 * MEMORY NOTE (Step 7): the caller owns zeroing the returned `bytes` buffer
 * immediately after use. This cannot also zero the base64url string
 * Entry.getPassword() returns (or the PEM string read from file) -- JS
 * strings are immutable, so nothing can zero their backing memory from JS
 * code. Buffers are the only representation that can actually be wiped;
 * keeping the string-typed intermediates as short-lived and few as
 * possible is the practical mitigation here, not a claim of true secure
 * erasure.
 */
async function locateFacilityKey(): Promise<LocatedKey> {
  const fromKeystore = keyringEntry().getPassword();
  if (fromKeystore) {
    return { bytes: Buffer.from(fromKeystore, 'base64url'), source: 'keystore' };
  }

  const config = loadConfig();
  if (existsSync(config.HUUID_FACILITY_PRIVATE_KEY_PATH)) {
    const pem = readFileSync(config.HUUID_FACILITY_PRIVATE_KEY_PATH, 'utf8');
    return { bytes: rawKeyFromPem(pem), source: 'file' };
  }

  if (process.platform === 'win32') {
    const migrated = await attemptKeytarMigration();
    if (migrated) {
      return { bytes: migrated.bytes, source: 'keystore' };
    }
  }

  return null;
}

/**
 * Kept `async` even though @napi-rs/keyring's API is synchronous (unlike
 * keytar's) -- every caller of this function already `await`s it, and
 * keeping the same Promise-returning signature means the keytar swap and
 * this migration both stay contained to this module.
 */
export async function getFacilityPrivateKeyRaw(): Promise<{ bytes: Buffer; source: 'keystore' | 'file' }> {
  const located = await locateFacilityKey();
  if (located) return located;

  throw new Error(
    'No facility private key found in the OS keystore, at HUUID_FACILITY_PRIVATE_KEY_PATH, or (Windows) ' +
      'in a legacy keytar credential. Place a PKCS8 PEM Ed25519 key at that path (see README), then ' +
      'optionally run npm run secure-keys.'
  );
}

/** For diagnostics/health -- reports where the key currently lives without holding onto the raw bytes. */
export async function getKeyStorageStatus(): Promise<KeyStorageStatus> {
  const located = await locateFacilityKey();
  if (!located) return 'missing';
  located.bytes.fill(0); // this call only needs to know *where* the key is, not the key itself
  return located.source;
}
