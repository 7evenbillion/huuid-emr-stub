import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, hkdfSync } from 'node:crypto';
import { loadConfig } from './config.js';

const SALT_SUFFIX = ':cache-encryption-v1';
const INFO = 'huuid-cache-key';
const KEY_LENGTH_BYTES = 32;

/**
 * Extracts the raw 32-byte Ed25519 private key scalar from a PKCS8 PEM file.
 * Node has no direct "give me the raw bytes" API for KeyObjects, but
 * exporting an OKP key as JWK yields `d` (base64url), which *is* the raw
 * private key -- no ASN.1 parsing needed.
 */
function readRawFacilityPrivateKey(path: string): Buffer {
  if (!existsSync(path)) {
    throw new Error(
      `Facility private key not found at ${path}. The cache cannot be encrypted without it. ` +
        `Run npm run download-keys for instructions, or place a PKCS8 PEM Ed25519 key there manually.`
    );
  }
  const pem = readFileSync(path, 'utf8');
  let jwk: { kty?: string; crv?: string; d?: string };
  try {
    const keyObject = createPrivateKey(pem);
    jwk = keyObject.export({ format: 'jwk' }) as { kty?: string; crv?: string; d?: string };
  } catch (err) {
    throw new Error(
      `Facility private key at ${path} could not be parsed as a PKCS8 PEM key: ${
        err instanceof Error ? err.message : 'unknown error'
      }`
    );
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d) {
    throw new Error(`Facility private key at ${path} is not an Ed25519 key.`);
  }
  return Buffer.from(jwk.d, 'base64url');
}

/**
 * Derives the 32-byte SQLCipher cache key from the facility private key via
 * HKDF-SHA256, per HUUID-EMR-STUB-v0.1.2.docx Section 2 P1 + this build
 * step's Step 2. Returns a hex string for SQLCipher's raw-key pragma syntax
 * (`key = "x'<hex>'"`) -- raw-key mode bypasses SQLCipher's own passphrase
 * KDF entirely, since HKDF has already produced high-entropy key material
 * (see cache.ts for why kdf_iter is consequently a no-op here).
 */
export function deriveCacheKeyHex(): string {
  const config = loadConfig();
  const rawPrivateKey = readRawFacilityPrivateKey(config.HUUID_FACILITY_PRIVATE_KEY_PATH);
  const salt = Buffer.from(config.HUUID_FACILITY_DID + SALT_SUFFIX, 'utf8');
  const info = Buffer.from(INFO, 'utf8');

  const derived = hkdfSync('sha256', rawPrivateKey, salt, info, KEY_LENGTH_BYTES);
  return Buffer.from(derived).toString('hex');
}
