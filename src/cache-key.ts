import { hkdfSync } from 'node:crypto';
import { loadConfig } from './config.js';
import { getFacilityPrivateKeyRaw } from './facility-key.js';

const SALT_SUFFIX = ':cache-encryption-v1';
const INFO = 'huuid-cache-key';
const KEY_LENGTH_BYTES = 32;

/**
 * Derives the 32-byte SQLCipher cache key from the facility private key via
 * HKDF-SHA256, per HUUID-EMR-STUB-v0.1.2.docx Section 2 P1 + this build
 * step's Step 2. Returns a hex string for SQLCipher's raw-key pragma syntax
 * (`key = "x'<hex>'"`) -- raw-key mode bypasses SQLCipher's own passphrase
 * KDF entirely, since HKDF has already produced high-entropy key material
 * (see cache.ts for why kdf_iter is consequently a no-op here).
 *
 * Keystore-first, file-fallback via facility-key.ts (Step 3). The raw key
 * bytes are zeroed immediately after deriving the cache key (Step 7) -- this
 * function is only called once per process (cache.ts memoizes the open DB
 * handle), so "zero after use" and "zero after every derivation" coincide.
 */
export async function deriveCacheKeyHex(): Promise<string> {
  const config = loadConfig();
  const { bytes: rawPrivateKey } = await getFacilityPrivateKeyRaw();
  try {
    const salt = Buffer.from(config.HUUID_FACILITY_DID + SALT_SUFFIX, 'utf8');
    const info = Buffer.from(INFO, 'utf8');
    const derived = hkdfSync('sha256', rawPrivateKey, salt, info, KEY_LENGTH_BYTES);
    return Buffer.from(derived).toString('hex');
  } finally {
    rawPrivateKey.fill(0);
  }
}
