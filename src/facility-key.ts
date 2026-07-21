import { Entry } from '@napi-rs/keyring';
import { readFileSync, existsSync } from 'node:fs';
import {
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { SignJWT } from 'jose';
import { attemptKeytarMigration } from './keystore-migration.js';

export const KEYRING_SERVICE = 'huuid-emr-stub';
export const KEYRING_ACCOUNT = 'facility-private-key';

function keyringEntry(): Entry {
  return new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);
}

export type KeyStorageStatus = 'keystore' | 'file' | 'missing';

/**
 * P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): this module is the ONLY place
 * in the Stub that ever holds raw facility private-key bytes. Every other
 * module -- cache.ts, resolver-client.ts, integrity-check.ts,
 * integrity-manifest.ts -- gets a DERIVED OUTPUT (a signed JWT string, a
 * signature, a symmetric key derived via HKDF) and never the private key
 * itself. This module never calls loadConfig() -- the orchestrator
 * (server.ts, or a script acting as its own orchestrator) calls
 * initFacilityKeyModule() below with just facilityDID and
 * facilityPrivateKeyPath.
 */
export interface FacilityKeyModuleConfig {
  facilityDID: string;
  facilityPrivateKeyPath: string;
}

let moduleConfig: FacilityKeyModuleConfig | null = null;

/** Called once by an orchestrator (server.ts, or a script acting as its own orchestrator) before any other export in this module is used. */
export function initFacilityKeyModule(cfg: FacilityKeyModuleConfig): void {
  moduleConfig = cfg;
}

function requireInit(): FacilityKeyModuleConfig {
  if (!moduleConfig) {
    throw new Error('facility-key module not initialized. Call initFacilityKeyModule() first.');
  }
  return moduleConfig;
}

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
 *
 * Kept exported -- unlike getFacilityPrivateKeyRaw below, this is a pure,
 * stateless conversion function with no dependency on this module's init or
 * on where the key currently lives. scripts/secure-keys.ts (a standalone
 * entry point that migrates a fresh .pem file into the OS keystore) uses it
 * directly on a file it just read itself; that script is its own
 * orchestrator, not one of the six least-privilege modules P5 scopes.
 */
export function rawKeyFromPem(pem: string): Buffer {
  const keyObject = createPrivateKey(pem);
  const jwk = keyObject.export({ format: 'jwk' }) as { kty?: string; crv?: string; d?: string };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d) {
    throw new Error('Key is not an Ed25519 key.');
  }
  return Buffer.from(jwk.d, 'base64url');
}

/** Reconstructs a usable signing KeyObject from just the raw 32-byte seed. Not exported -- callers outside this module never get a KeyObject built from raw bytes, only signed/derived output. */
function buildEd25519KeyObjectFromRaw(rawBytes: Buffer): KeyObject {
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

  const cfg = requireInit();
  if (existsSync(cfg.facilityPrivateKeyPath)) {
    const pem = readFileSync(cfg.facilityPrivateKeyPath, 'utf8');
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
 *
 * Not exported (P5): the raw bytes this returns never leave this module.
 * Every other module gets a signature, a JWT string, or a derived symmetric
 * key -- see signFacilityJWT / signManifestHash / verifyManifestSignature /
 * deriveKeyMaterial below, all of which call this internally and zero the
 * bytes in a `finally` block before returning.
 */
async function getFacilityPrivateKeyRaw(): Promise<{ bytes: Buffer; source: 'keystore' | 'file' }> {
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

/**
 * Generic HKDF-SHA256 derivation of a symmetric key from the facility
 * private key, salted with this facility's own DID (domain-separated by
 * `saltSuffix` + `info` so unrelated derived keys can never collide) --
 * shared primitive behind deriveCacheEncryptionKeyHex() and
 * deriveManifestHmacKey() below. Raw private-key bytes are fetched fresh
 * for every derivation and zeroed immediately after (Step 7's "zero after
 * use," applied here exactly as it already was in signFacilityJWT).
 */
async function deriveKeyMaterial(saltSuffix: string, info: string, lengthBytes: number): Promise<Buffer> {
  const cfg = requireInit();
  const { bytes: rawPrivateKey } = await getFacilityPrivateKeyRaw();
  try {
    const salt = Buffer.from(cfg.facilityDID + saltSuffix, 'utf8');
    const infoBuf = Buffer.from(info, 'utf8');
    return Buffer.from(hkdfSync('sha256', rawPrivateKey, salt, infoBuf, lengthBytes));
  } finally {
    rawPrivateKey.fill(0);
  }
}

const CACHE_KEY_SALT_SUFFIX = ':cache-encryption-v1';
const CACHE_KEY_INFO = 'huuid-cache-key';
const CACHE_KEY_LENGTH_BYTES = 32;

/**
 * Derives the 32-byte SQLCipher cache key, per HUUID-EMR-STUB-v0.1.2.docx
 * Section 2 P1. Returns a hex string for SQLCipher's raw-key pragma syntax
 * (`key = "x'<hex>'"`). Formerly lived in cache-key.ts and was called lazily
 * by cache.ts itself; moved here under P5 so cache.ts (which must NOT
 * receive facilityDID or touch key material at all) never calls it --
 * the orchestrator calls this ONCE at startup and passes the resulting
 * value into cache.ts's own init as a plain string, same as dbPath.
 */
export async function deriveCacheEncryptionKeyHex(): Promise<string> {
  const derived = await deriveKeyMaterial(CACHE_KEY_SALT_SUFFIX, CACHE_KEY_INFO, CACHE_KEY_LENGTH_BYTES);
  const hex = derived.toString('hex');
  derived.fill(0);
  return hex;
}

const MANIFEST_HMAC_SALT_SUFFIX = ':integrity-baseline-v1';
const MANIFEST_HMAC_INFO = 'huuid-integrity-key';

/**
 * Domain-separated from the cache encryption key (different salt suffix,
 * different info string) via the same HKDF-over-facility-private-key
 * pattern -- one root secret, two independent derived keys for two
 * unrelated purposes. Unlike the cache key, this is called fresh on every
 * integrity check (computeManifest() in integrity-manifest.ts), not
 * precomputed once -- a manifest is hashed over content that can change
 * between checks, so there is nothing to precompute at startup the way
 * there is for the cache key (see docs/TECHNICAL-DECISIONS.md's P5 entry).
 */
export async function deriveManifestHmacKey(): Promise<Buffer> {
  return deriveKeyMaterial(MANIFEST_HMAC_SALT_SUFFIX, MANIFEST_HMAC_INFO, 32);
}

/** EdDSA-signs the manifest hash with the facility private key (Step 1.3 of the integrity-hashing build step). */
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

export interface FacilityJWTRequest {
  claims: Record<string, unknown>;
  issuer: string;
  subject: string;
  audience: string;
  expiresInSeconds: number;
  jti: string;
}

/**
 * Signs an EdDSA facility JWT and returns only the signed string -- P5's
 * "returns signed JWT strings only, never exposes raw key bytes to other
 * modules." resolver-client.ts (the caller) supplies WHAT to put in the
 * token (claims, issuer/subject/audience, expiry, jti); this function is
 * the only place that ever touches the private key to actually sign it.
 *
 * No caching of the signing key here (deliberately -- see Step 7 of the
 * keystore build step). Raw key bytes are fetched fresh for every signing
 * call and zeroed immediately after the KeyObject is built.
 */
export async function signFacilityJWT(req: FacilityJWTRequest): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const { bytes: rawKey } = await getFacilityPrivateKeyRaw();
  let signingKey: KeyObject;
  try {
    signingKey = buildEd25519KeyObjectFromRaw(rawKey);
  } finally {
    rawKey.fill(0);
  }

  return new SignJWT(req.claims)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + req.expiresInSeconds)
    .setIssuer(req.issuer)
    .setSubject(req.subject)
    .setAudience(req.audience)
    .setJti(req.jti)
    .sign(signingKey);
}
