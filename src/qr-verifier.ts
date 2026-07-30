import { createPublicKey, createHash, verify as cryptoVerify } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { z } from 'zod';

export interface QRAllergy {
  substance: string;
  reaction: string | null;
  severity: string | null;
}

export interface QRMedication {
  name: string;
  dose: string | null;
  frequency: string | null;
}

export interface QRContraindication {
  substance: string;
  reason: string | null;
}

export interface QRVerificationResult {
  valid: boolean;
  expired: boolean;
  huuid: string | null;
  bloodType: string | null;
  /** Backward-compatible: allergy substance names only (ca[].s). Existing
   * callers (cache.ts, server.ts, /debug/resolver) read this field; kept so
   * this format change doesn't ripple into their SQLite schema. */
  criticalAllergies: string[];
  allergies: QRAllergy[];
  medications: QRMedication[];
  chronicConditions: string[];
  organDonor: string | null;
  implantedDevices: string[];
  pregnancyStatus: string | null;
  primaryFacilityName: string | null;
  /** Contraindications with severity 'never' -- the single most
   * safety-critical field on the card. Must never be silently dropped. */
  doNotGive: QRContraindication[];
  /** When this specific token was generated (resolver's `gen` field) --
   * absent on tokens signed before that field existed. */
  generatedAt: Date | null;
  expiresAt: Date | null;
  /** Set only when valid && expired: identity still resolves (valid stays
   * true), but the medical data carried in this token may be stale. Null
   * whenever the token is not expired -- callers must not infer staleness
   * from expiresAt alone, only from this field being non-null. */
  warning: string | null;
  error: string | null;
}

const EXPIRED_WARNING = 'Token expired. Medical data may be outdated. Verify via resolver when connectivity available.';

const SUPPORTED_VERSION = 1;

// Mirrors huuid-resolver's lib/qr-token.ts payload shape exactly (Phase 2A,
// see docs/TECHNICAL-DECISIONS.md). No .default() on any optional field --
// a default would inject a key/value (e.g. cc: []) into the re-signed
// canonical JSON that was never present in what the resolver actually
// signed, breaking verification for every token that omits that field.
// .optional() alone preserves "absent stays absent".
const allergySchema = z.object({
  s: z.string().min(1),
  r: z.string().optional(),
  sv: z.string().optional(),
});

const medicationSchema = z.object({
  n: z.string().min(1),
  d: z.string().optional(),
  f: z.string().optional(),
});

const contraindicationSchema = z.object({
  s: z.string().min(1),
  r: z.string().optional(),
});

const qrTokenSchema = z.object({
  v: z.number(),
  huuid: z.string().min(1),
  bt: z.string().optional(),
  ca: z.array(allergySchema).optional(),
  cm: z.array(medicationSchema).optional(),
  cc: z.array(z.string()).optional(),
  od: z.string().optional(),
  id: z.array(z.string()).optional(),
  preg: z.string().optional(),
  pf: z.string().optional(),
  nd: z.array(contraindicationSchema).optional(),
  /** Added alongside the medical-profile-update notification feature.
   * Optional (not `.default()`, per this file's own established rule) so a
   * token signed before this field existed still verifies -- the resolver
   * always sends it now, but a verifier must not require it. */
  gen: z.number().optional(),
  exp: z.number().finite(),
  iss: z.string().min(1),
  sig: z.string().min(1),
});

type QRToken = z.infer<typeof qrTokenSchema>;

function emptyResult(error: string): QRVerificationResult {
  return {
    valid: false,
    expired: false,
    huuid: null,
    bloodType: null,
    criticalAllergies: [],
    allergies: [],
    medications: [],
    chronicConditions: [],
    organDonor: null,
    implantedDevices: [],
    pregnancyStatus: null,
    primaryFacilityName: null,
    doNotGive: [],
    generatedAt: null,
    expiresAt: null,
    warning: null,
    error,
  };
}

/**
 * Same recursive sorted-key JSON canonicalization as huuid-resolver's
 * lib/canonical-json.ts (Break-Glass, Month 3) -- deliberately kept
 * identical so that if a resolver-side token issuer is built later, signer
 * and verifier agree on serialization without inventing a second
 * convention. Exported so the test-token generation used for this build
 * step's DoD signs over exactly the same bytes this function verifies.
 */
export function canonicalJsonStringify(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Builds a verification-only Ed25519 KeyObject from raw 32 public key bytes.
 * Same JWK-import approach as huuid-resolver's lib/stub-integrity-
 * signature.ts, applied here to the resolver's own signing public key
 * instead of a facility's -- Node's public-key JWK import only needs `x`,
 * no DER-prefix reconstruction is required the way it is for private keys
 * (see facility-key.ts's buildEd25519KeyObjectFromRaw comment).
 */
function buildEd25519PublicKeyObject(rawBytes: Uint8Array) {
  return createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rawBytes).toString('base64url') },
    format: 'jwk',
  });
}

/**
 * Resolution tier 4 (offline QR card fallback), Month 4; wire format fixed
 * to match the real resolver-side signer in Phase 2A (huuid-resolver's
 * lib/qr-token.ts, first built and deployed this phase -- no resolver
 * token issuer existed when this function was originally written, so its
 * wire-format assumptions were never cross-checked against a real signer
 * until now). Fully offline -- no network calls, no cache access, no
 * filesystem access. Receives ONLY the resolver's public key bytes, never
 * a file path or any other secret -- least privilege, same principle as
 * every other module in this Stub.
 *
 * Only one resolver key is ever loaded in this build (see server.ts Step
 * 6), so the token's `iss` field is included in the signed payload but not
 * checked against a key registry here -- there is nothing to look it up
 * against yet. If key rotation / multiple resolver keys are introduced
 * later, `iss` would need to select which public key to verify against;
 * tracked as a future gap, not silently assumed away.
 */
export function verifyQRToken(payload: string, resolverPublicKeyBytes: Uint8Array): QRVerificationResult {
  let decoded: string;
  try {
    // Resolver deflate-compresses (zlib deflateRawSync) the signed JSON
    // object before base64url-encoding it, to keep the printed QR small --
    // must inflate before parsing. See docs/TECHNICAL-DECISIONS.md.
    const compressed = Buffer.from(payload, 'base64url');
    decoded = inflateRawSync(compressed).toString('utf8');
  } catch {
    return emptyResult('Malformed QR token.');
  }

  let raw: unknown;
  try {
    raw = JSON.parse(decoded);
  } catch {
    return emptyResult('Malformed QR token.');
  }

  if (typeof raw !== 'object' || raw === null || !('v' in raw)) {
    return emptyResult('Malformed QR token.');
  }
  if ((raw as { v: unknown }).v !== SUPPORTED_VERSION) {
    return emptyResult('Unsupported token version');
  }

  const parsed = qrTokenSchema.safeParse(raw);
  if (!parsed.success) {
    return emptyResult('Malformed QR token.');
  }
  const token: QRToken = parsed.data;

  const nowSeconds = Math.floor(Date.now() / 1000);
  const expired = token.exp <= nowSeconds;

  const { sig, ...fieldsToVerify } = token;
  const signTarget = canonicalJsonStringify(fieldsToVerify);
  // Resolver signs SHA-256(canonical_json), not the raw canonical JSON
  // bytes -- same hash-before-sign convention as lib/bg-request-
  // signature.ts's Break-Glass verification. This was the actual bug that
  // made every token fail signature verification before this fix: this
  // function used to verify over the raw string directly.
  const signTargetHash = createHash('sha256').update(signTarget, 'utf8').digest();

  let signatureValid: boolean;
  try {
    const publicKeyObj = buildEd25519PublicKeyObject(resolverPublicKeyBytes);
    const signature = Buffer.from(sig, 'base64url');
    signatureValid = cryptoVerify(null, signTargetHash, publicKeyObj, signature);
  } catch {
    signatureValid = false;
  }

  if (!signatureValid) {
    // Do not return any health data alongside an invalid-signature verdict --
    // enforced here (not just at the route layer) so a tampered card's data
    // never leaves this function in the first place.
    return emptyResult('Invalid signature. Card may be tampered.');
  }

  return {
    // Identity verification always succeeds on a validly-signed token,
    // expired or not -- only the medical-data freshness signal changes.
    valid: true,
    expired,
    huuid: token.huuid,
    bloodType: token.bt ?? null,
    criticalAllergies: (token.ca ?? []).map((a) => a.s),
    allergies: (token.ca ?? []).map((a) => ({ substance: a.s, reaction: a.r ?? null, severity: a.sv ?? null })),
    medications: (token.cm ?? []).map((m) => ({ name: m.n, dose: m.d ?? null, frequency: m.f ?? null })),
    chronicConditions: token.cc ?? [],
    organDonor: token.od ?? null,
    implantedDevices: token.id ?? [],
    pregnancyStatus: token.preg ?? null,
    primaryFacilityName: token.pf ?? null,
    doNotGive: (token.nd ?? []).map((c) => ({ substance: c.s, reason: c.r ?? null })),
    generatedAt: token.gen ? new Date(token.gen * 1000) : null,
    expiresAt: new Date(token.exp * 1000),
    warning: expired ? EXPIRED_WARNING : null,
    error: null,
  };
}
