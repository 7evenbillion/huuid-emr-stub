import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { z } from 'zod';

export interface QRVerificationResult {
  valid: boolean;
  expired: boolean;
  huuid: string | null;
  bloodType: string | null;
  criticalAllergies: string[];
  expiresAt: Date | null;
  error: string | null;
}

const SUPPORTED_VERSION = 1;

const qrTokenSchema = z.object({
  v: z.number(),
  huuid: z.string().min(1),
  bt: z.string().nullable().optional(),
  ca: z.array(z.string()).default([]),
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
    expiresAt: null,
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
 * Resolution tier 4 (offline QR card fallback), Month 4. Fully offline --
 * no network calls, no cache access, no filesystem access. Receives ONLY
 * the resolver's public key bytes, never a file path or any other secret --
 * least privilege, same principle as every other module in this Stub.
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
    decoded = Buffer.from(payload, 'base64url').toString('utf8');
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

  let signatureValid: boolean;
  try {
    const publicKeyObj = buildEd25519PublicKeyObject(resolverPublicKeyBytes);
    const signature = Buffer.from(sig, 'base64url');
    signatureValid = cryptoVerify(null, Buffer.from(signTarget, 'utf8'), publicKeyObj, signature);
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
    valid: true,
    expired,
    huuid: token.huuid,
    bloodType: token.bt ?? null,
    criticalAllergies: token.ca,
    expiresAt: new Date(token.exp * 1000),
    error: null,
  };
}
