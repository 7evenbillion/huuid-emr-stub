import { SignJWT } from 'jose';
import { randomUUID } from 'node:crypto';
import { loadConfig } from './config.js';
import { getFacilityPrivateKeyRaw, buildEd25519KeyObjectFromRaw } from './facility-key.js';

/**
 * Fixed per HUUID-RESOLVER-API-v0.2 Section 2.1 -- the resolver's own JWT
 * verification (lib/facility-jwt.ts in huuid-resolver) checks `aud` against
 * this literal string, NOT against whatever host the HTTP request actually
 * went to. Do not derive this from HUUID_RESOLVER_BASE_URL.
 */
const RESOLVER_AUD = 'https://resolver.huuid.health';
const MAX_JWT_WINDOW_SECONDS = 300;

export type PurposeCode = 'Treatment' | 'Administrative' | 'Emergency';

export interface LiveResolverSuccess {
  ok: true;
  huuid: string;
  displayName: string | null;
  bloodType: string | null;
  criticalAllergies: string[];
  serviceEndpoints: string[];
  resolvedAt: string;
}

export interface LiveResolverFailure {
  ok: false;
  reason: string;
  httpStatus?: number;
}

export type LiveResolverResult = LiveResolverSuccess | LiveResolverFailure;

/**
 * No caching of the signing key here (deliberately -- see Step 7 of this
 * build step). Keystore-first, file-fallback via facility-key.ts (Step 4);
 * `download-keys` still has no real endpoint to call (see README), so the
 * file fallback still requires a manually-placed PKCS8 PEM until either that
 * endpoint exists or npm run secure-keys has moved the key to the keystore.
 *
 * Raw key bytes are fetched fresh for every signing call and zeroed
 * immediately after the KeyObject is built -- "zero out the key bytes"
 * after every signing operation, not just once at process start.
 */
async function signFacilityJWT(purposeCode: PurposeCode, requestId: string): Promise<string> {
  const config = loadConfig();
  const now = Math.floor(Date.now() / 1000);

  const { bytes: rawKey } = await getFacilityPrivateKeyRaw();
  let signingKey;
  try {
    signingKey = buildEd25519KeyObjectFromRaw(rawKey);
  } finally {
    rawKey.fill(0);
  }

  return new SignJWT({
    huuid_purpose: purposeCode,
    huuid_facility_code: config.HUUID_FACILITY_CODE,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + MAX_JWT_WINDOW_SECONDS)
    .setIssuer(config.HUUID_FACILITY_DID)
    .setSubject(config.HUUID_FACILITY_DID)
    .setAudience(RESOLVER_AUD)
    .setJti(requestId)
    .sign(signingKey);
}

interface ResolutionResponseBody {
  didDocument: Record<string, unknown> | null;
  didResolutionMetadata?: { resolvedAt?: string; error?: string; errorMessage?: string };
}

/**
 * Calls the live production resolver's GET /1.0/identifiers/{did}. Times out
 * after HUUID_RESOLVER_TIMEOUT_MS (default 3000ms, Step 5) and returns a
 * failure result rather than throwing, so callers fall through to cache.
 */
export async function resolveViaLiveResolver(
  did: string,
  purposeCode: PurposeCode
): Promise<LiveResolverResult> {
  const config = loadConfig();
  const requestId = randomUUID();

  let jwt: string;
  try {
    jwt = await signFacilityJWT(purposeCode, requestId);
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'Failed to sign facility JWT.' };
  }

  const url = `${config.HUUID_RESOLVER_BASE_URL}/1.0/identifiers/${encodeURIComponent(did)}`;
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), config.HUUID_RESOLVER_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${jwt}`,
        'X-HUUID-Purpose': purposeCode,
        'X-HUUID-Facility': config.HUUID_FACILITY_DID,
        'X-HUUID-Request-ID': requestId,
      },
      signal: controller.signal,
    });

    const body = (await res.json()) as ResolutionResponseBody;

    if (!res.ok || !body.didDocument) {
      return {
        ok: false,
        httpStatus: res.status,
        reason: body.didResolutionMetadata?.errorMessage ?? `Resolver returned ${res.status}`,
      };
    }

    const doc = body.didDocument;
    // The live Month 2 resolver stores only standard W3C DID fields today -- no
    // offlineToken/bloodType/criticalAllergies exist in production yet, despite
    // the example DID Document in HUUID-RESOLUTION-SPEC-v0.2.docx Section 2.1
    // showing one (confirmed against supabase/migrations/001_initial.sql's seed
    // data in huuid-resolver). Reading them defensively here means this parses
    // correctly today and picks the fields up automatically once the resolver
    // starts returning them, without this Stub needing a code change.
    const offlineToken = doc.offlineToken as
      | { bloodType?: string; criticalAllergies?: string[] }
      | undefined;
    const service = doc.service as Array<{ serviceEndpoint?: string }> | undefined;
    const serviceEndpoints = Array.isArray(service)
      ? service.map((s) => s.serviceEndpoint).filter((s): s is string => Boolean(s))
      : [];

    return {
      ok: true,
      huuid: (doc.id as string | undefined) ?? did,
      // No name field exists anywhere in the DID Document schema by design --
      // Section 3.1 of the Resolution Spec weights name/DOB at 0.00 and marks
      // it "fallback only," never part of the cryptographic identity.
      displayName: null,
      bloodType: offlineToken?.bloodType ?? null,
      criticalAllergies: offlineToken?.criticalAllergies ?? [],
      serviceEndpoints,
      resolvedAt: body.didResolutionMetadata?.resolvedAt ?? new Date().toISOString(),
    };
  } catch (err) {
    const aborted = err instanceof Error && err.name === 'AbortError';
    return {
      ok: false,
      reason: aborted
        ? `Resolver request timed out after ${config.HUUID_RESOLVER_TIMEOUT_MS}ms`
        : err instanceof Error
          ? err.message
          : 'Network error',
    };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

export async function pingResolver(): Promise<{ ok: boolean; detail: string }> {
  const config = loadConfig();
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), config.HUUID_RESOLVER_TIMEOUT_MS);
  try {
    const res = await fetch(`${config.HUUID_RESOLVER_BASE_URL}/api/health`, {
      signal: controller.signal,
    });
    return { ok: res.ok, detail: `HTTP ${res.status} from ${config.HUUID_RESOLVER_BASE_URL}/api/health` };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : 'Network error' };
  } finally {
    clearTimeout(timeoutHandle);
  }
}
