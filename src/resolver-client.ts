import { randomUUID } from 'node:crypto';
import { signFacilityJWT } from './facility-key.js';

/**
 * Fixed per HUUID-RESOLVER-API-v0.2 Section 2.1 -- the resolver's own JWT
 * verification (lib/facility-jwt.ts in huuid-resolver) checks `aud` against
 * this literal string, NOT against whatever host the HTTP request actually
 * went to. Do not derive this from resolverBaseUrl.
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
 * P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): this module receives ONLY
 * resolverBaseUrl and facilityDID (plus the two operational, non-secret
 * values it already needed -- facilityCode as a JWT claim value, and
 * timeoutMs -- neither of which is credential material). It never receives
 * the private key: signing is delegated entirely to facility-key.ts's
 * signFacilityJWT(), which returns only the finished JWT string.
 */
export interface ResolverClientModuleConfig {
  resolverBaseUrl: string;
  facilityDID: string;
  facilityCode: string;
  timeoutMs: number;
}

let moduleConfig: ResolverClientModuleConfig | null = null;

/** Called once by the orchestrator before any other export in this module is used. */
export function initResolverClientModule(cfg: ResolverClientModuleConfig): void {
  moduleConfig = cfg;
}

function requireInit(): ResolverClientModuleConfig {
  if (!moduleConfig) {
    throw new Error('resolver-client module not initialized. Call initResolverClientModule() first.');
  }
  return moduleConfig;
}

interface ResolutionResponseBody {
  didDocument: Record<string, unknown> | null;
  didResolutionMetadata?: { resolvedAt?: string; error?: string; errorMessage?: string };
}

/**
 * Calls the live production resolver's GET /1.0/identifiers/{did}. Times out
 * after timeoutMs (default 3000ms, Step 5) and returns a failure result
 * rather than throwing, so callers fall through to cache.
 */
export async function resolveViaLiveResolver(
  did: string,
  purposeCode: PurposeCode
): Promise<LiveResolverResult> {
  const cfg = requireInit();
  const requestId = randomUUID();

  let jwt: string;
  try {
    jwt = await signFacilityJWT({
      claims: { huuid_purpose: purposeCode, huuid_facility_code: cfg.facilityCode },
      issuer: cfg.facilityDID,
      subject: cfg.facilityDID,
      audience: RESOLVER_AUD,
      expiresInSeconds: MAX_JWT_WINDOW_SECONDS,
      jti: requestId,
    });
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'Failed to sign facility JWT.' };
  }

  const url = `${cfg.resolverBaseUrl}/1.0/identifiers/${encodeURIComponent(did)}`;
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), cfg.timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${jwt}`,
        'X-HUUID-Purpose': purposeCode,
        'X-HUUID-Facility': cfg.facilityDID,
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
        ? `Resolver request timed out after ${cfg.timeoutMs}ms`
        : err instanceof Error
          ? err.message
          : 'Network error',
    };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

export async function pingResolver(): Promise<{ ok: boolean; detail: string }> {
  const cfg = requireInit();
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    const res = await fetch(`${cfg.resolverBaseUrl}/api/health`, {
      signal: controller.signal,
    });
    return { ok: res.ok, detail: `HTTP ${res.status} from ${cfg.resolverBaseUrl}/api/health` };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : 'Network error' };
  } finally {
    clearTimeout(timeoutHandle);
  }
}
