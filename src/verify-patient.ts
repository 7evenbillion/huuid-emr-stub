import {
  resolveViaLiveResolver,
  type PurposeCode,
  type LiveResolverSuccess,
} from './resolver-client.js';
import {
  getCacheEntry,
  upsertCacheEntry,
  cacheAgeSeconds,
  FRESH_WINDOW_SECONDS,
  CACHE_VALID_SECONDS,
  type CacheEntry,
} from './cache.js';

export type { PurposeCode };

export interface HUUIDResult {
  success: boolean;
  source: 'resolver' | 'cache' | 'qr_card' | 'not_found';
  huuid: string | null;
  displayName: string | null;
  bloodType: string | null;
  criticalAllergies: string[];
  serviceEndpoints: string[];
  resolvedAt: string;
  cacheAge: number;
  error: string | null;
}

export interface VerifyPatientOptions {
  headers: { 'X-Local-Auth': string };
}

/**
 * KNOWN GAP, flagged rather than silently resolved: this signature (per
 * HUUID-EMR-STUB-v0.1.2.docx Section 3) takes no `did` parameter, but the
 * live resolver only resolves an *already-known* did:huuid -- there is no
 * arbitrary-local-ID lookup anywhere in the protocol. The doc's own
 * architecture table says the Stub "maps local ID to HUUID," but the only
 * mechanism described anywhere for establishing that mapping is a QR-card
 * scan at first encounter (Section 3.1, tier 4) -- explicitly deferred for
 * this build step ("Do not build QR verification yet").
 *
 * For now: on a cache miss, localPatientId is passed directly to the resolver
 * as a candidate did:huuid. This lets the base resolver-call path work and
 * satisfies the DoD (first call resolves live, second call hits cache), but
 * it means a real, non-DID local MRN will simply fail to resolve until the
 * QR-linking step exists. Do not treat this as "local ID lookup is done."
 */
export async function verifyPatient(
  localPatientId: string,
  purposeCode: PurposeCode,
  // Accepted for signature parity with the EMR-facing contract in the spec.
  // X-Local-Auth is already verified by local-auth.ts middleware before this
  // function is ever called (see server.ts) -- not re-checked here.
  _options: VerifyPatientOptions
): Promise<HUUIDResult> {
  const now = Math.floor(Date.now() / 1000);
  const cached = await getCacheEntry(localPatientId);

  if (cached) {
    const age = cacheAgeSeconds(cached, now);

    // "cache < 15 min" -- skip a redundant live call (DoD test 4: second
    // verify() for the same patient must return source: 'cache').
    if (age < FRESH_WINDOW_SECONDS) {
      return resultFromCache(cached, age);
    }

    // "cache < 24 hours old" -- return cache now, refresh in the background.
    // Fire-and-forget: must not block this response.
    if (age < CACHE_VALID_SECONDS) {
      void refreshInBackground(localPatientId, purposeCode);
      return resultFromCache(cached, age);
    }

    // "cache > 24 hours" (stale). Prefer a fresh live resolution if the
    // resolver is reachable; otherwise fall back to the stale cache. The
    // given HUUIDResult type has no separate "stale" flag, so cacheAge is
    // how the caller is meant to detect this (Section 3.1 says "warn," not
    // "refuse").
    const live = await resolveViaLiveResolver(localPatientId, purposeCode);
    if (live.ok) {
      await persistToCache(localPatientId, live);
      return resultFromLive(live, 'resolver');
    }
    return resultFromCache(cached, age);
  }

  // No cache at all -- must attempt a live resolution (see gap note above).
  const live = await resolveViaLiveResolver(localPatientId, purposeCode);
  if (live.ok) {
    await persistToCache(localPatientId, live);
    return resultFromLive(live, 'resolver');
  }

  // Tier 4 (QR card scan) is explicitly deferred for this build step --
  // falls through to tier 5, not_found.
  return {
    success: false,
    source: 'not_found',
    huuid: null,
    displayName: null,
    bloodType: null,
    criticalAllergies: [],
    serviceEndpoints: [],
    resolvedAt: new Date().toISOString(),
    cacheAge: 0,
    error: live.reason,
  };
}

async function persistToCache(localPatientId: string, live: LiveResolverSuccess): Promise<void> {
  await upsertCacheEntry({
    localPatientId,
    huuid: live.huuid,
    displayName: live.displayName,
    bloodType: live.bloodType,
    criticalAllergies: live.criticalAllergies,
    serviceEndpoints: live.serviceEndpoints,
    source: 'resolver',
    tokenExpiresAt: null,
  });
}

function resultFromCache(entry: CacheEntry, age: number): HUUIDResult {
  return {
    success: true,
    source: 'cache',
    huuid: entry.huuid,
    displayName: entry.displayName,
    bloodType: entry.bloodType,
    criticalAllergies: entry.criticalAllergies,
    serviceEndpoints: entry.serviceEndpoints,
    resolvedAt: new Date(entry.verifiedAt * 1000).toISOString(),
    cacheAge: age,
    error: null,
  };
}

function resultFromLive(live: LiveResolverSuccess, source: 'resolver' | 'qr_card'): HUUIDResult {
  return {
    success: true,
    source,
    huuid: live.huuid,
    displayName: live.displayName,
    bloodType: live.bloodType,
    criticalAllergies: live.criticalAllergies,
    serviceEndpoints: live.serviceEndpoints,
    resolvedAt: live.resolvedAt,
    cacheAge: 0,
    error: null,
  };
}

async function refreshInBackground(localPatientId: string, purposeCode: PurposeCode): Promise<void> {
  try {
    const live = await resolveViaLiveResolver(localPatientId, purposeCode);
    if (live.ok) {
      await persistToCache(localPatientId, live);
    }
  } catch {
    // Best-effort -- background refresh failures are never surfaced to the caller.
  }
}
