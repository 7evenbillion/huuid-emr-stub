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
  TTL_SECONDS,
  type CacheEntry,
} from './cache.js';

export type { PurposeCode };

export interface HUUIDResult {
  success: boolean;
  // 'qr_card_required' added Month 4 (Step 5) -- additive, does not change
  // the meaning of any existing value. 'not_found' is still reachable in
  // principle (see gap note above) but tiers 1-3 exhausting now yields
  // 'qr_card_required' instead, per HUUID-EMR-STUB-v0.1.2.docx Section 3.1's
  // resolution priority table putting QR card scan (tier 4) before "not
  // found" (tier 5).
  source: 'resolver' | 'cache' | 'qr_card' | 'qr_card_required' | 'not_found';
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

  // Tiers 1-3 exhausted (no cache at all, live resolver unreachable). Tier 4
  // is QR card scan -- verifyPatient() cannot perform that itself (it
  // requires a physical scan via POST /qr/verify, a separate request), so it
  // signals the caller to prompt for one rather than declaring not_found
  // outright.
  return {
    success: false,
    source: 'qr_card_required',
    huuid: null,
    displayName: null,
    bloodType: null,
    criticalAllergies: [],
    serviceEndpoints: [],
    resolvedAt: new Date().toISOString(),
    cacheAge: 0,
    error: 'Resolver unreachable and no cache entry. Please scan patient QR card.',
  };
}

/**
 * Called by POST /qr/verify (server.ts) after a QR token passes signature
 * verification -- never on an invalid signature (that returns 400 with no
 * health data, per Step 4, before this function is ever reached). TTL is
 * min(token expiry, 72 hours) per Section 3.1's tier 4 cache behavior ("Stores
 * verified QR data in cache for 72 hours") -- an already-expired-but-validly-
 * signed token naturally floors to ~0 forward validity via Math.max below,
 * which is correct: it's still cached (so /debug/resolver and a same-second
 * re-verify see it) but immediately eligible for tier 3's "prefer a fresh
 * live resolution" behavior on the very next lookup, not tier 2's 15-minute
 * skip-the-live-call fast path.
 */
export async function recordQRVerification(
  localPatientId: string,
  qr: { huuid: string; bloodType: string | null; criticalAllergies: string[]; expiresAtSeconds: number }
): Promise<HUUIDResult> {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Math.max(Math.min(qr.expiresAtSeconds - now, TTL_SECONDS.qr_card), 0);

  await upsertCacheEntry({
    localPatientId,
    huuid: qr.huuid,
    displayName: null,
    bloodType: qr.bloodType,
    criticalAllergies: qr.criticalAllergies,
    serviceEndpoints: [],
    source: 'qr_card',
    tokenExpiresAt: now + ttl,
    verifiedAt: now,
  });

  return {
    success: true,
    source: 'qr_card',
    huuid: qr.huuid,
    displayName: null,
    bloodType: qr.bloodType,
    criticalAllergies: qr.criticalAllergies,
    serviceEndpoints: [],
    resolvedAt: new Date(now * 1000).toISOString(),
    cacheAge: 0,
    error: null,
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
