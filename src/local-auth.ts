import type { NextFunction, Request, Response } from 'express';
import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

/**
 * P5 (HUUID-EMR-STUB-v0.1.2.docx Section 2): this module receives ONLY
 * localSecretPath -- no other secret.
 */
export interface LocalAuthModuleConfig {
  localSecretPath: string;
}

let moduleConfig: LocalAuthModuleConfig | null = null;

/** Called once by the orchestrator before any other export in this module is used. */
export function initLocalAuthModule(cfg: LocalAuthModuleConfig): void {
  moduleConfig = cfg;
}

function requireInit(): LocalAuthModuleConfig {
  if (!moduleConfig) {
    throw new Error('local-auth module not initialized. Call initLocalAuthModule() first.');
  }
  return moduleConfig;
}

const FAILURE_WINDOW_MS = 60_000; // "3 failures in 60 seconds"
const FAILURE_THRESHOLD = 3;
const LOCKOUT_MS = 15 * 60_000; // "lockout 15 min"

interface IpState {
  failureTimestamps: number[];
  lockedUntil: number | null;
}

const state = new Map<string, IpState>();

function getState(ip: string): IpState {
  let s = state.get(ip);
  if (!s) {
    s = { failureTimestamps: [], lockedUntil: null };
    state.set(ip, s);
  }
  return s;
}

function recordFailure(ip: string, now: number): void {
  const s = getState(ip);
  s.failureTimestamps = s.failureTimestamps.filter((t) => now - t < FAILURE_WINDOW_MS);
  s.failureTimestamps.push(now);
  if (s.failureTimestamps.length >= FAILURE_THRESHOLD) {
    s.lockedUntil = now + LOCKOUT_MS;
    s.failureTimestamps = [];
  }
}

function recordSuccess(ip: string): void {
  state.delete(ip);
}

function lockoutRemainingMs(ip: string, now: number): number | null {
  const s = state.get(ip);
  if (!s?.lockedUntil) return null;
  const remaining = s.lockedUntil - now;
  if (remaining <= 0) {
    s.lockedUntil = null;
    return null;
  }
  return remaining;
}

let cachedSecret: string | null = null;

function loadLocalSecret(): string {
  if (cachedSecret !== null) return cachedSecret;
  const cfg = requireInit();
  if (!existsSync(cfg.localSecretPath)) {
    throw new Error(
      `No local-auth secret found at ${cfg.localSecretPath}. ` +
        `Run: npm run generate-local-secret`
    );
  }
  cachedSecret = readFileSync(cfg.localSecretPath, 'utf8').trim();
  return cachedSecret;
}

/**
 * Fixed-length digest comparison so timingSafeEqual never throws on a
 * length mismatch (it requires equal-length buffers) -- hashing both sides
 * first normalizes length without weakening the constant-time comparison
 * P3 calls for.
 */
function secretsMatch(provided: string, expected: string): boolean {
  const a = createHash('sha256').update(provided).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export function localAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
  const now = Date.now();

  const lockedFor = lockoutRemainingMs(ip, now);
  if (lockedFor !== null) {
    res.status(429).json({
      success: false,
      error: 'locked_out',
      message: `Too many failed X-Local-Auth attempts. Locked out for ${Math.ceil(lockedFor / 1000)}s.`,
    });
    return;
  }

  const provided = req.header('X-Local-Auth');
  if (!provided) {
    recordFailure(ip, now);
    res.status(401).json({ success: false, error: 'missing_auth', message: 'X-Local-Auth header is required.' });
    return;
  }

  let expected: string;
  try {
    expected = loadLocalSecret();
  } catch (err) {
    res.status(500).json({
      success: false,
      error: 'server_misconfigured',
      message: err instanceof Error ? err.message : 'Local-auth secret not configured.',
    });
    return;
  }

  if (!secretsMatch(provided, expected)) {
    recordFailure(ip, now);
    res.status(401).json({ success: false, error: 'invalid_auth', message: 'X-Local-Auth did not match.' });
    return;
  }

  recordSuccess(ip);
  next();
}

export function localAuthDiagnostics(): { secretConfigured: boolean; lockedIps: number } {
  const cfg = requireInit();
  let secretConfigured = false;
  try {
    secretConfigured = existsSync(cfg.localSecretPath);
  } catch {
    secretConfigured = false;
  }
  const now = Date.now();
  let lockedIps = 0;
  for (const s of state.values()) {
    if (s.lockedUntil && s.lockedUntil > now) lockedIps++;
  }
  return { secretConfigured, lockedIps };
}
