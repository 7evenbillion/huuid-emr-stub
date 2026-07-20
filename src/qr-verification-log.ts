import type { QRVerificationResult } from './qr-verifier.js';

// In-memory only, per Step 8 ("a simple in-memory log, not a DB table") --
// resets on restart, capped at the last 5. This is a debug convenience for
// /debug/resolver, not an audit trail; nothing here is persisted or signed.

export interface QRVerificationLogEntry {
  timestamp: string;
  valid: boolean;
  expired: boolean;
  huuid: string | null;
  error: string | null;
}

const MAX_LOG_ENTRIES = 5;
const log: QRVerificationLogEntry[] = [];

export function recordQRVerificationAttempt(result: QRVerificationResult): void {
  log.unshift({
    timestamp: new Date().toISOString(),
    valid: result.valid,
    expired: result.expired,
    huuid: result.huuid,
    error: result.error,
  });
  log.length = Math.min(log.length, MAX_LOG_ENTRIES);
}

export function getRecentQRVerifications(): QRVerificationLogEntry[] {
  return [...log];
}
