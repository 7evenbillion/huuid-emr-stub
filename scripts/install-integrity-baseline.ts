/**
 * NOT IMPLEMENTED -- explicitly deferred for this build step, same reasoning
 * as secure-keys.ts. When built, this will HMAC-SHA256 every Stub source
 * file into ./integrity/baseline.hmac (Section 2 P4 of
 * HUUID-EMR-STUB-v0.1.2.docx) so the server can refuse to start on a
 * tampered install.
 */
console.log('install-integrity-baseline: NOT IMPLEMENTED (deferred to the hardening step).');
process.exit(1);
