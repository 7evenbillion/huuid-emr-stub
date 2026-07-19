/**
 * NOT IMPLEMENTED -- explicitly deferred per the build instructions for this
 * step ("Do not build OS keystore yet ... those are the next steps after
 * this base works. One layer at a time.").
 *
 * When built, this will import the facility private key into the OS
 * credential store (Windows Credential Manager / macOS Keychain / Linux
 * libsecret via `keytar`) and shred the .pem file, per Section 2 P2 of
 * HUUID-EMR-STUB-v0.1.2.docx. Until then, the private key stays as a plain
 * file at HUUID_FACILITY_PRIVATE_KEY_PATH -- a known, temporary, and
 * explicitly-flagged insecurity, not a silent one.
 */
console.log('secure-keys: NOT IMPLEMENTED (deferred to the OS-keystore hardening step).');
console.log('The facility private key remains a plain PEM file for this build. See README.md.');
process.exit(1);
