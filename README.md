# HUUID EMR Stub Middleware

Local clinic integration layer. Bridges an existing EMR to the HUUID
resolver network without moving any medical data off the clinic's own
server. Governing spec: `HUUID-EMR-STUB-v0.1.2.docx` (v0.1 and v0.1.1 are
retired -- see Section 0 of that document).

This is a standalone Node.js/Express/TypeScript service, **not** part of
the Next.js resolver (`huuid-resolver`). It runs locally at each clinic.

## Status

**Base build + Security Layer 1 (SQLCipher, P1) + Security Layer 2 (OS
keystore, P2).** The local cache DB is AES-256-CBC + HMAC-SHA512 encrypted
(SQLCipher's real cipher -- not GCM, see below), keyed by HKDF-SHA256 over
the facility private key. The facility private key itself now lives in the
OS credential store (Windows Credential Manager / macOS Keychain / Linux
libsecret via `@napi-rs/keyring`) once `npm run secure-keys` has been run --
the PEM file is shredded and deleted at that point. A file fallback remains
for the transition period before that script has been run. **Explicitly not
implemented yet** (by design, one layer at a time):

- Integrity baseline / HMAC monitoring (P4)
- QR card offline verification (resolution tier 4)

`npm run diagnostics` reports both honestly as not-yet-started.

### `keytar` replaced with `@napi-rs/keyring`

`keytar` (used for the initial P2 build) is unmaintained upstream -- last
release over a year ago, GitHub repo archived. `@napi-rs/keyring` is its
actively maintained replacement: verified here with a real Windows prebuild
(`@napi-rs/keyring-win32-x64-msvc`, N-API so ABI-stable), a full Windows
Credential Manager set/get/delete roundtrip, and its API is synchronous
(unlike keytar's Promise-based one) -- `facility-key.ts`'s exported
functions stay `async` regardless, purely so every existing caller's
`await` keeps working unchanged.

**Real finding, not a prebuild problem: the two libraries are not
Credential-Manager-interoperable.** keytar stores under Windows target
`huuid-emr-stub/facility-private-key` (service/account); `@napi-rs/keyring`
stores under `facility-private-key.huuid-emr-stub` (account.service) --
different strings, same underlying store, mutually invisible. A facility
that already ran the keytar-based `secure-keys` has its PEM already
shredded and its key now orphaned under the old target name after this
dependency swap. This build's own test key hit exactly that: recovered
here only because the resolver's test-facility fixture could regenerate a
fresh PEM; a real facility key has no such backup. **If this swap is
deployed to any facility that already ran the old `secure-keys`, that
facility's key must be recovered before upgrading** -- there is no
automatic migration path in this codebase, and none should be assumed.

### Where the facility private key actually lives now

`src/facility-key.ts` is the single source of truth: keystore first, PEM
file fallback, clear error if neither has a key. Two implementation details
worth knowing:

- **Raw-bytes reconstruction, not PEM round-tripping.** The keystore stores
  only the raw 32-byte Ed25519 private scalar (base64url). Rebuilding a
  usable signing key from just that requires the RFC 8410 PKCS8 DER prefix
  for Ed25519 (fixed, 16 bytes, same for every key) rather than Node's JWK
  import, which insists on the public key (`x`) even though it's
  mathematically redundant for Ed25519. This also avoids ever creating an
  intermediate PEM string, which -- being an immutable JS string -- could
  not be zeroed anyway (see below).
- **Memory zeroing (Step 7) is real but string-limited.** Every raw-bytes
  `Buffer` touching the private key is `.fill(0)`'d immediately after use
  (`cache-key.ts`, `facility-key.ts`, `resolver-client.ts`,
  `scripts/secure-keys.ts`). `resolver-client.ts` no longer caches a signing
  key across requests -- it fetches raw bytes, builds a key, signs, and
  zeroes on every single call, per this step's literal wording. What
  *cannot* be zeroed: the base64url string `Entry.getPassword()` returns,
  or a PEM string, since JS strings are immutable and nothing can wipe their
  backing memory from JS code. This is a real limit of the runtime, not an
  oversight -- documented rather than glossed over.

### SQLCipher package: `@signalapp/sqlcipher`, not `@journeyapps/sqlcipher`

The spec's Step 1 named `@journeyapps/sqlcipher`. Its own README states
Windows is not supported ("Windows and prebuilt binary publishing are
intentionally unsupported in this phase") -- confirmed by testing, and a
real blocker since Windows is a first-class clinic deployment target per
the doc's own OS-keystore step. `@signalapp/sqlcipher` (Signal Desktop's
own SQLCipher binding) has a verified working `win32-x64` prebuild and a
synchronous, better-sqlite3-like API. **Trade-off: it's AGPL-3.0-only**,
versus `@journeyapps/sqlcipher`'s BSD-3-Clause -- a real licensing
consideration for this codebase, flagged and approved before use, not
picked silently.

### `PRAGMA cipher = 'aes-256-gcm'` is not real

Verified against SQLCipher's own docs and empirically: SQLCipher has no
GCM mode. The pragma is silently accepted but has no effect --
`PRAGMA cipher` still reports `aes-256-cbc` afterward. SQLCipher's real
authenticated encryption is AES-256-CBC + HMAC-SHA512 (both defaults, left
untouched). `src/cache.ts` does not set this pragma; see the comment there.

### `kdf_iter` is a no-op in this build

Verified empirically: `PRAGMA kdf_iter` only affects SQLCipher's own
passphrase-based key derivation. This Stub supplies a raw, pre-derived key
(`x'<hex>'` syntax) from HKDF-SHA256 over the facility private key, which
bypasses that KDF step entirely. Set anyway for spec fidelity -- it does
not weaken or strengthen anything here.

## Setup

```
npm install
cp config-template.env .env   # fill in your facility's values
npm run generate-local-secret
```

You also need a facility Ed25519 private key (PKCS8 PEM) at the path set by
`HUUID_FACILITY_PRIVATE_KEY_PATH`. **`npm run download-keys` cannot fetch
this for you yet** -- the live resolver has no key-distribution endpoint.
Place it manually until that exists.

```
npm run start
```

## Known gaps (flagged, not hidden)

- **No local-ID-to-DID linking mechanism yet.** `verifyPatient(localPatientId, ...)`
  has no `did` parameter, but the resolver can only resolve an
  already-known `did:huuid` -- it has no arbitrary local-ID lookup. The
  only mechanism the spec describes for establishing that mapping is a
  QR-card scan at first encounter, which is explicitly deferred this step.
  For now, a cache-miss `localPatientId` is passed directly to the resolver
  as a candidate DID. Real MRNs will not resolve until QR linking exists.
- **`download-keys` is not implemented.** No endpoint exists on the live
  resolver to serve facility keys. Placeholder script explains this and
  exits non-zero rather than faking success.
- **The live resolver does not yet return `bloodType` / `criticalAllergies`.**
  The example DID Document in the Resolution Spec (Section 2.1) includes an
  `offlineToken` with these fields, but the actual Month 2/3 resolver's
  stored DID documents (see `huuid-resolver/supabase/migrations/001_initial.sql`)
  only carry the standard W3C DID fields. This Stub parses `offlineToken`
  defensively and will pick the fields up automatically once the resolver
  starts returning them -- no code change needed here.
- **`config-template.env` has no "Section 6" to copy from.** The spec
  document only goes up to Section 5. Only `HUUID_FACILITY_DID`,
  `HUUID_API_KEY`, and `HUUID_FACILITY_CODE` are doc-mandated fields;
  everything else in the template is there because this code needs it,
  commented as such.

## Scripts

| Script | Status |
|---|---|
| `start` | Implemented |
| `test-connection` | Implemented -- pings resolver health, then verifies the facility certificate via a probe resolution |
| `diagnostics` | Implemented |
| `generate-local-secret` | Implemented |
| `check-permissions` | Implemented |
| `install-service` (Windows) | Implemented -- generates a wrapper + prints `sc.exe` commands; does not self-elevate |
| `install-systemd` (Linux) | Implemented -- generates a unit file + prints `systemctl` commands; does not self-install |
| `download-keys` | Not implemented -- no live endpoint yet |
| `secure-keys` | Implemented -- imports the facility key to the OS keystore, verifies the roundtrip, then shreds + deletes the PEM. Halts without deleting anything if verification fails. |
| `install-integrity-baseline` | Not implemented -- deferred (HMAC monitoring) |

`npm run diagnostics` also verifies cache encryption is active (checks the
DB file lacks SQLite's plaintext magic header) and reports `Cache: ENCRYPTED`,
and reports `Key storage: KEYSTORE / FILE / MISSING` with a warning or error
as appropriate.

**Note on `scripts/secure-keys.ts`'s location:** this build step's brief
named `src/scripts/secure-keys.ts` as the file path. The repo's established
convention -- and the already-registered `package.json` script -- puts every
CLI script at the top-level `scripts/`, so the implementation lives at
`scripts/secure-keys.ts` (same place as the rest) rather than creating a
second, disconnected path under `src/`.

## Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Local system status (no external calls) |
| `POST /verify` | `X-Local-Auth` | The EMR integration surface -- calls `verifyPatient()` |
| `GET /debug/resolver` | none | Local cache contents (developer page, mirrors the resolver repo's own `/debug/resolver`) |
| `GET /debug/qr` | none | Explains QR scanning isn't built yet |
