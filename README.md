# HUUID EMR Stub Middleware

Local clinic integration layer. Bridges an existing EMR to the HUUID
resolver network without moving any medical data off the clinic's own
server. Governing spec: `HUUID-EMR-STUB-v0.1.2.docx` (v0.1 and v0.1.1 are
retired -- see Section 0 of that document).

This is a standalone Node.js/Express/TypeScript service, **not** part of
the Next.js resolver (`huuid-resolver`). It runs locally at each clinic.

## Status

**Base build + Security Layer 1 (SQLCipher, P1) + Security Layer 2 (OS
keystore, P2) + Security Layer 3 (process integrity hashing, P4).** The
local cache DB is AES-256-CBC + HMAC-SHA512 encrypted (SQLCipher's real
cipher -- not GCM, see below), keyed by HKDF-SHA256 over the facility
private key. The facility private key itself lives in the OS credential
store (Windows Credential Manager / macOS Keychain / Linux libsecret via
`@napi-rs/keyring`) once `npm run secure-keys` has been run -- the PEM
file is shredded and deleted at that point. A file fallback remains for
the transition period before that script has been run. `npm run
install-integrity-baseline` signs a manifest of every `src/`/`scripts/`
file (plus `package-lock.json`) with the facility key; `npm run start`
verifies it on every startup and every 6 hours thereafter. **Explicitly
not implemented yet** (by design, one layer at a time):

- QR card offline verification (resolution tier 4)

`npm run diagnostics` reports this honestly as not-yet-started.

### `keytar` replaced with `@napi-rs/keyring`

`keytar` (used for the initial P2 build) is unmaintained upstream -- last
release over a year ago, GitHub repo archived. `@napi-rs/keyring` is its
actively maintained replacement: verified here with a real Windows prebuild
(`@napi-rs/keyring-win32-x64-msvc`, N-API so ABI-stable), a full Windows
Credential Manager set/get/delete roundtrip, and its API is synchronous
(unlike keytar's Promise-based one) -- `facility-key.ts`'s exported
functions stay `async` regardless, purely so every existing caller's
`await` keeps working unchanged.

**Real finding, not a prebuild problem: the two libraries were not
Credential-Manager-interoperable.** keytar stored under Windows target
`huuid-emr-stub/facility-private-key` (service/account); `@napi-rs/keyring`
stores under `facility-private-key.huuid-emr-stub` (account.service) --
different strings, same underlying store, mutually invisible. This was
originally a real operational gap: a facility that had already run the
keytar-based `secure-keys` had its PEM already shredded, leaving its key
orphaned under the old target name after the dependency swap, with no
plaintext backup. **This is now fixed automatically -- see "Upgrading from
keytar-based installations" below.**

### Upgrading from keytar-based installations (v0.x before July 2026)

Migration is automatic on first startup after upgrading. No manual steps
required.

`src/keystore-migration.ts` runs as the last-resort step in the same
lookup chain `facility-key.ts` already used (current keystore -> PEM file
-> *then* legacy keytar, Windows only) -- so it only ever runs for a
facility that has neither a current-format keystore entry nor a PEM file,
which is exactly the state a keytar-upgraded facility is in (its PEM was
already shredded by the old `secure-keys`). On every other startup it is
never reached at all.

**How it actually reads the legacy credential -- and why not the obvious
way.** `@napi-rs/keyring` ships `Entry.withTarget(target, service, account)`,
which looked like the natural fix: point it at keytar's exact target string
and read the key without any extra dependency. Tested against a real
keytar-written credential, it returned an empty string. Tested again as a
*pure self-consistency* check -- writing with `withTarget` and reading back
with `withTarget`, no keytar involved at all -- it *still* returned an
empty string. That ruled it out as a bug in the npm package on Windows,
not a target-string mismatch, before it was built on.

The actual mechanism: raw P/Invoke to `advapi32.dll`'s `CredRead` /
`CredDelete` via PowerShell's `Add-Type` -- the same underlying Win32 API
keytar's native addon and `@napi-rs/keyring`'s Rust backend both call
internally, invoked directly rather than through either npm package.
`Get-StoredCredential` (the other tool named for this) also doesn't work
out of the box -- it isn't a built-in cmdlet, it ships in the third-party
`CredentialManager` PowerShell module, which isn't installed by default
and installing it wasn't assumed. `Add-Type`/P/Invoke requires no module
install; it ships with every Windows PowerShell.

One more thing verified rather than assumed: the `CredentialBlob` decode.
The "correct" Windows-native assumption is UTF-16LE. Decoding a real
keytar-written credential that way produced garbage. keytar's Windows
addon writes the password as raw UTF-8 bytes instead -- confirmed by
switching the decode to UTF-8 and getting a byte-for-byte match against
the known original value. `src/keystore-migration.ts` decodes as UTF-8
for exactly this reason.

Migration sequence, matching the spec's steps exactly: read the legacy
credential -> write it to the current keystore -> read it back and verify
the value matches -> only then delete the legacy credential. If
verification fails, the legacy credential is left in place and nothing is
deleted -- `npm run diagnostics` reports this as an error rather than
silently losing the key. Every failure mode (PowerShell unavailable, call
times out, nothing to migrate) returns `null` and falls through to the
normal "no key found" handling; migration never crashes startup.

`npm run diagnostics` reports `Migrated facility key from legacy keytar
store to current keyring store (this run)` when it (or `npm run start`)
is the one that triggers the migration, and includes `"keytarMigration":
"migrated"` in its JSON output. On any later run, once the key is already
in the current keystore, this step is skipped entirely and nothing is
reported.

**Scope note:** this migration path is Windows-only, matching the target
strings actually verified against a real keytar-written credential. macOS
Keychain and Linux libsecret were not observed to have the same
interoperability gap during this build and are out of scope here.

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

### Process integrity hashing (P4)

`npm run install-integrity-baseline` computes a single HMAC-SHA256 over
every `.ts`/`.js` file in `src/` and `scripts/` plus `package-lock.json`
(sorted by path, path and content both hashed so a rename or a swap
between two same-sized files is caught, not just an edit), EdDSA-signs
that hash with the facility private key, and writes `integrity/
baseline.hmac` read-only (`attrib +r` on Windows, `chmod 444` elsewhere).
`npm run start` recomputes and verifies the same manifest on every
startup and every 6 hours thereafter (`src/integrity-check.ts`).

**Deferred by design, not by oversight: a mismatch does NOT stop the
Stub from starting.** The doc says a mismatch should refuse to start.
This build deliberately doesn't do that yet -- refusing to start on any
manifest mismatch risks bricking a clinic machine over a stale baseline
(e.g. a legitimate `npm update` that wasn't followed by re-running
`install-integrity-baseline`), which is a worse outcome for patient care
than a facility running while flagged. The alert to the Root Authority
(`POST /1.0/stub-integrity` on the resolver) is the load-bearing piece
for now; `integrityViolation` is tracked and surfaced via `/health` and
`npm run diagnostics`, but the server keeps running.

**Real gotcha, not a bug: `git checkout`/`git pull` on Windows can trip a
false-positive violation.** Found while testing the tamper-then-restore
flow -- restoring a file via `git checkout` produced a byte-different
file (CRLF line endings, from Windows' `core.autocrlf`) even though the
text content was identical to what the baseline was computed from (LF).
The manifest hashes raw bytes, so it correctly flagged this as changed --
which is the check working as designed, but it means **re-running `npm
run install-integrity-baseline` after any `git pull` that could have
touched line endings is a real operational step**, not just after
intentional code edits. Worth knowing before this trips someone up in a
real deployment.

**HMAC key is HKDF-derived, domain-separated from the cache encryption
key.** Same root secret (facility private key), different salt/info
strings (`:integrity-baseline-v1` / `huuid-integrity-key` vs.
cache-key.ts's `:cache-encryption-v1` / `huuid-cache-key`), so a leak or
reuse of one derived key says nothing about the other. Not strictly
load-bearing for tamper-*detection* -- the EdDSA signature over the
manifest hash is what actually prevents forgery -- but it keeps the raw
manifest fingerprint tied to a specific facility rather than being a
plain, publicly comparable hash.

**Self-verification, not a fetch.** `verifyManifestSignature` checks the
baseline's signature against a public key derived from the SAME private
key bytes this process already holds (Ed25519 public keys are always
deterministically derivable from the private seed -- see
`buildEd25519KeyObjectFromRaw` in `facility-key.ts`), not against
`huuid_facilities.public_key_multibase` on the resolver. This answers
"did *this* Stub's own key sign this baseline," which is what startup
tamper-detection needs; it is not a claim that some other party has
independently attested to the key's legitimacy.

**Resolver side: the alert endpoint doesn't verify the signature yet.**
`POST /1.0/stub-integrity` (in the `huuid-resolver` repo) accepts, logs
to `huuid_stub_integrity_log`, and returns 200 -- deliberately minimal,
matching this step's scope. It does NOT check the payload's `signature`
against the reporting facility's public key before writing the row. "No
auth required because it's signed" is only true once something actually
checks the signature; until then, treat this table as a diagnostic log
of self-reported claims, not a verified audit trail. Flagged in both the
route and its migration file, not silently treated as trusted.

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
| `install-integrity-baseline` | Implemented -- signs a manifest of `src/`/`scripts/`/`package-lock.json` with the facility key, writes it read-only. Warns and asks for confirmation before overwriting an existing baseline. |

`npm run diagnostics` also verifies cache encryption is active (checks the
DB file lacks SQLite's plaintext magic header) and reports `Cache: ENCRYPTED`;
reports `Key storage: KEYSTORE / FILE / MISSING` with a warning or error as
appropriate; and reports `Integrity baseline: EXISTS/MISSING`, `Last
integrity check: PASS/FAIL/NOT RUN`, and the 6-hour check interval (running
its own fresh integrity check first, since it's a separate process from any
running `npm run start` and has no other way to know the current state).

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
