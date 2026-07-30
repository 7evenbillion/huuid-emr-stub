# HUUID EMR Stub — Technical Decisions

This document records non-obvious technical decisions
and the reasons behind them. Before simplifying or
replacing any of the patterns below, read the relevant
section in full.

---

## 1. SQLCipher package: @signalapp/sqlcipher not @journeyapps/sqlcipher

**Decision:** Use @signalapp/sqlcipher.

**Why not @journeyapps/sqlcipher:**
@journeyapps/sqlcipher has no Windows build path.
Confirmed by their own README and a failed install
attempt. Since pilot clinic machines run Windows,
this was a deployment blocker, not a dev preference.

**Why @signalapp/sqlcipher:**
Verified working Windows prebuild. Used by Signal
Desktop in production on Windows, Mac, and Linux.
Same underlying SQLCipher library as all alternatives.

**License note:** AGPL-3.0. Acceptable because the
HUUID Stub is open source (public GitHub repo).
AGPL requires source availability on distribution,
which is already satisfied.

---

## 2. Encryption algorithm: AES-256-CBC not AES-256-GCM

**Decision:** AES-256-CBC + HMAC-SHA512 (SQLCipher default).

**What the spec says:** HUUID-EMR-STUB-v0.1.2.docx
specifies AES-256-GCM. This is a known spec/
implementation variance, documented here.

**Why not GCM:**
SQLCipher has no GCM mode. The pragma
"PRAGMA cipher = 'aes-256-gcm'" is silently accepted
but ignored. The actual algorithm remains AES-256-CBC.
Confirmed empirically: PRAGMA cipher always reports
'aes-256-cbc' regardless of what was set.

**Why CBC + HMAC is acceptable:**
AES-256-CBC + HMAC-SHA512 provides encryption plus
authentication — the same two properties that GCM
provides, via a different construction. This is what
Signal, WhatsApp, and VeraCrypt use for at-rest
encryption. It is not a weaker choice.

**Action required before pilot launch:**
Update HUUID-EMR-STUB-v0.1.2.docx to reflect
AES-256-CBC + HMAC-SHA512 rather than AES-256-GCM.

---

## 3. OS keystore package: @napi-rs/keyring not keytar

**Decision:** Use @napi-rs/keyring.

**Why not keytar:**
keytar is archived and unmaintained (no releases
for over one year). @napi-rs/keyring is the
community-recommended Rust-based replacement with
identical OS store support on Windows, Mac, Linux.

**Interoperability warning:**
keytar and @napi-rs/keyring use different credential
target strings on Windows:
- keytar: "huuid-emr-stub/facility-private-key"
- @napi-rs/keyring: "facility-private-key.huuid-emr-stub"
They are mutually invisible in Windows Credential Manager.
See keystore-migration.ts for the automatic migration
that handles facilities provisioned under keytar.

---

## 4. keytar migration: raw Win32 P/Invoke not npm package

**Decision:** Use advapi32.dll CredRead/CredDelete
directly via PowerShell Add-Type P/Invoke.

**Three approaches evaluated:**

@napi-rs/keyring Entry.withTarget() — REJECTED
Bug on Windows. Returns empty string even for
self-written credentials. Confirmed not a naming
issue via self-consistency test. Do not use.

PowerShell Get-StoredCredential — REJECTED
Not a built-in cmdlet. Requires CredentialManager
PowerShell module, not installed by default on Windows.

Direct advapi32.dll P/Invoke — CHOSEN
Ships with every Windows installation. Zero extra
dependencies. Same Win32 API used internally by
both keytar and @napi-rs/keyring. Verified against
a real keytar credential byte-for-byte.

**Do not replace this with withTarget() or
Get-StoredCredential. Both were tested and failed.**

---

## 5. Credential encoding: UTF-8 not UTF-16LE

**Decision:** Decode keytar credentials as UTF-8.

**Why not UTF-16LE:**
Windows Credential Manager natively uses UTF-16LE.
keytar deviates from this and stores values as UTF-8.
Decoding as UTF-16LE produces garbage bytes.
Confirmed against a real keytar credential:
UTF-16LE = garbage, UTF-8 = correct key bytes,
JWT signed and accepted by live production resolver.

**Scope:** Applies only to reading credentials
written by keytar. @napi-rs/keyring credentials
are read via the normal keyring API, not this path.

**Do not change this to UTF-16LE.**

---

## 6. kdf_iter pragma: present but inert

**Decision:** Keep PRAGMA kdf_iter in code despite
being a no-op.

**Why it is a no-op:**
kdf_iter only affects SQLCipher's passphrase-based
KDF. We supply a raw HKDF-derived 32-byte key
directly, bypassing that step entirely.

**Why it is kept:**
Fidelity to the spec. Harmless. Removing it would
require explaining why it was removed, which is
more confusing than leaving it with this comment.

---

## 7. Baseline read-only: attrib +r, not icacls /deny

**Decision:** Windows read-only uses the classic file
ATTRIBUTE (`attrib +r`), not an NTFS ACL deny.

**Why not icacls /deny Everyone:W:**
Literally what the spec named. Tested first. It
blocks READS too, not just writes -- Node's
readFileSync failed with EPERM even though the ACL
only listed a write deny. That would have broken
integrity-check.ts, which must read baseline.hmac on
every startup. Confirmed by testing, not assumed.

**Why attrib +r:**
The standard Windows equivalent of chmod 444. Tested:
blocks writes, leaves reads fully intact. `attrib -r`
cleanly restores full access for legitimate baseline
updates (Step 1.7's overwrite-with-confirmation flow).

**Do not switch this to an icacls deny approach.**

---

## 8. Integrity manifest key: HKDF-derived, not a fixed/public key

**Decision:** The HMAC-SHA256 manifest key is derived
via HKDF-SHA256 over the facility private key, salt
`{facilityDid}:integrity-baseline-v1`, info
`huuid-integrity-key` -- domain-separated from the
cache encryption key (P1), which uses a different
salt/info pair from the same root secret.

**Why this isn't strictly load-bearing:**
The manifest's real tamper-evidence comes from the
EdDSA signature over the hash (facility private key,
Ed25519), not from the HMAC key being secret. An
attacker who modifies files can recompute a new
manifest hash with any key; what they cannot do is
produce a valid EdDSA signature over it.

**Why it's kept anyway:**
Ties the raw manifest fingerprint to a specific
facility rather than leaving it a plain, universally
comparable SHA-256. Reuses the same HKDF-from-facility-
key pattern already established for the cache key,
rather than introducing a new key-management approach
for one feature.

---

## 9. Startup tamper check -- history and current state

**Original decision (superseded, see §10):** An
integrity violation was logged and alerted, but the
Stub still started. Deferred from the spec's "refuse
to start if tampered," over the risk of bricking a
clinic machine on a stale baseline. **This is now
closed -- see §10 for the grace-period/override
mechanism that replaced it.** Left here for history;
do not read this section as describing current
behavior.

**Real gotcha found while testing this, still
current:** `git checkout`/`git pull` on Windows can
trip a false-positive violation. Restoring a file via
`git checkout` produced CRLF line endings (Windows'
core.autocrlf) even though the text was identical to
what the baseline was computed from (LF) -- a
byte-different file the manifest correctly flagged as
changed. Re-running install-integrity-baseline after
any git pull that could touch line endings is a real
operational step, not just after intentional edits.

**Resolver-side signature verification gap: also now
closed, see §11.**

---

## 10. Startup grace period + emergency override (Gap 1 closure)

**Decision:** A startup integrity violation now leads
to a 60-second countdown (printed every 10s) and
`process.exit(1)`, UNLESS `HUUID_INTEGRITY_OVERRIDE=1`
is set at process launch, in which case the Stub
starts immediately with a logged warning, a second
alert (`override: true`), and `/health` carrying
`integrity_override_active: true` plus a `warning`
field on every response for the life of that process.

**Why this design specifically:**
The override is read ONCE, at startup -- not polled
during the countdown. "Restart within 60 seconds"
means a NEW process launch with the var already set,
not a live process somehow observing an external env
change mid-countdown. This is why a failing process
just counts down to its own death regardless of what
happens elsewhere: the countdown's only job is to make
the failure visible long enough (with periodic
reminders) for an operator to notice, decide, and
relaunch -- not to wait for a live signal.

**Why scoped to startup only, not the 6-hour periodic
recheck:** Forcibly killing a server that has been
running fine and serving patients for hours, on a
LATER recheck, is a materially different (and worse)
risk than gating startup -- not requested, not built.
`runIntegrityCheck()` (the periodic recheck) keeps its
original soft-fail behavior unchanged;
`enforceStartupIntegrity()` (new, startup-only) wraps
it with the countdown/exit/override logic.

**Do not make the periodic recheck also refuse to
continue running without a fresh design discussion --
that changes the risk calculus this section describes.**

---

## 11. Resolver signature verification (Gap 2 closure)

**Decision:** POST /1.0/stub-integrity now verifies
the payload's EdDSA `signature` against the claimed
facility's public key (huuid_facilities
.public_key_multibase) before logging anything.
Unknown facility -> 403, not logged. Invalid/missing
signature -> 401, not logged. Verified -> logged with
signature_verified: true, 200.

**Why NOT the Break-Glass requestSignature pattern:**
bg-request-signature.ts verifies SHA-256(canonical_json
(body_minus_signature)) -- a different construction.
The Stub's integrity-manifest.ts signs the raw UTF-8
bytes of manifestHash directly, no pre-hash. Verifying
with the Break-Glass pattern would make every genuine
signature fail. New lib/stub-integrity-signature.ts
matches the Stub's actual signing exactly:
crypto.verify(null, Buffer.from(manifestHash, 'utf8'),
publicKey, signature).

**Extra gap found and fixed, not in the stated scope:**
Gap 2's own combined-testing requirement (an override
alert from Gap 1 must be "logged with override: true")
needed a column that didn't exist and wasn't in the
specified migration. Migration 008 adds it. Per the
standing rule -- new gaps get fixed, not documented
away -- this was added rather than silently dropping
the override flag on the floor.

**Do not remove the facility lookup or signature
check to "simplify" this endpoint. That is Gap 2,
reopened.**

---

## 12. QR verification (tier 4): .json over .pem, and the shared-key honesty note

**Decision:** `HUUID_RESOLVER_PUBLIC_KEY_PATH` defaults to
`./keys/resolver-public-key.json`, not the `.pem` HUUID-
EMR-STUB-v0.1.2.docx Section 4 step 5 names.

**Why:** The resolver's `GET /1.0/resolver-public-key`
returns `{ publicKeyMultibase, keyId, validFrom,
algorithm }`. `keyId` and `validFrom` are consumed
directly by `/health` and `/debug/resolver` -- a bare
PEM has no field for either. Same treatment as the
AES-CBC-vs-GCM spec/implementation variance (§2):
documented rather than silently done.

**Real bug caught by testing this, not by inspection:**
`.env` and `config-template.env` both still had the
OLD `.pem` path hardcoded from when this variable was
first added (before QR verification existed), silently
overriding the new default in `config.ts`. The first
`npm run download-keys` run wrote to
`keys/resolver-public-key.pem` instead of `.json` --
caught by checking the actual file on disk rather than
trusting the script's own "success" printout. Both env
files were wrong in the same way; fixing only `config.ts`
would not have fixed the bug.

**The single most important honesty note in this
build step:** `GET /1.0/resolver-public-key` and every
test token signed for this step's DoD both use
`HUUID_TEST_FACILITY_JWK` -- the only signing keypair
that exists anywhere in this shared build environment.
Verifying a test-signed token against the "resolver's"
published key therefore proves the verification LOGIC
is correct (base64url/JSON parsing, version check, exp
handling, EdDSA verification, tamper rejection) but
proves NOTHING about signer/verifier key separation,
because there is no separation in this test setup --
issuer and verifier are, by construction, the same key.

**What production actually needs, not yet built:** a
distinct resolver-owned signing keypair, held only by
the Root Authority, used exclusively to sign patient QR
cards at enrollment -- never a facility's own key, and
never shared with JWT/ProviderJWT/Break-Glass signing
the way one test key currently stands in for all of
them across this whole session's build steps. Nothing
in either repo issues a real QR card yet either --
verification only. Both are pre-pilot items.

**Do not read a passing DoD 3-5 (valid/tampered/expired
token tests) as proof that key separation works. It
proves the opposite question was answered correctly --
"does this code verify a signature correctly" -- not
"can a facility forge a card," which is unfalsifiable
until the resolver has its own key.**

## 13. Module isolation (P5): built last, and why raw key access is confined to one module, not just JWT signing

HUUID-EMR-STUB-v0.1.2.docx Section 2 P5 specifies that
each module receives only the secrets it needs, that no
module reads `process.env` directly, and that
`src/server.ts` (the orchestrator) loads every secret
once at startup and hands each module its own narrow
slice.

**Why this was built last, not first.** P5 requires
knowing the full module dependency graph before it can
be designed correctly -- which modules exist, which of
them legitimately need which secret, and which pieces of
logic that look like they belong to one module actually
touch raw key material on another module's behalf.
Building P5 before P1-P4 and QR verification existed
would have meant guessing at that graph and reworking it
on every subsequent build step as new modules
(`integrity-check.ts`, `integrity-manifest.ts`,
`resolver-key.ts`) were added. Building it last, once the
graph was stable, meant doing this restructuring exactly
once.

**Raw key confinement goes beyond JWT signing.** The doc's
wording for `facility-key.ts` ("signs JWTs internally...
never exposes raw key bytes to other modules") describes
one use of the private key, but this codebase has three:
signing a facility JWT (`resolver-client.ts`), signing/
verifying an integrity manifest hash (`integrity-check.ts`
via `integrity-manifest.ts`), and deriving two unrelated
symmetric keys via HKDF (the SQLCipher cache key and the
manifest's HMAC key -- formerly `cache-key.ts` and a
private function inside `integrity-manifest.ts`). All
three needed raw private-key bytes as input. Splitting
"raw key access" across three modules that each touched
it a little would have satisfied the letter of "one
signing module" while leaving raw bytes reachable from
three places instead of one. Instead, every one of these
operations was moved into `facility-key.ts` itself, which
now exports only derived outputs -- a signed JWT string
(`signFacilityJWT`), a signature (`signManifestHash`), a
boolean (`verifyManifestSignature`), and derived symmetric
keys (`deriveCacheEncryptionKeyHex`,
`deriveManifestHmacKey`). `cache-key.ts` no longer exists;
its one function moved here. `getFacilityPrivateKeyRaw`
and `buildEd25519KeyObjectFromRaw` are no longer exported
at all -- it is now a compile error, not just a convention,
for another module to import raw key access from this one.

**Precompute-once vs. signing-reference, and why they
differ.** `cache.ts` receives a single precomputed
`cacheEncryptionKeyHex` string via `initCacheModule()`,
called once at startup -- the cache key never changes for
the life of the process, so there is nothing to gain from
letting `cache.ts` call back into `facility-key.ts` itself.
`integrity-check.ts`, by contrast, imports
`signManifestHash`/`verifyManifestSignature` from
`facility-key.ts` as ordinary function references and
calls them fresh on every check (startup, and every 6
hours) -- a manifest hash is computed over file contents
that can legitimately change between checks, so there is
no fixed value to precompute. Both patterns satisfy "never
receives the raw key"; which one applies depends on
whether the secret-touching operation's output is constant
or must be recomputed per call.

**Scope: `server.ts` and `scripts/*.ts` are orchestrators,
not the six least-privilege modules.** The doc's pattern
text names `src/server.ts` as *the* orchestrator. This
codebase has several other independent entry points
(`diagnostics.ts`, `test-connection.ts`,
`install-integrity-baseline.ts`, `secure-keys.ts`,
`download-keys.ts`, `generate-local-secret.ts`,
`check-permissions.ts`) that each run as their own
one-shot Node process via `npm run <script>`, not as code
imported into the running server. Each of these legitimately
calls `loadConfig()` once, for the same reason `server.ts`
does -- they are bootstrapping their own process, not
consuming a secret an orchestrator handed them. `grep`
confirms zero `loadConfig()`/`process.env.HUUID_` usage in
every module that IS imported by other modules for runtime
logic (`cache.ts`, `facility-key.ts`, `resolver-client.ts`,
`local-auth.ts`, `integrity-check.ts`,
`integrity-manifest.ts`, `resolver-key.ts`, `status.ts`,
`qr-verifier.ts` -- the last of these needed no changes at
all, it already took `resolverPublicKeyBytes` as a plain
function argument from day one). `resolver-key.ts` and
`status.ts` were not named explicitly in the doc's P5 list
(they handle a public key path and display-only facility
identifiers, neither a secret in the threat-model sense)
but were brought under the same `initXModule()` pattern
anyway, so "grep confirms zero hits" is a whole-codebase
guarantee, not one with quiet carve-outs for the modules
the doc happened not to name.

**Verified, not asserted.** `npm run diagnostics` computes
`Module isolation: ACTIVE` by actually clearing every
`HUUID_`-prefixed `process.env` key after this script's own
init sequence completes, then checking that none remain --
the same clearing `server.ts` performs before it starts
accepting requests. If a future change reintroduces a
direct `process.env` read in one of the nine library
modules, or the clearing loop itself regresses, this
reports `INACTIVE` and lists the leaked keys, rather than
printing a fixed string regardless of actual state.

---

## 14. QR token wire format, fixed against the real resolver signer (Phase 2A cross-repo compatibility fix)

**Context.** §12 noted "nothing in either repo issues a real
QR card yet -- verification only," with `qr-verifier.ts`'s
wire-format assumptions never cross-checked against an
actual resolver-side signer. That changed this session:
huuid-resolver's `lib/qr-token.ts` (Phase 2A, "emergency
medical profile") now builds and signs real offline tokens
at enrollment, and `/enroll/card`'s printed QR now encodes
one. Running a real signed token from that code through this
Stub's `verifyQRToken()` surfaced three real mismatches, all
now fixed in `qr-verifier.ts`. This section documents the
correct wire format going forward; treat huuid-resolver's
`lib/qr-token.ts` as the source of truth if the two ever
drift again -- this Stub is the consumer, not the spec owner.

**Mismatch 1 -- compression.** The resolver
`zlib.deflateRawSync()`-compresses the signed JSON object
before base64url-encoding it (keeps the printed QR small).
The old `verifyQRToken()` base64url-decoded straight to a
JSON string with no inflate step -- every real token failed
at `JSON.parse` with "Malformed QR token." Fixed: decode
base64url -> `zlib.inflateRawSync()` -> `JSON.parse`.

**Mismatch 2 -- signing target.** The resolver signs
`SHA-256(canonical_json(payload))` (same hash-before-sign
convention as `lib/bg-request-signature.ts`'s Break-Glass
verification). The old `verifyQRToken()` verified the
EdDSA signature against the raw canonical JSON string
directly, with no SHA-256 step -- this made every signature
fail regardless of the compression fix. This is the one that
would have been hardest to catch by inspection alone (both
sides "looked" like they used the same
`canonicalJsonStringify`, and in isolation each function's
own logic was internally consistent); it only surfaced by
actually running a real signed token through the verifier.
Fixed: hash `signTarget` with SHA-256 before calling
`crypto.verify`.

**Mismatch 3 -- payload shape.** The old schema had `ca:
string[]` (bare allergy names) and no fields at all for
medications, chronic conditions, organ donor, implanted
devices, pregnancy status, primary facility, or contra-
indications. The real payload's `ca` is an array of `{s, r?,
sv?}` objects, and six more top-level fields exist that
`qrTokenSchema` didn't recognize. Zod's default parsing mode
silently drops unrecognized keys rather than erroring, so
this wouldn't have thrown -- it would have silently discarded
every one of these fields, including `nd` (do-not-give /
severity `'never'` contraindications), the single most
safety-critical field on the card. Fixed: schema now
recognizes all real fields; `QRVerificationResult` exposes
`allergies`/`medications`/`chronicConditions`/`organDonor`/
`implantedDevices`/`pregnancyStatus`/`primaryFacilityName`/
`doNotGive`, while `criticalAllergies: string[]` is kept
(derived as `ca[].s`) so `cache.ts`, `server.ts`, and
`/debug/resolver`'s HTML table don't need any changes.

**Why no `.default()` on the new optional schema fields.**
`z.array(...).default([])` would inject a key (e.g. `cc: []`)
into `parsed.data` for a field the resolver never included in
what it actually signed, and `fieldsToVerify` is built by
destructuring `sig` off the *parsed* token -- so a `.default()`
would make the re-signed canonical JSON diverge from the
original signed bytes and every token with an omitted field
would fail verification. `.optional()` alone preserves
"absent stays absent" through the parse.

**The full token format (huuid-resolver `lib/qr-token.ts`,
verified against by this Stub's `qr-verifier.ts`):**

```
QR string := base64url( deflateRaw( JSON.stringify({
  v:      1,                                  // token version
  huuid:  "did:huuid:<cc>:<id>",
  bt?:    "O-",                               // blood type, omitted if unset/'unknown'
  ca?:    [{ s: "Penicillin", r?: "...", sv?: "..." }],  // allergies
  cm?:    [{ n: "Metformin", d?: "500mg", f?: "..." }],  // medications
  cc?:    ["Diabetes (Type 2)", ...],         // chronic conditions
  od?:    "yes" | "no" | "unknown",           // organ donor
  id?:    ["Pacemaker", ...],                 // implanted devices
  preg?:  "pregnant" | "not_pregnant" | "unknown",
  pf?:    "Korle Bu Teaching Hospital",       // primary facility name
  nd?:    [{ s: "Aspirin", r?: "G6PD deficiency" }],  // DO NOT GIVE -- severity:'never' only
  exp:    1942883961,                         // epoch seconds
  iss:    "huuid-self-enrolled-v1",
  sig:    "<base64url EdDSA signature>",
}) ) )
```

`sig` = `base64url( Ed25519_sign( resolver_private_key, SHA256(canonical_json(payload_without_sig)) ) )`,
where `canonical_json` recursively sorts object keys
(`canonicalJsonStringify`, duplicated byte-for-byte in both
repos -- see the function of the same name in this file and
in huuid-resolver's `lib/canonical-json.ts`). Every field
except `v`, `huuid`, `exp`, `iss`, `sig` is omitted entirely
(not `null`) when the patient hasn't provided that data.

**Verified this session:** a real token built and signed by
`lib/qr-token.ts` (blood type, 2 allergies including a
life-threatening one, 1 medication, 2 chronic conditions,
organ donor, 1 implanted device, primary facility, 2
contraindications including one `'never'`), run through the
fixed `verifyQRToken()` with the live production resolver's
actual published public key (`GET /1.0/resolver-public-key`,
downloaded fresh, not reused from an old cache): decodes,
signature verifies, all fields decode correctly including
`doNotGive: [{ substance: "Aspirin", reason: "G6PD
deficiency" }]`. A tampered token (corrupted trailing bytes)
is correctly rejected with no health data returned. `npm run
typecheck` passes with no changes needed in `server.ts`,
`cache.ts`, or `qr-verification-log.ts`.

**Still true, unchanged by this fix (see §12's honesty
note):** the signer is still `HUUID_TEST_FACILITY_JWK`, the
same interim key `GET /1.0/resolver-public-key` has always
published -- huuid-resolver's own
`docs/HANDOFF.md` §18.11 and `docs/TECHNICAL-DECISIONS.md`
call this **Pre-Pilot Blocker 2, still open**. §12's specific
claim that "nothing in either repo issues a real QR card yet"
is now **stale** -- huuid-resolver's `/enroll/card` does, as
of Phase 2A -- but its underlying warning (no real signer/
verifier key separation exists) is unchanged and still
correct. Do not treat a card issued today as carrying a
production-trustworthy signature.

**Do not reintroduce `.default()` on the schema's optional
fields, and do not remove the SHA-256 hash step from
`verifyQRToken()` -- both were the actual root causes here,
not stylistic choices.**

---

## 15. Token freshness: `gen`, `generatedAt`, and the expiry `warning`

**Context.** huuid-resolver added a medical-profile-update
notification feature (its own `docs/HANDOFF.md` §18.14) and
changed the QR token TTL from an undocumented 5-year default
to an explicit 90 days, adding a `gen` (generated-at, epoch
seconds) field to every token alongside `exp`.

**Decision.** `qrTokenSchema` gained `gen: z.number().optional()`
-- optional, not `.default()`, for the same reason as every
other optional field here (§14): a default would inject a key
into the re-signed canonical JSON that a token signed before
`gen` existed never had, breaking its signature verification.
`QRVerificationResult` gained two fields: `generatedAt: Date |
null` (parsed from `gen` when present) and `warning: string |
null`.

**`warning` is set to exactly `"Token expired. Medical data
may be outdated. Verify via resolver when connectivity
available."` when, and only when, `expired === true`; `null`
otherwise.** `valid` was already `true` on an expired-but-
correctly-signed token before this change -- identity
verification has never been gated on expiry in this function,
only the medical-data trust level changes. This decision just
gives that state a concrete, machine-readable explanation
instead of a bare `expired: true` a caller might not surface
to anyone. Net effect, stated the way the operator specified
it: identity verification always works; medical data has a
freshness signal; the clinician knows if data is stale; the
patient (via huuid-resolver's SMS) is prompted to refresh.

**Extra gap found and fixed while touching `server.ts`'s
`POST /qr/verify` handler for the warning-text swap, not
requested by this task specifically.** That endpoint's `200`
response only ever returned `bloodType`/`criticalAllergies` --
`doNotGive`, `allergies`, `medications`, `chronicConditions`,
`organDonor`, `implantedDevices`, and `primaryFacilityName`
have been present on `verifyQRToken()`'s return value since
§14's fix, but nothing wired them into the actual HTTP
response a clinician's system calls. DO NOT GIVE -- the single
most safety-critical field this whole file exists to surface
-- was computed correctly and then silently dropped on the
floor before it ever left the process. Fixed by adding the
full field set to all three response branches (`503` no-key,
`400` invalid, `200` valid). **Not fixed, a real follow-up**:
`cache.ts`'s `QRCacheEntry`/SQLite schema still only persists
`bloodType`/`criticalAllergies` -- extending the local DB
schema is a larger, separate change, not attempted here.

**Verified:** two real tokens built via huuid-resolver's actual
`buildQrTokenPayload`/`signQrToken` (not hand-edited payloads)
-- one with the default 90-day TTL, one with `ttlSeconds:
-3600` to produce a token already expired at signing time --
decoded through this fixed `verifyQRToken()` against the live
production resolver's public key. Fresh: `valid: true, expired:
false, warning: null, generatedAt` populated. Expired: `valid:
true, expired: true, warning: "Token expired. Medical data may
be outdated. Verify via resolver when connectivity available."`,
exact match, `generatedAt` still populated correctly. `npm run
typecheck` passes clean.

**Do not gate `valid` on `expired` in any future change here --
that was true before this task and stays true after it. An
expired token is still a genuine, unforged identity; only the
medical payload's freshness is in question.**
