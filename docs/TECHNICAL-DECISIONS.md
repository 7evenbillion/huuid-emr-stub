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
