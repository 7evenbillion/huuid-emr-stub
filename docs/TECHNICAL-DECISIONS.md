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

## 9. Startup tamper check does not refuse to start

**Decision:** An integrity violation is logged and
alerted, but the Stub still starts. Deferred from the
spec's "refuse to start if tampered."

**Why:**
Refusing to start on any manifest mismatch risks
bricking a clinic machine over a stale baseline (e.g.
a legitimate npm update not followed by re-running
install-integrity-baseline) -- a worse outcome for
patient care than running while flagged. The alert to
the Root Authority is the load-bearing piece for this
step; `integrityViolation` is tracked and surfaced via
/health and diagnostics.

**Real gotcha found while testing this:** `git
checkout`/`git pull` on Windows can trip a
false-positive violation. Restoring a file via `git
checkout` produced CRLF line endings (Windows'
core.autocrlf) even though the text was identical to
what the baseline was computed from (LF) -- a
byte-different file the manifest correctly flagged as
changed. Re-running install-integrity-baseline after
any git pull that could touch line endings is a real
operational step, not just after intentional edits.

**Resolver-side gap, not yet closed:** POST
/1.0/stub-integrity accepts, logs, and returns 200 but
does not verify the payload's signature against the
reporting facility's public key before writing the
row. Treat huuid_stub_integrity_log as a diagnostic
log of self-reported claims for this step, not a
verified audit trail.

**Do not change either the no-refuse-to-start
behavior or the resolver's accept-without-verify
behavior without addressing both flagged gaps above
first.**
