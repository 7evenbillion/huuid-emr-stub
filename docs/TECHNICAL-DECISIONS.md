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
