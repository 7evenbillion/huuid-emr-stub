# HUUID EMR Stub Middleware

Local clinic integration layer. Bridges an existing EMR to the HUUID
resolver network without moving any medical data off the clinic's own
server. Governing spec: `HUUID-EMR-STUB-v0.1.2.docx` (v0.1 and v0.1.1 are
retired -- see Section 0 of that document).

This is a standalone Node.js/Express/TypeScript service, **not** part of
the Next.js resolver (`huuid-resolver`). It runs locally at each clinic.

## Status: base build (this step)

Implements the smallest working version of `verifyPatient()`, per the
5-tier resolution priority order in Section 3.1 of the spec. **Explicitly
not implemented yet** (by design, one layer at a time):

- SQLCipher cache encryption (P1)
- OS keystore for the facility private key (P2)
- Integrity baseline / HMAC monitoring (P4)
- QR card offline verification (resolution tier 4)

`npm run diagnostics` reports all of these honestly as not-yet-started.

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
| `secure-keys` | Not implemented -- deferred (OS keystore) |
| `install-integrity-baseline` | Not implemented -- deferred (HMAC monitoring) |

## Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Local system status (no external calls) |
| `POST /verify` | `X-Local-Auth` | The EMR integration surface -- calls `verifyPatient()` |
| `GET /debug/resolver` | none | Local cache contents (developer page, mirrors the resolver repo's own `/debug/resolver`) |
| `GET /debug/qr` | none | Explains QR scanning isn't built yet |
