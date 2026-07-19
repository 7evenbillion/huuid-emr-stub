import { Entry } from '@napi-rs/keyring';
import { execFileSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

/**
 * Duplicated (not imported) from facility-key.ts's KEYRING_SERVICE/
 * KEYRING_ACCOUNT deliberately -- facility-key.ts needs to import
 * attemptKeytarMigration from this module, so importing these two
 * constants back from facility-key.ts would create a circular import.
 * Two string literals are cheaper and safer to keep in sync than a cycle
 * between the two modules that handle key storage.
 */
const KEYRING_SERVICE = 'huuid-emr-stub';
const KEYRING_ACCOUNT = 'facility-private-key';

/**
 * keytar's Windows target format was "service/account" -- confirmed against
 * a real keytar-written credential (see README's migration section for how
 * this was verified, including the reasoning for NOT using
 * @napi-rs/keyring's own Entry.withTarget(): it was tested against that
 * real credential and found to be broken for password round-tripping on
 * this platform -- even a pure self-write-then-read using withTarget alone,
 * no cross-library involvement, returned an empty string. That is a bug in
 * the npm package on Windows, not a target-string mismatch, and ruled out
 * building the migration on top of it.
 */
const LEGACY_KEYTAR_TARGET = 'huuid-emr-stub/facility-private-key';
const CRED_TYPE_GENERIC = 1;

/*
 * TECHNICAL DECISION — DO NOT SIMPLIFY
 *
 * We use raw Win32 API calls (advapi32.dll CredRead/CredDelete)
 * via PowerShell Add-Type P/Invoke instead of any npm package.
 *
 * Three approaches were evaluated and rejected before this:
 *
 * 1. @napi-rs/keyring Entry.withTarget()
 *    REJECTED: Bug on Windows. withTarget() returns an empty
 *    string even when writing and reading back a credential
 *    using the same call in the same process. Confirmed not
 *    a naming issue — a self-consistency write/read test
 *    with no keytar involvement also returned empty.
 *    Do not use withTarget() for migration reads on Windows.
 *
 * 2. PowerShell Get-StoredCredential cmdlet
 *    REJECTED: Not a built-in Windows cmdlet. Ships in the
 *    CredentialManager PowerShell module which is not
 *    installed by default on Windows. Cannot be relied upon
 *    at clinic deployment sites.
 *
 * 3. Direct advapi32.dll P/Invoke (CURRENT APPROACH)
 *    CHOSEN: Ships with every Windows installation.
 *    Zero additional dependencies. Same underlying Win32 API
 *    that both keytar and @napi-rs/keyring call internally.
 *    Verified working against a real keytar-written credential
 *    byte-for-byte. This is the only approach that worked.
 *
 * If you are tempted to replace this with a cleaner-looking
 * npm package call or PowerShell cmdlet, re-read the above
 * before doing so. The complexity is load-bearing.
 */

/**
 * Raw P/Invoke to advapi32.dll's CredRead/CredDelete via PowerShell's
 * Add-Type -- this is the same underlying Win32 API both keytar's native
 * addon and keyring-rs's Windows backend call internally, so it reads
 * exactly what either of them wrote, faithfully. No extra npm package or
 * PowerShell module required (Add-Type/P/Invoke ships with every Windows
 * PowerShell). The `Comment`/`FILETIME` field types across .NET/PowerShell
 * versions occasionally vary, so `LastWritten` is read as a plain `long`
 * here rather than the FILETIME struct -- offsets still line up correctly
 * because it's the same size, and this script never reads that field.
 *
 * CredentialBlob is decoded as UTF-8, verified empirically against a real
 * keytar-written credential (byte-for-byte match) -- decoding as UTF-16,
 * which would be the more "native Windows" assumption, produced garbage,
 * confirming keytar's Windows addon writes the password as raw UTF-8 bytes
 * rather than converting to UTF-16LE.
 */
const CRED_SCRIPT = String.raw`
param([string]$Action, [string]$Target)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NativeCred {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CredFree(IntPtr cred);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredDelete(string target, int type, int flags);
}
"@

if ($Action -eq 'Read') {
    $credPtr = [IntPtr]::Zero
    $ok = [NativeCred]::CredRead($Target, 1, 0, [ref]$credPtr)
    if (-not $ok) {
        Write-Output "NOTFOUND"
        exit 0
    }
    $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type][NativeCred+CREDENTIAL])
    $bytes = New-Object byte[] $cred.CredentialBlobSize
    [System.Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $cred.CredentialBlobSize)
    [NativeCred]::CredFree($credPtr) | Out-Null
    <#
     TECHNICAL DECISION — DO NOT CHANGE ENCODING

     Decode credential bytes as UTF-8, not UTF-16LE.

     Windows Credential Manager natively stores blobs as UTF-16LE.
     keytar deviates from this convention and stores values as UTF-8.
     Decoding as UTF-16LE produces garbage bytes, not the key.

     This was confirmed against a real keytar-written credential:
     - UTF-16LE decode: garbage, JWT signing fails
     - UTF-8 decode: correct key bytes, JWT accepted by live resolver

     This only affects reading credentials written by keytar.
     Credentials written by @napi-rs/keyring use a different
     target string and are read by the normal keyring API,
     not by this migration function.

     Do not change this to UTF-16LE. It will silently corrupt
     the migrated key and lock the facility out of their records.
    #>
    $value = [System.Text.Encoding]::UTF8.GetString($bytes)
    Write-Output $value
} elseif ($Action -eq 'Delete') {
    $ok = [NativeCred]::CredDelete($Target, 1, 0)
    if ($ok) { Write-Output "DELETED" } else { Write-Output "FAILED" }
} else {
    Write-Output "UNKNOWN_ACTION"
}
`;

function runCredScript(action: 'Read' | 'Delete', target: string): string | null {
  const scriptPath = join(tmpdir(), `huuid-cred-${randomUUID()}.ps1`);
  try {
    writeFileSync(scriptPath, CRED_SCRIPT, 'utf8');
    const output = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, '-Action', action, '-Target', target],
      { encoding: 'utf8', timeout: 5000, windowsHide: true }
    );
    // PowerShell's stdout can carry a leading UTF-8 BOM depending on host
    // configuration -- strip it so string comparisons against "NOTFOUND"
    // and the recovered value itself are exact.
    return output.replace(/^﻿/, '').trim();
  } catch {
    return null; // PowerShell unavailable, timed out, or errored -- migration is best-effort, never blocks startup
  } finally {
    try {
      unlinkSync(scriptPath);
    } catch {
      // best-effort cleanup
    }
  }
}

let migrationOutcome: 'migrated' | 'not_found' | 'not_attempted' | 'verify_failed' = 'not_attempted';

export function getMigrationOutcome(): typeof migrationOutcome {
  return migrationOutcome;
}

/**
 * Windows-only (Step 3). Looks for a facility key stored under keytar's
 * legacy target string; if found, writes it to the current
 * @napi-rs/keyring location, verifies the write, then deletes the legacy
 * credential. Returns the raw key bytes on success so the caller can use
 * them immediately without a second round trip through the keystore.
 *
 * Never throws -- every failure mode (PowerShell unavailable, nothing to
 * migrate, write verification failure) results in `null`, and the caller
 * falls through to its normal "no key found" handling.
 */
export async function attemptKeytarMigration(): Promise<{ bytes: Buffer } | null> {
  if (process.platform !== 'win32') {
    migrationOutcome = 'not_attempted';
    return null;
  }

  const legacyValue = runCredScript('Read', LEGACY_KEYTAR_TARGET);
  if (!legacyValue || legacyValue === 'NOTFOUND' || legacyValue === 'UNKNOWN_ACTION') {
    migrationOutcome = 'not_found';
    return null;
  }

  const entry = new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);
  entry.setPassword(legacyValue);

  const verify = entry.getPassword();
  if (verify !== legacyValue) {
    migrationOutcome = 'verify_failed';
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'keytar_migration_verify_failed',
        message:
          'Read a legacy keytar credential but the value did not verify after writing it to the current keystore. Not deleting the legacy credential.',
        timestamp: new Date().toISOString(),
      })
    );
    return null;
  }

  const deleteResult = runCredScript('Delete', LEGACY_KEYTAR_TARGET);
  const legacyDeleted = deleteResult === 'DELETED';

  migrationOutcome = 'migrated';
  console.log(
    JSON.stringify({
      level: 'info',
      event: 'keytar_migration_complete',
      message: 'Migrated facility key from legacy keytar store to current keyring store.',
      legacyCredentialDeleted: legacyDeleted,
      timestamp: new Date().toISOString(),
    })
  );

  return { bytes: Buffer.from(legacyValue, 'base64url') };
}
