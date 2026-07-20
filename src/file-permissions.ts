import { chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

/**
 * Windows: the classic read-only file ATTRIBUTE (`attrib +r`), not an NTFS
 * ACL deny. `icacls /deny Everyone:W` was tested first (install-integrity-
 * baseline's original spec) and found to block READS too, not just writes --
 * Node's readFileSync failed with EPERM even though the ACL only listed a
 * WRITE deny. `attrib +r` is the standard Windows equivalent of chmod 444:
 * verified to block writes while leaving reads fully intact. Shared here
 * because both the integrity baseline and the downloaded resolver public
 * key need the identical read-only-after-write pattern.
 */
export function setReadOnly(path: string): void {
  if (process.platform === 'win32') {
    execFileSync('attrib', ['+r', path], { stdio: 'ignore' });
  } else {
    chmodSync(path, 0o444);
  }
}

export function clearReadOnly(path: string): void {
  if (process.platform === 'win32') {
    execFileSync('attrib', ['-r', path], { stdio: 'ignore' });
  } else {
    chmodSync(path, 0o644);
  }
}
