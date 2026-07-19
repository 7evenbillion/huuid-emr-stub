import { Entry } from '@napi-rs/keyring';
import { existsSync, readFileSync, writeFileSync, unlinkSync, statSync } from 'node:fs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { loadConfig } from '../src/config.js';
import { rawKeyFromPem, KEYRING_SERVICE, KEYRING_ACCOUNT } from '../src/facility-key.js';

const entry = new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);

const config = loadConfig();
const pemPath = config.HUUID_FACILITY_PRIVATE_KEY_PATH;

if (!existsSync(pemPath)) {
  console.error(`No facility private key found at ${pemPath}. Nothing to secure.`);
  process.exit(1);
}

// Step 1: read the key from the file.
const pem = readFileSync(pemPath, 'utf8');
let rawBytes: Buffer;
try {
  rawBytes = rawKeyFromPem(pem);
} catch (err) {
  console.error(`Could not read the key at ${pemPath}: ${err instanceof Error ? err.message : 'unknown error'}`);
  process.exit(1);
}

// Step 2: store in the OS keystore.
const encoded = rawBytes.toString('base64url');
entry.setPassword(encoded);

// Step 3: retrieve immediately to verify storage worked.
const retrieved = entry.getPassword();

const matches =
  retrieved !== null &&
  retrieved.length === encoded.length &&
  timingSafeEqual(Buffer.from(retrieved), Buffer.from(encoded));

rawBytes.fill(0);

if (!matches) {
  // Step 5: HALT. Do not delete the .pem file.
  console.error(
    'Key verification FAILED after storing to the OS keystore -- the value read back did not match ' +
      'what was written. The .pem file has NOT been deleted. Check OS keystore access ' +
      '(Credential Manager / Keychain / libsecret) and try again.'
  );
  process.exit(1);
}

// Step 4: shred the .pem file, then delete it.
shredFile(pemPath);
unlinkSync(pemPath);

console.log('Key imported to OS keystore.');
console.log('facility-private-key.pem deleted.');

/**
 * Overwrites the file's on-disk bytes before unlinking. This defeats naive
 * undelete/recovery tools that only look at directory-entry-level deletion --
 * it does NOT guarantee the original plaintext is unrecoverable at the
 * physical storage layer. Modern SSDs (wear-leveling), copy-on-write
 * filesystems, and journaling can all retain copies of the old blocks
 * regardless of what gets written to the logical file path. Flagged here
 * rather than claimed as a stronger guarantee than it is.
 */
function shredFile(path: string): void {
  const size = statSync(path).size;
  if (size === 0) return;

  if (process.platform === 'win32') {
    // "Multi-pass overwrite" per Step 2.4 -- zeros, then random, then zeros.
    writeFileSync(path, Buffer.alloc(size, 0));
    writeFileSync(path, randomBytes(size));
    writeFileSync(path, Buffer.alloc(size, 0));
  } else {
    writeFileSync(path, Buffer.alloc(size, 0));
  }
}
