import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { loadConfig } from '../src/config.js';

const config = loadConfig();
const path = config.HUUID_LOCAL_AUTH_SECRET_PATH;

if (existsSync(path)) {
  console.log(`Secret already exists at ${path}. Delete it first if you want to regenerate.`);
  process.exit(0);
}

mkdirSync(dirname(path), { recursive: true });
const secret = randomBytes(32).toString('base64url');
writeFileSync(path, secret, { mode: 0o600 });
try {
  chmodSync(path, 0o600); // best-effort on platforms where writeFileSync's mode isn't honored (e.g. Windows)
} catch {
  // Windows ACLs don't map onto POSIX chmod bits -- this is expected there.
}

console.log(`Local-auth secret generated at ${path}.`);
console.log('Configure your EMR integration to send this value as the X-Local-Auth header.');
