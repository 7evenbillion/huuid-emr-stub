import { existsSync, statSync } from 'node:fs';
import { loadConfig } from '../src/config.js';

const config = loadConfig();

const targets = [
  { label: 'Local-auth secret', path: config.HUUID_LOCAL_AUTH_SECRET_PATH },
  { label: 'Facility private key', path: config.HUUID_FACILITY_PRIVATE_KEY_PATH },
  { label: 'Resolver public key', path: config.HUUID_RESOLVER_PUBLIC_KEY_PATH },
  { label: 'Cache database', path: config.HUUID_CACHE_DB_PATH },
];

let anyProblem = false;

for (const t of targets) {
  if (!existsSync(t.path)) {
    console.log(`[MISSING]  ${t.label}: ${t.path}`);
    continue;
  }
  const stat = statSync(t.path);
  const mode = (stat.mode & 0o777).toString(8);
  // POSIX mode bits are informational-only on Windows (ACLs govern access
  // there instead) -- this still surfaces the value for operators on Linux/macOS.
  const worldOrGroupReadable = (stat.mode & 0o077) !== 0;
  if (worldOrGroupReadable && process.platform !== 'win32') {
    console.log(`[WARN]     ${t.label}: ${t.path} (mode ${mode} -- readable beyond owner)`);
    anyProblem = true;
  } else {
    console.log(`[OK]       ${t.label}: ${t.path} (mode ${mode})`);
  }
}

if (anyProblem) {
  console.log('\nSome files are more permissive than they should be. Restrict them to the owner only.');
  process.exit(1);
}
console.log('\nAll present files have acceptable permissions.');
