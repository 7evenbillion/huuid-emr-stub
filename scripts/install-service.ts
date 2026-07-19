/**
 * Generates a Windows service definition and prints the commands to register
 * it. Does NOT run those commands itself -- registering a service requires
 * an elevated (Administrator) shell, which this script should not silently
 * assume it has.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

if (process.platform !== 'win32') {
  console.error('install-service is for Windows. Use install-systemd on Linux.');
  process.exit(1);
}

const repoRoot = resolve(import.meta.dirname, '..');
const nodeExe = process.execPath;
const scriptPath = resolve(repoRoot, 'node_modules', '.bin', 'tsx');
const entryPath = resolve(repoRoot, 'src', 'server.ts');

const wrapperBat = `@echo off
cd /d "${repoRoot}"
"${nodeExe}" "${scriptPath}" "${entryPath}"
`;

mkdirSync(resolve(repoRoot, 'service'), { recursive: true });
const wrapperPath = resolve(repoRoot, 'service', 'huuid-emr-stub.bat');
writeFileSync(wrapperPath, wrapperBat);

console.log(`Wrapper script written to ${wrapperPath}`);
console.log('');
console.log('To register as a Windows service, run the following from an Administrator prompt');
console.log('using NSSM (https://nssm.cc/) or the built-in sc.exe:');
console.log('');
console.log(`  sc.exe create HUUIDEMRStub binPath= "${wrapperPath}" start= auto`);
console.log('  sc.exe start HUUIDEMRStub');
console.log('');
console.log('This script only generates the wrapper -- it does not register the service');
console.log('itself, since that requires an elevated shell this process should not assume.');
