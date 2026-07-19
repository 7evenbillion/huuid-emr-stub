/**
 * Generates a systemd unit file and prints the commands to install it. Does
 * NOT install or enable it itself -- that requires root, which this script
 * should not silently assume it has.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { userInfo } from 'node:os';

if (process.platform === 'win32') {
  console.error('install-systemd is for Linux. Use install-service on Windows.');
  process.exit(1);
}

const repoRoot = resolve(import.meta.dirname, '..');
const nodeExe = process.execPath;
const tsxBin = resolve(repoRoot, 'node_modules', '.bin', 'tsx');
const entryPath = resolve(repoRoot, 'src', 'server.ts');
const user = userInfo().username;

const unit = `[Unit]
Description=HUUID EMR Stub Middleware
After=network-online.target

[Service]
Type=simple
User=${user}
WorkingDirectory=${repoRoot}
ExecStart=${nodeExe} ${tsxBin} ${entryPath}
Restart=on-failure
RestartSec=5
EnvironmentFile=${repoRoot}/.env

[Install]
WantedBy=multi-user.target
`;

mkdirSync(resolve(repoRoot, 'service'), { recursive: true });
const unitPath = resolve(repoRoot, 'service', 'huuid-emr-stub.service');
writeFileSync(unitPath, unit);

console.log(`Unit file written to ${unitPath}`);
console.log('');
console.log('To install and enable it, run:');
console.log('');
console.log(`  sudo cp ${unitPath} /etc/systemd/system/huuid-emr-stub.service`);
console.log('  sudo systemctl daemon-reload');
console.log('  sudo systemctl enable --now huuid-emr-stub');
console.log('');
console.log('This script only generates the unit file -- it does not install it itself,');
console.log('since that requires root, which this process should not silently assume.');
