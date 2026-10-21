'use strict';

const fs = require('node:fs');
const path = require('node:path');

const packageRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(packageRoot, '..');
const source = path.join(repoRoot, 'src', 'WinSecHunter');
const target = path.join(packageRoot, 'module');

if (!fs.existsSync(path.join(source, 'WinSecHunter.psd1'))) {
  throw new Error(`module source not found: ${source}`);
}

fs.rmSync(target, { recursive: true, force: true });
fs.cpSync(source, target, { recursive: true });
fs.copyFileSync(path.join(repoRoot, 'LICENSE'), path.join(packageRoot, 'LICENSE'));

console.log(`prepared module payload from ${source}`);
