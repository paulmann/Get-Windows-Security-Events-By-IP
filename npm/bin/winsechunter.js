#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const pkg = require('../package.json');

const manifest = path.join(__dirname, '..', 'module', 'WinSecHunter.psd1');
const pwsh = process.env.WINSECHUNTER_PWSH || (process.platform === 'win32' ? 'pwsh.exe' : 'pwsh');

function fail(message, code = 2) {
  console.error(`winsechunter: ${message}`);
  process.exit(code);
}

function usage() {
  console.log(`winsechunter ${pkg.version} — incident-response toolkit for Windows security events

Usage:
  winsechunter help [Cmdlet]           Show the toolkit reference or one cmdlet
  winsechunter catalog [--profile X]   List catalogued events
  winsechunter sweep <ip|cidr> [--last-hours N] [--json]
                                       Collect events referencing an address
  winsechunter --version               Print the version

Requirements:
  PowerShell 7.6+ (pwsh) in PATH. Collection requires Windows and, for the
  Security log, an elevated session. Analysis and reporting run on any OS.

Full functionality lives in the PowerShell module:
  Import-Module <package>/module/WinSecHunter.psd1
  Show-WinSecHunterHelp

Docs: https://github.com/paulmann/Get-Windows-Security-Events-By-IP`);
}

function runPowerShell(script, extraEnv = {}) {
  if (!fs.existsSync(manifest)) {
    fail('module payload is missing; reinstall the package', 3);
  }
  const result = spawnSync(
    pwsh,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
    {
      stdio: 'inherit',
      env: { ...process.env, WSH_MANIFEST: manifest, ...extraEnv },
    },
  );
  if (result.error) {
    if (result.error.code === 'ENOENT') {
      fail('PowerShell 7.6+ (pwsh) was not found in PATH', 4);
    }
    fail(result.error.message, 4);
  }
  process.exit(result.status === null ? 1 : result.status);
}

const argv = process.argv.slice(2);
if (argv.length === 0) {
  usage();
  process.exit(0);
}

const command = argv[0];

if (command === '--version' || command === '-v' || command === 'version') {
  console.log(pkg.version);
  process.exit(0);
}

if (command === 'help') {
  const cmdlet = argv[1] || '';
  if (cmdlet && !/^[A-Za-z]+-WinSec[A-Za-z]+$/.test(cmdlet)) {
    fail(`invalid cmdlet name: ${cmdlet}`);
  }
  runPowerShell(
    'Import-Module $env:WSH_MANIFEST -Force; ' +
    'if ($env:WSH_CMDLET) { Show-WinSecHunterHelp -Cmdlet $env:WSH_CMDLET -PassThru } ' +
    'else { Show-WinSecHunterHelp -PassThru }',
    { WSH_CMDLET: cmdlet },
  );
}

if (command === 'catalog') {
  let profile = '';
  const index = argv.indexOf('--profile');
  if (index > 0) { profile = argv[index + 1] || ''; }
  if (profile && !/^[A-Za-z]+$/.test(profile)) { fail(`invalid profile: ${profile}`); }
  runPowerShell(
    'Import-Module $env:WSH_MANIFEST -Force; ' +
    '$items = if ($env:WSH_PROFILE) { Get-WinSecEventCatalog -Profile $env:WSH_PROFILE } else { Get-WinSecEventCatalog }; ' +
    '$items | Format-Table EventId, Log, Name, Category, Importance -AutoSize',
    { WSH_PROFILE: profile },
  );
}

if (command === 'sweep') {
  const target = argv[1];
  if (!target) { fail('usage: winsechunter sweep <ip|cidr> [--last-hours N] [--json]'); }
  if (!/^[0-9A-Fa-f:./]+$/.test(target)) { fail(`invalid IP or CIDR: ${target}`); }

  let hours = 24;
  let json = false;
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--json') { json = true; }
    else if (argv[i] === '--last-hours') {
      hours = Number(argv[i + 1]);
      i += 1;
    } else { fail(`unknown option: ${argv[i]}`); }
  }
  if (!Number.isInteger(hours) || hours < 1 || hours > 8760) {
    fail('--last-hours must be an integer between 1 and 8760');
  }

  const script = [
    'Import-Module $env:WSH_MANIFEST -Force',
    '$e = @(Get-WinSecEventByIp -IpAddress $env:WSH_IP -LastHours ([int]$env:WSH_HOURS) -PassHostStatus -WarningAction SilentlyContinue)',
    "if ($env:WSH_JSON -eq '1') { @($e) | ConvertTo-Json -Depth 6 }",
    'else { $e | Format-Table TimeUtc, Computer, LogName, EventId, TargetAccount, SourceIp, Status -AutoSize }',
  ].join('; ');

  runPowerShell(script, { WSH_IP: target, WSH_HOURS: String(hours), WSH_JSON: json ? '1' : '0' });
}

usage();
process.exit(2);
