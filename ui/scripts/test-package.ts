import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const consumer = mkdtempSync(join(tmpdir(), 'foundation-auth-consumer-'));
const npmCli = process.env.npm_execpath;
assert(npmCli, 'Run this check with npm run test:package');

try {
  mkdirSync('dist', { recursive: true });
  writeFileSync('dist/stale-build-output.js', '');
  const result: unknown = JSON.parse(
    execFileSync(process.execPath, [npmCli, 'pack', '--json', '--pack-destination', consumer], {
      encoding: 'utf8',
    }),
  );
  assert(typeof result === 'object' && result !== null);
  assert('@mustardseednetworks/auth-ui' in result);
  const artifact = result['@mustardseednetworks/auth-ui'];
  assert(typeof artifact === 'object' && artifact !== null && 'filename' in artifact);
  assert(typeof artifact.filename === 'string');
  assert('files' in artifact && Array.isArray(artifact.files));
  const files = artifact.files.map((file: unknown) => {
    assert(typeof file === 'object' && file !== null && 'path' in file);
    assert(typeof file.path === 'string');
    return file.path;
  });
  assert.deepEqual(files.sort(), [
    'LICENSE',
    'README.md',
    'dist/contracts.d.ts',
    'dist/contracts.js',
    'dist/webauthn.d.ts',
    'dist/webauthn.js',
    'package.json',
  ]);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  execFileSync(
    process.execPath,
    [
      npmCli,
      'install',
      '--ignore-scripts',
      '--package-lock=false',
      join(consumer, artifact.filename),
    ],
    {
      cwd: consumer,
      stdio: 'inherit',
    },
  );
  writeFileSync(
    join(consumer, 'consumer.ts'),
    `
import type { SignInAdapter, SignInOutcome } from '@mustardseednetworks/auth-ui/contracts';
import { createPasskeyCredential, getPasskeyCredential } from '@mustardseednetworks/auth-ui/webauthn';
const outcome: SignInOutcome = { status: 'authenticated' };
type Result = Awaited<ReturnType<SignInAdapter['password']>>;
const result: Result = outcome;
if (result.status !== 'authenticated') throw new Error('Invalid exported outcome');
if (typeof createPasskeyCredential !== 'function' || typeof getPasskeyCredential !== 'function') {
  throw new Error('Missing runtime exports');
}
`,
  );
  assert.deepEqual(
    readFileSync(join(consumer, 'node_modules/@mustardseednetworks/auth-ui/LICENSE')),
    readFileSync(new URL('../../LICENSE', import.meta.url)),
  );
  execFileSync(
    process.execPath,
    [
      resolve('node_modules/typescript/bin/tsc'),
      '--strict',
      '--module',
      'NodeNext',
      '--target',
      'ES2022',
      '--noEmit',
      'consumer.ts',
    ],
    { cwd: consumer, stdio: 'inherit' },
  );
  execFileSync(process.execPath, ['consumer.ts'], { cwd: consumer, stdio: 'inherit' });
  // Publication consumes this exact verified tarball, never a second pack.
  const artifactPath = process.env.AUTH_UI_ARTIFACT_PATH;
  if (artifactPath) copyFileSync(join(consumer, artifact.filename), artifactPath);
} finally {
  rmSync(consumer, { recursive: true, force: true });
}
