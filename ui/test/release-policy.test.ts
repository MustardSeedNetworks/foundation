import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';
import { validateRelease } from '../scripts/release-policy.js';

const metadata = {
  name: '@mustardseednetworks/auth-ui',
  version: '0.1.0',
  repository: {
    type: 'git',
    url: 'https://github.com/MustardSeedNetworks/foundation.git',
    directory: 'ui',
  },
  publishConfig: { access: 'public', registry: 'https://registry.npmjs.org/' },
};

test('accepts the exact stable UI release and public package identity', () => {
  expect(() => validateRelease('auth-ui-v0.1.0', metadata)).not.toThrow();
});

test.each([
  'v0.1.0',
  'auth-ui-v0.2.0',
  'auth-ui-v0.1.0-beta.1',
  'auth-ui-v01.1.0',
  'auth-ui-v0.1.0\n',
])('rejects mismatched or non-stable tag %j', (tag) => {
  expect(() => validateRelease(tag, metadata)).toThrow();
});

test.each([
  null,
  {},
  { ...metadata, private: true },
  { ...metadata, name: '@other/auth-ui' },
  { ...metadata, repository: { ...metadata.repository, directory: '.' } },
  {
    ...metadata,
    repository: { ...metadata.repository, url: 'https://github.com/other/foundation.git' },
  },
  { ...metadata, publishConfig: { access: 'restricted' } },
])('rejects unsafe publication metadata %#', (value) => {
  expect(() => validateRelease('auth-ui-v0.1.0', value)).toThrow();
});

test('keeps Go root tags and releases UI changes independently', () => {
  const config: unknown = JSON.parse(
    readFileSync(new URL('../../.github/release-please-config.json', import.meta.url), 'utf8'),
  );
  expect(config).toMatchObject({
    packages: {
      '.': { 'release-type': 'go', 'include-component-in-tag': false, 'exclude-paths': ['ui'] },
      ui: { 'release-type': 'node', component: 'auth-ui', 'include-component-in-tag': true },
    },
  });
  expect(config).not.toMatchObject({ 'separate-pull-requests': true });
});
