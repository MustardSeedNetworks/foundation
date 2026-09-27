import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

function record(value: unknown): asserts value is Record<string, unknown> {
  assert(typeof value === 'object' && value !== null && !Array.isArray(value));
}

if (import.meta.main) {
  const tag = process.env.AUTH_UI_RELEASE_TAG;
  assert(tag, 'AUTH_UI_RELEASE_TAG is required');
  const metadata: unknown = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  );
  validateRelease(tag, metadata);
}

export function validateRelease(tag: string, metadata: unknown): void {
  assert(
    tag.trim() === tag && /^auth-ui-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(tag),
    'Expected a stable auth-ui release tag',
  );
  record(metadata);
  assert(metadata.name === '@mustardseednetworks/auth-ui', 'Unexpected package name');
  assert(metadata.version === tag.slice('auth-ui-v'.length), 'Tag and package version differ');
  assert(metadata.private !== true, 'Package remains private');
  validatePublicationDestination(metadata);
}

function validatePublicationDestination(metadata: Record<string, unknown>): void {
  record(metadata.repository);
  assert(
    metadata.repository.type === 'git' &&
      metadata.repository.url === 'https://github.com/MustardSeedNetworks/foundation.git' &&
      metadata.repository.directory === 'ui',
    'Unexpected package repository',
  );
  record(metadata.publishConfig);
  assert(
    metadata.publishConfig.access === 'public' &&
      metadata.publishConfig.registry === 'https://registry.npmjs.org/',
    'Unexpected publication destination',
  );
}
