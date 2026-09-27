import { describe, expect, expectTypeOf, it } from 'vitest';
import type { AuthFailure, SignInAdapter, SignInOutcome } from '../src/contracts.js';

describe('sign-in contract', () => {
  it('keeps a TOTP challenge distinct from an authenticated session', () => {
    const outcome: SignInOutcome = { status: 'totp-required', challengeId: 'ephemeral' };
    expect(outcome.status).not.toBe('authenticated');
    expectTypeOf<Extract<SignInOutcome, { status: 'authenticated' }>>().toEqualTypeOf<{
      status: 'authenticated';
    }>();
  });

  it('exposes no access or refresh token in a successful outcome', () => {
    const outcome: SignInOutcome = { status: 'authenticated' };
    expect(Object.keys(outcome)).toEqual(['status']);
    // @ts-expect-error Tokens stay inside the product session transport.
    const invalid: SignInOutcome = { status: 'authenticated', token: 'not-exposed' };
    expect(invalid.status).toBe('authenticated');
  });

  it('requires durable failures to remain failures', () => {
    const failure: AuthFailure = { status: 'failed', reason: 'persistence-failed' };
    expect(failure.status).toBe('failed');
    expectTypeOf<
      Awaited<ReturnType<SignInAdapter['finishPasskey']>>
    >().toEqualTypeOf<SignInOutcome>();
  });
});
