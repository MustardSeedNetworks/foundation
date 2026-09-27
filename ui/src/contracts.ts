export type AuthFailure = {
  status: 'failed';
  reason:
    | 'invalid-credentials'
    | 'challenge-expired'
    | 'rate-limited'
    | 'unavailable'
    | 'persistence-failed';
};

export type SignInOutcome =
  | { status: 'authenticated' }
  | { status: 'totp-required'; challengeId: string }
  | AuthFailure;

/** Product adapters own cookies, CSRF, response validation and session publication. */
export interface SignInAdapter {
  password(
    input: { username: string; password: string },
    signal: AbortSignal,
  ): Promise<SignInOutcome>;
  totp(input: { challengeId: string; code: string }, signal: AbortSignal): Promise<SignInOutcome>;
  beginPasskey(signal: AbortSignal): Promise<PublicKeyCredentialRequestOptionsJSON | AuthFailure>;
  finishPasskey(
    credential: AuthenticationResponseJSON,
    signal: AbortSignal,
  ): Promise<SignInOutcome>;
}
