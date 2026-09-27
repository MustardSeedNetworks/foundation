// Native WebAuthn JSON conversion retains extension data and authenticator metadata.
export function supportsPasskeys(): boolean {
  return (
    globalThis.isSecureContext === true &&
    typeof PublicKeyCredential !== 'undefined' &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.prototype.toJSON === 'function' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.create === 'function' &&
    typeof navigator.credentials?.get === 'function'
  );
}

function credentialJSON(
  credential: Credential | null,
): RegistrationResponseJSON | AuthenticationResponseJSON {
  if (credential === null) {
    throw new DOMException('No credential returned.', 'NotAllowedError');
  }
  if (!(credential instanceof PublicKeyCredential)) {
    throw new TypeError('Expected a public-key credential.');
  }
  return credential.toJSON();
}

export async function createPasskeyCredential(
  options: PublicKeyCredentialCreationOptionsJSON,
  signal?: AbortSignal,
): Promise<RegistrationResponseJSON> {
  if (!supportsPasskeys()) {
    throw new DOMException('Native passkey APIs are unavailable.', 'NotSupportedError');
  }
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options);
  const result = credentialJSON(
    await navigator.credentials.create({ publicKey, ...(signal ? { signal } : {}) }),
  );
  if (!('attestationObject' in result.response)) {
    throw new TypeError('Expected an attestation response.');
  }
  return { ...result, response: result.response };
}

export async function getPasskeyCredential(
  options: PublicKeyCredentialRequestOptionsJSON,
  signal?: AbortSignal,
): Promise<AuthenticationResponseJSON> {
  if (!supportsPasskeys()) {
    throw new DOMException('Native passkey APIs are unavailable.', 'NotSupportedError');
  }
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options);
  const result = credentialJSON(
    await navigator.credentials.get({ publicKey, ...(signal ? { signal } : {}) }),
  );
  if (!('signature' in result.response)) {
    throw new TypeError('Expected an assertion response.');
  }
  return { ...result, response: result.response };
}
