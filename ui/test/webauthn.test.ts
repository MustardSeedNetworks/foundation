import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import {
  createPasskeyCredential,
  getPasskeyCredential,
  supportsPasskeys,
} from '../src/webauthn.js';

const creationOptions: PublicKeyCredentialCreationOptionsJSON = {
  challenge: 'AQID',
  rp: { name: 'Example', id: 'example.test' },
  user: { id: 'BAUG', name: 'owner', displayName: 'Owner' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
};
const requestOptions: PublicKeyCredentialRequestOptionsJSON = { challenge: 'AQID' };
const registration: RegistrationResponseJSON = {
  id: 'BAUG',
  rawId: 'BAUG',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  clientExtensionResults: { credProps: { rk: true } },
  response: {
    clientDataJSON: 'AQID',
    attestationObject: 'BwgJ',
    transports: ['internal'],
    authenticatorData: 'CgsM',
    publicKeyAlgorithm: -7,
  },
};
const authentication: AuthenticationResponseJSON = {
  id: 'BAUG',
  rawId: 'BAUG',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  clientExtensionResults: { appid: false },
  response: {
    clientDataJSON: 'AQID',
    authenticatorData: 'BwgJ',
    signature: 'CgsM',
    userHandle: 'BAUG',
  },
};
const create = vi.fn();
const get = vi.fn();

class BrowserCredential {
  static parseCreationOptionsFromJSON = vi.fn();
  static parseRequestOptionsFromJSON = vi.fn();

  constructor(private readonly json: RegistrationResponseJSON | AuthenticationResponseJSON) {}

  toJSON(): RegistrationResponseJSON | AuthenticationResponseJSON {
    return this.json;
  }
}

beforeEach(() => {
  vi.stubGlobal('isSecureContext', true);
  vi.stubGlobal('PublicKeyCredential', BrowserCredential);
  vi.stubGlobal('navigator', { credentials: { create, get } });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetAllMocks();
});

test('detects native JSON ceremony support without invoking an authenticator', () => {
  expect(supportsPasskeys()).toBe(true);
  expect(create).not.toHaveBeenCalled();
  expect(get).not.toHaveBeenCalled();
});

test.each(['PublicKeyCredential', 'navigator'])('does not advertise support without %s', (name) => {
  vi.stubGlobal(name, undefined);
  expect(supportsPasskeys()).toBe(false);
});

test('does not advertise passkeys outside a secure context', () => {
  vi.stubGlobal('isSecureContext', false);
  expect(supportsPasskeys()).toBe(false);
});

test.each(['parseCreationOptionsFromJSON', 'parseRequestOptionsFromJSON', 'toJSON'])(
  'does not advertise support without native %s',
  (method) => {
    const browser = {
      parseCreationOptionsFromJSON: vi.fn(),
      parseRequestOptionsFromJSON: vi.fn(),
      prototype: { toJSON: vi.fn() },
    };
    if (method === 'toJSON') Reflect.deleteProperty(browser.prototype, method);
    else Reflect.deleteProperty(browser, method);
    vi.stubGlobal('PublicKeyCredential', browser);
    expect(supportsPasskeys()).toBe(false);
  },
);

test.each(['create', 'get'])(
  'does not advertise support without navigator.credentials.%s',
  (method) => {
    const credentials = { create, get };
    Reflect.deleteProperty(credentials, method);
    vi.stubGlobal('navigator', { credentials });
    expect(supportsPasskeys()).toBe(false);
  },
);

test('unsupported browsers fail both ceremonies without invoking credentials', async () => {
  vi.stubGlobal('isSecureContext', false);
  await expect(createPasskeyCredential(creationOptions)).rejects.toMatchObject({
    name: 'NotSupportedError',
  });
  await expect(getPasskeyCredential(requestOptions)).rejects.toMatchObject({
    name: 'NotSupportedError',
  });
  expect(create).not.toHaveBeenCalled();
  expect(get).not.toHaveBeenCalled();
});

test('creation passes native options and cancellation signal without dropping response fields', async () => {
  const native = { challenge: new Uint8Array([1, 2, 3]) };
  BrowserCredential.parseCreationOptionsFromJSON.mockReturnValue(native);
  create.mockResolvedValue(new BrowserCredential(registration));
  const signal = new AbortController().signal;
  expect(await createPasskeyCredential(creationOptions, signal)).toEqual(registration);
  expect(BrowserCredential.parseCreationOptionsFromJSON).toHaveBeenCalledWith(creationOptions);
  expect(create).toHaveBeenCalledWith({ publicKey: native, signal });
});

test('authentication preserves native response extensions and attachment', async () => {
  const native = { challenge: new Uint8Array([1, 2, 3]) };
  BrowserCredential.parseRequestOptionsFromJSON.mockReturnValue(native);
  get.mockResolvedValue(new BrowserCredential(authentication));
  expect(await getPasskeyCredential(requestOptions)).toEqual(authentication);
  expect(BrowserCredential.parseRequestOptionsFromJSON).toHaveBeenCalledWith(requestOptions);
  expect(get).toHaveBeenCalledWith({ publicKey: native });
});

test('a null credential is not represented as a successful assertion', async () => {
  get.mockResolvedValue(null);
  await expect(getPasskeyCredential(requestOptions)).rejects.toMatchObject({
    name: 'NotAllowedError',
  });
});

test('preserves browser cancellation, timeout and invalid-option exceptions for the UI boundary', async () => {
  const denied = new DOMException('Not allowed', 'NotAllowedError');
  get.mockRejectedValue(denied);
  await expect(getPasskeyCredential(requestOptions)).rejects.toBe(denied);
  const invalid = new DOMException('Invalid encoding', 'EncodingError');
  BrowserCredential.parseCreationOptionsFromJSON.mockImplementation(() => {
    throw invalid;
  });
  await expect(createPasskeyCredential(creationOptions)).rejects.toBe(invalid);
  expect(create).not.toHaveBeenCalled();
});

test('rejects an assertion returned from creation instead of mislabelling it', async () => {
  create.mockResolvedValue(new BrowserCredential(authentication));
  await expect(createPasskeyCredential(creationOptions)).rejects.toMatchObject({
    name: 'TypeError',
  });
});

test('rejects an attestation returned from authentication', async () => {
  get.mockResolvedValue(new BrowserCredential(registration));
  await expect(getPasskeyCredential(requestOptions)).rejects.toMatchObject({ name: 'TypeError' });
});

test('forwards abort signals and native JSON binary extension output during authentication', async () => {
  const response: AuthenticationResponseJSON = {
    ...authentication,
    clientExtensionResults: { prf: { results: { first: 'AQID', second: 'BAUG' } } },
  };
  get.mockResolvedValue(new BrowserCredential(response));
  const signal = new AbortController().signal;
  expect(await getPasskeyCredential(requestOptions, signal)).toEqual(response);
  expect(get).toHaveBeenCalledWith(expect.objectContaining({ signal }));
});

test('rejects non-public-key credentials', async () => {
  create.mockResolvedValue({ id: 'password', type: 'password' });
  await expect(createPasskeyCredential(creationOptions)).rejects.toMatchObject({
    name: 'TypeError',
  });
});
