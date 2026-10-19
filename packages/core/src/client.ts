import { createPrivateKey, createPublicKey, randomBytes, type KeyObject } from 'node:crypto';
import { canonicalRequest, parsePublicKey, signPayload } from './signing.js';

/**
 * A seat private key from an env value: a PEM, or a single line of base64 PKCS#8 DER
 * (env files cannot carry a multi-line PEM, so the vault stores the DER form).
 */
export function loadPrivateKey(raw: string): KeyObject {
  const text = raw.trim();
  if (text.includes('-----BEGIN')) return createPrivateKey(text);
  return createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
}

/** sha256 of the SPKI public key that belongs to a private key: the seat-registration credential. */
export function publicKeySha256(privateKey: KeyObject): string {
  return parsePublicKey(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64')).sha256;
}

export type SeatCredential = { kind: 'key'; publicKeySha256: string } | { kind: 'token'; token: string };

export interface SignedSeatRequest {
  method: string;
  headers: Record<string, string>;
  body?: string;
}

/** Builds one muster-request-v1 signed request (README "Identity"). Never logs its output: it carries the token. */
export function signedRequest(p: {
  audience: string;
  method: string;
  path: string;
  body?: unknown;
  credential: SeatCredential;
  privateKey: KeyObject;
}): SignedSeatRequest {
  const bodyText = p.body === undefined ? '' : JSON.stringify(p.body);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(18).toString('base64url');
  const credential = p.credential.kind === 'key' ? `key:${p.credential.publicKeySha256}` : p.credential.token;
  const authorization = p.credential.kind === 'key' ? `Muster-Key ${p.credential.publicKeySha256}` : `Muster-PoP ${p.credential.token}`;
  const payload = canonicalRequest({
    audience: p.audience,
    method: p.method,
    pathWithQuery: p.path,
    timestamp,
    nonce,
    body: Buffer.from(bodyText),
    credential,
  });
  return {
    method: p.method,
    headers: {
      'content-type': 'application/json',
      authorization,
      'muster-timestamp': timestamp,
      'muster-nonce': nonce,
      'muster-signature': signPayload(p.privateKey, payload),
    },
    ...(p.method === 'GET' ? {} : { body: bodyText }),
  };
}
