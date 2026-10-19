import { createHash, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { MusterError } from './errors.js';

export const REQUEST_SIGNATURE_VERSION = 'muster-request-v1';
export const KEY_PROOF_VERSION = 'muster-key-proof-v1';
/** Server time is authoritative; a signed timestamp may differ from it by at most this much. */
export const MAX_CLOCK_SKEW_SECONDS = 60;

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export interface ParsedPublicKey {
  key: KeyObject;
  /** sha256 hex over the SPKI DER bytes; the value stored in public_key_sha256. */
  sha256: string;
}

/** Parses a base64 SPKI DER Ed25519 public key, rejecting other key types and non-canonical encodings. */
export function parsePublicKey(publicKeyB64: unknown): ParsedPublicKey {
  if (typeof publicKeyB64 !== 'string' || publicKeyB64.length > 200 || !BASE64.test(publicKeyB64)) {
    throw new MusterError(400, 'invalid_public_key');
  }
  const der = Buffer.from(publicKeyB64, 'base64');
  let key: KeyObject;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new MusterError(400, 'invalid_public_key');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new MusterError(400, 'invalid_public_key', 'public key must be Ed25519');
  }
  if (!key.export({ format: 'der', type: 'spki' }).equals(der)) {
    throw new MusterError(400, 'invalid_public_key', 'public key encoding is not canonical');
  }
  return { key, sha256: sha256Hex(der) };
}

export interface CanonicalRequestParts {
  /** The deployment identity (MUSTER_AUDIENCE); a request signed for one deployment fails on another. */
  audience: string;
  method: string;
  pathWithQuery: string;
  timestamp: string;
  nonce: string;
  body: Buffer;
  /** The token for token-authenticated requests, or `key:<sha256>` for key-authenticated registration. */
  credential: string;
}

/** The exact bytes a client signs. Binding method, path, body hash, and credential stops cross-request reuse. */
export function canonicalRequest(p: CanonicalRequestParts): string {
  return [
    REQUEST_SIGNATURE_VERSION,
    p.audience,
    p.method.toUpperCase(),
    p.pathWithQuery,
    p.timestamp,
    p.nonce,
    sha256Hex(p.body),
    p.credential,
  ].join('\n');
}

/** What a runner signs with its new key so a launcher cannot enroll a key the runner does not hold. */
export function keyProofPayload(p: { audience: string; agentId: string; claimId: string; nonce: string; publicKeySha256: string }): string {
  return [KEY_PROOF_VERSION, p.audience, p.agentId, p.claimId, p.nonce, p.publicKeySha256].join('\n');
}

export function verifySignature(key: KeyObject, payload: string, signatureB64: unknown): boolean {
  if (typeof signatureB64 !== 'string' || signatureB64.length > 100 || !BASE64.test(signatureB64)) return false;
  const signature = Buffer.from(signatureB64, 'base64');
  if (signature.length !== 64) return false;
  try {
    return verify(null, Buffer.from(payload), key, signature);
  } catch {
    return false;
  }
}

export function signPayload(privateKey: KeyObject | string, payload: string): string {
  return sign(null, Buffer.from(payload), privateKey).toString('base64');
}

export function generateSigningKeyPair(): { publicKeyB64: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyB64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}
