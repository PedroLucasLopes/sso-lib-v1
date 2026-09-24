import * as crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;

export function readKey(raw: string, varName: string): Buffer {
  const key = Buffer.from(raw.trim(), 'hex');

  if (key.length !== KEY_BYTES) {
    throw new Error(
      `${varName} deve ter ${KEY_BYTES} bytes em hex (${KEY_BYTES * 2} caracteres). ` +
        `Gere com: openssl rand -hex ${KEY_BYTES}`,
    );
  }

  return key;
}

export function sealCompact(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  return [
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

export function openCompact(key: Buffer, token: string): string | null {
  const parts = token.split('.');

  if (parts.length !== 3) return null;

  const [iv, tag, payload] = parts;

  try {
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      key,
      Buffer.from(iv, 'base64url'),
    );

    decipher.setAuthTag(Buffer.from(tag, 'base64url'));

    return Buffer.concat([
      decipher.update(Buffer.from(payload, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}
