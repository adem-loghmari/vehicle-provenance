import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

// Envelope encryption: every evidence file gets its own random data key (DEK), and only
// the DEK is encrypted with the master key (KEK). In production the KEK lives in an HSM
// or a self-hosted KMS (e.g. OpenBao/Vault) and never touches application disk.
// Deleting a file's wrapped DEK makes every copy of it unreadable, backups included
// ("crypto-shredding"), which is how retention and deletion requests are honoured.

export const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest('hex');

function seal(key: Buffer, plain: Buffer): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]); // iv(12) | tag(16) | ciphertext
}

function open(key: Buffer, sealed: Buffer): Buffer {
  const d = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 12));
  d.setAuthTag(sealed.subarray(12, 28));
  return Buffer.concat([d.update(sealed.subarray(28)), d.final()]);
}

export function encryptFile(kek: Buffer, plain: Buffer) {
  const dek = randomBytes(32);
  return { ciphertext: seal(dek, plain), wrappedKey: seal(kek, dek) };
}

export function decryptFile(kek: Buffer, wrappedKey: Buffer, ciphertext: Buffer): Buffer {
  return open(open(kek, wrappedKey), ciphertext);
}

// What goes on-chain is a salted commitment, never the bare file hash. A public hash
// would let anyone holding a copy of a document confirm it belongs to a registry record.
export function commitment(salt: string, fileSha256: string) {
  return sha256(`${salt}:${fileSha256}`);
}

export const newSalt = () => randomBytes(16).toString('hex');
export const newId = (prefix: string) => `${prefix}_${randomBytes(8).toString('hex')}`;
