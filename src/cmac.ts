import { createCipheriv } from 'node:crypto';

// AES-128-CMAC (RFC 4493). Node's crypto has no CMAC, and NTAG 424 DNA uses it
// both to derive session keys and to compute the per-scan MAC.

const RB = 0x87;

function aesBlock(key: Buffer, block: Buffer): Buffer {
  const c = createCipheriv('aes-128-ecb', key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

function shiftLeft(b: Buffer): Buffer {
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) out[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0)) & 0xff;
  if (b[0] & 0x80) out[15] ^= RB;
  return out;
}

function subkeys(key: Buffer): [Buffer, Buffer] {
  const k1 = shiftLeft(aesBlock(key, Buffer.alloc(16)));
  return [k1, shiftLeft(k1)];
}

export function cmac(key: Buffer, msg: Buffer): Buffer {
  if (key.length !== 16) throw new Error('CMAC key must be 16 bytes');
  const [k1, k2] = subkeys(key);
  const n = Math.max(1, Math.ceil(msg.length / 16));
  const complete = msg.length > 0 && msg.length % 16 === 0;

  const last = Buffer.alloc(16);
  msg.copy(last, 0, (n - 1) * 16);
  if (complete) {
    for (let i = 0; i < 16; i++) last[i] ^= k1[i];
  } else {
    last[msg.length - (n - 1) * 16] = 0x80;
    for (let i = 0; i < 16; i++) last[i] ^= k2[i];
  }

  let x: Buffer = Buffer.alloc(16);
  for (let i = 0; i < n - 1; i++) {
    const y = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) y[j] = x[j] ^ msg[i * 16 + j];
    x = aesBlock(key, y);
  }
  for (let j = 0; j < 16; j++) last[j] ^= x[j];
  return aesBlock(key, last);
}
