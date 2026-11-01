import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';
import { cmac } from './cmac.js';

// NTAG 424 DNA "Secure Unique NFC" (SUN) messages, following NXP AN12196.
//
// A plain NFC tag returns a fixed UID, so anyone with a phone can read it and write
// the same UID onto a blank tag. An NTAG 424 DNA instead returns a fresh URL on every
// tap, e.g. https://registry.example/t?picc=<32 hex>&cmac=<16 hex>:
//   picc = AES-CBC(metaKey, 0xC7 | UID | readCounter | random)   hides the UID
//   cmac = truncated AES-CMAC under a session key derived from fileKey, UID, counter
// The counter increments inside the chip on each tap. The keys never leave the chip,
// so a cloned tag cannot produce valid MACs, and a recorded URL replays an old counter.

export interface TagKeys {
  metaKey: Buffer; // SDMMetaReadKey: decrypts the PICC data
  fileKey: Buffer; // SDMFileReadKey: derives the per-scan MAC key
}

export interface SunMessage {
  picc: string;
  cmac: string;
}

export interface DecodedScan {
  uid: string; // hex, 7 bytes
  counter: number;
}

const ZERO_IV = Buffer.alloc(16);
const PICC_TAG = 0xc7; // UID mirrored + counter mirrored + UID length 7

function sessionMacKey(fileKey: Buffer, uid: Buffer, counter: number): Buffer {
  const ctr = Buffer.alloc(3);
  ctr.writeUIntLE(counter, 0, 3);
  const sv2 = Buffer.concat([Buffer.from('3cc300010080', 'hex'), uid, ctr]);
  return cmac(fileKey, sv2);
}

// The chip sends only the odd-indexed bytes of the 16-byte CMAC.
function truncate(mac: Buffer): Buffer {
  const out = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) out[i] = mac[2 * i + 1];
  return out;
}

function sunMac(fileKey: Buffer, uid: Buffer, counter: number): Buffer {
  // No file data is mirrored, so the MAC input is empty.
  return truncate(cmac(sessionMacKey(fileKey, uid, counter), Buffer.alloc(0)));
}

/**
 * Per-tag key derived from a master key and the tag's UID (the idea of NXP AN10922).
 * Every chip gets a different key, so extracting one chip's key does not compromise
 * the others, and the server stores no per-tag secrets.
 */
export function diversify(master: Buffer, uid: Buffer): Buffer {
  return cmac(master, Buffer.concat([Buffer.from([0x01]), uid, Buffer.from('VPR-SDM')]));
}

/**
 * Decrypt and authenticate a scan. Throws if the MAC is wrong. Does not check replay.
 * `keys.fileKey` may be a function of the UID, since the UID is only known after decryption.
 */
export function decodeSun(msg: SunMessage, keys: { metaKey: Buffer; fileKey: Buffer | ((uid: Buffer) => Buffer) }): DecodedScan {
  if (!/^[0-9a-fA-F]{32}$/.test(msg.picc) || !/^[0-9a-fA-F]{16}$/.test(msg.cmac)) throw new Error('malformed tag message');
  const enc = Buffer.from(msg.picc, 'hex');
  const d = createDecipheriv('aes-128-cbc', keys.metaKey, ZERO_IV);
  d.setAutoPadding(false);
  const plain = Buffer.concat([d.update(enc), d.final()]);
  if (plain[0] !== PICC_TAG) throw new Error('unexpected PICC data tag (wrong key or not one of our tags)');

  const uid = plain.subarray(1, 8);
  const counter = plain.readUIntLE(8, 3);
  const fileKey = typeof keys.fileKey === 'function' ? keys.fileKey(uid) : keys.fileKey;
  const expected = sunMac(fileKey, uid, counter);
  if (!timingSafeEqual(expected, Buffer.from(msg.cmac, 'hex'))) throw new Error('invalid tag MAC');
  return { uid: uid.toString('hex'), counter };
}

/** A software stand-in for the physical chip, so the flow can be tested without hardware. */
export class SimulatedTag {
  private counter: number;
  constructor(readonly uid: Buffer, private keys: TagKeys, startCounter = 0) {
    if (uid.length !== 7) throw new Error('UID must be 7 bytes');
    this.counter = startCounter;
  }

  tap(): SunMessage {
    this.counter += 1;
    const ctr = Buffer.alloc(3);
    ctr.writeUIntLE(this.counter, 0, 3);
    const plain = Buffer.concat([Buffer.from([PICC_TAG]), this.uid, ctr, randomBytes(5)]);
    const c = createCipheriv('aes-128-cbc', this.keys.metaKey, ZERO_IV);
    c.setAutoPadding(false);
    const picc = Buffer.concat([c.update(plain), c.final()]);
    return { picc: picc.toString('hex'), cmac: sunMac(this.keys.fileKey, this.uid, this.counter).toString('hex') };
  }
}
