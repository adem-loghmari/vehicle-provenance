import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cmac } from '../src/cmac.js';
import { SimulatedTag, decodeSun, diversify } from '../src/tag.js';

test('CMAC matches RFC 4493 vectors', () => {
  const k = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
  const m = Buffer.from('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710', 'hex');
  assert.equal(cmac(k, Buffer.alloc(0)).toString('hex'), 'bb1d6929e95937287fa37d129b756746');
  assert.equal(cmac(k, m.subarray(0, 16)).toString('hex'), '070a16b46b4d4144f79bdd9dd04a287c');
  assert.equal(cmac(k, m.subarray(0, 40)).toString('hex'), 'dfa66747de9ae63030ca32611497c827');
  assert.equal(cmac(k, m).toString('hex'), '51f0bebf7e3b9d92fc49741779363cfe');
});

test('SUN decoding matches the NXP AN12196 example', () => {
  const zero = Buffer.alloc(16);
  const scan = decodeSun({ picc: 'EF963FF7828658A599F3041510671E88', cmac: '94EED9EE65337086' }, { metaKey: zero, fileKey: zero });
  assert.deepEqual(scan, { uid: '04de5f1eacc040', counter: 61 });
});

test('a tampered MAC or wrong key is rejected', () => {
  const zero = Buffer.alloc(16);
  assert.throws(() => decodeSun({ picc: 'EF963FF7828658A599F3041510671E88', cmac: '94EED9EE65337087' }, { metaKey: zero, fileKey: zero }), /invalid tag MAC/);
  assert.throws(() => decodeSun({ picc: 'EF963FF7828658A599F3041510671E88', cmac: '94EED9EE65337086' }, { metaKey: zero, fileKey: Buffer.alloc(16, 1) }), /invalid tag MAC/);
  assert.throws(() => decodeSun({ picc: 'EF963FF7828658A599F3041510671E88', cmac: '94EED9EE65337086' }, { metaKey: Buffer.alloc(16, 1), fileKey: zero }), /PICC data tag/);
  assert.throws(() => decodeSun({ picc: 'zz', cmac: '00' }, { metaKey: zero, fileKey: zero }), /malformed/);
});

test('simulated tag produces scans the decoder accepts, with a rising counter', () => {
  const uid = randomBytes(7);
  const master = randomBytes(16);
  const keys = { metaKey: randomBytes(16), fileKey: diversify(master, uid) };
  const tag = new SimulatedTag(uid, keys);
  const a = decodeSun(tag.tap(), { metaKey: keys.metaKey, fileKey: (u) => diversify(master, u) });
  const b = decodeSun(tag.tap(), { metaKey: keys.metaKey, fileKey: (u) => diversify(master, u) });
  assert.equal(a.uid, uid.toString('hex'));
  assert.equal(b.counter, a.counter + 1);
});

test('diversified keys differ per chip, so one extracted key does not open another', () => {
  const master = randomBytes(16);
  const meta = randomBytes(16);
  const uidA = randomBytes(7);
  const uidB = randomBytes(7);
  assert.notDeepEqual(diversify(master, uidA), diversify(master, uidB));
  // An attacker who extracted chip A's key programs a blank chip with B's UID.
  const fake = new SimulatedTag(uidB, { metaKey: meta, fileKey: diversify(master, uidA) });
  assert.throws(() => decodeSun(fake.tap(), { metaKey: meta, fileKey: (u) => diversify(master, u) }), /invalid tag MAC/);
});
