import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { MemoryChain } from '../src/chain.js';
import { openDb } from '../src/db.js';
import { Denied, IntegrityError, Registry } from '../src/registry.js';
import { SimulatedTag } from '../src/tag.js';

function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpr-test-'));
  let clock = new Date('2026-11-02T09:00:00Z');
  const chain = new MemoryChain();
  const db = openDb();
  const reg = new Registry({
    db, chain, kek: randomBytes(32), tagMetaKey: randomBytes(16), tagMasterKey: randomBytes(16),
    storageDir: dir, admins: ['staff:anna'], engineers: ['eng:paul'], now: () => clock,
  });
  const advance = (hours: number) => { clock = new Date(clock.getTime() + hours * 3600_000); };
  return { reg, chain, db, dir, advance };
}

const pdf = (s: string) => Buffer.from(`%PDF-1.4 ${s}`);

test('registration anchors the record and gives the owner custody', async () => {
  const { reg } = setup();
  const { id } = await reg.registerVehicle('owner:max', { vin: 'WP0ZZZ91ZJS100001', make: 'Porsche', model: '911 Carrera', year: 1973 });
  assert.equal(reg.ownerOf(id), 'owner:max');
  const [a] = reg.anchors(id);
  assert.equal(a.type, 'register');
  assert.equal(a.memo.prev, null);
  assert.ok(!JSON.stringify(a.memo).includes('WP0ZZZ'), 'VIN must not go on-chain');
});

test('evidence is encrypted at rest and verifies against its on-chain commitment', async () => {
  const { reg, dir } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const doc = pdf('service history 1981-1995');
  const { id } = await reg.addEvidence('owner:max', car, { kind: 'service_record', filename: 'history.pdf', data: doc });

  const raw = fs.readFileSync(path.join(dir, `${id}.bin`));
  assert.equal(raw.indexOf('service history'), -1, 'file must not be stored in plaintext');
  assert.deepEqual(reg.readEvidence('owner:max', id), doc);

  const v = await reg.verifyEvidence('owner:max', id);
  assert.ok(v.ok, JSON.stringify(v.checks));
});

test('on-chain memo holds a salted commitment, not the bare file hash', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const doc = pdf('x');
  await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: doc });
  const memo = reg.anchors(car)[1].memo;
  const { createHash } = await import('node:crypto');
  assert.notEqual(memo.c, createHash('sha256').update(doc).digest('hex'));
});

test('tampering with a stored file is detected on read', async () => {
  const { reg, dir } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const { id } = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  const file = path.join(dir, `${id}.bin`);
  const buf = fs.readFileSync(file);
  buf[buf.length - 1] ^= 0xff;
  fs.writeFileSync(file, buf);
  assert.throws(() => reg.readEvidence('owner:max', id), IntegrityError); // AES-GCM authentication fails
  fs.rmSync(file);
  assert.throws(() => reg.readEvidence('owner:max', id), IntegrityError);
  assert.ok(reg.auditLog().some((r) => r.outcome === 'error' && r.target === id));
});

test('owners cannot file or revoke engineering assessments', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  await assert.rejects(reg.addEvidence('owner:max', car, { kind: 'assessment', filename: 'a.pdf', data: pdf('ok') }), Denied);
  const { id } = await reg.addEvidence('eng:paul', car, { kind: 'assessment', filename: 'a.pdf', data: pdf('matching numbers: no') });
  await assert.rejects(reg.revokeEvidence('owner:max', id, 'dislike'), Denied);
  assert.equal(reg.listEvidence('owner:max', car)[0].status, 'active');
});

test('versioning: a new version supersedes the old one and links to it on-chain', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const v1 = await reg.addEvidence('eng:paul', car, { kind: 'assessment', filename: 'a.pdf', data: pdf('draft') });
  const v2 = await reg.addEvidence('eng:paul', car, { kind: 'assessment', filename: 'a.pdf', data: pdf('final'), supersedes: v1.id });
  assert.equal(v2.version, 2);
  assert.equal(reg.anchors(car).at(-1).memo.sup, v1.sig);
  const old = await reg.verifyEvidence('eng:paul', v1.id);
  assert.equal(old.ok, false);
  assert.ok(old.checks.some((c) => c.name === 'latest version' && !c.ok));
});

test('revocation is anchored and makes verification fail', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const { id, sig } = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  const r = await reg.revokeEvidence('owner:max', id, 'wrong car in photo');
  assert.equal(reg.anchors(car).at(-1).memo.of, sig);
  assert.ok(!JSON.stringify(reg.anchors(car).at(-1).memo).includes('wrong car'), 'reason stays off-chain');
  const v = await reg.verifyEvidence('owner:max', id);
  assert.equal(v.ok, false);
  assert.ok(r.sig);
});

test('selective, time-limited sharing with revocation', async () => {
  const { reg, advance } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const a = await reg.addEvidence('owner:max', car, { kind: 'service_record', filename: 'history.pdf', data: pdf('h') });
  const b = await reg.addEvidence('owner:max', car, { kind: 'valuation', filename: 'valuation.pdf', data: pdf('EUR 410,000') });

  assert.throws(() => reg.readEvidence('buyer:jo', a.id), Denied);
  const g = reg.grantAccess('owner:max', car, 'buyer:jo', [a.id], 48);
  assert.ok(reg.readEvidence('buyer:jo', a.id));
  assert.throws(() => reg.readEvidence('buyer:jo', b.id), Denied, 'valuation was not shared');
  assert.deepEqual(reg.listEvidence('buyer:jo', car).map((e) => e.id), [a.id]);

  advance(49);
  assert.throws(() => reg.readEvidence('buyer:jo', a.id), Denied, 'grant expired');

  const g2 = reg.grantAccess('owner:max', car, 'adviser:kim', [a.id, b.id], 24);
  assert.ok(reg.readEvidence('adviser:kim', b.id));
  reg.revokeAccess('owner:max', g2.id);
  assert.throws(() => reg.readEvidence('adviser:kim', b.id), Denied, 'grant revoked');
  assert.ok(g.id);
});

test('only the owner can share, and only items on their record', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const { id: other } = await reg.registerVehicle('owner:eva', { vin: 'V2' });
  const e = await reg.addEvidence('owner:eva', other, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  assert.throws(() => reg.grantAccess('buyer:jo', car, 'buyer:jo', [], 1), Denied);
  assert.throws(() => reg.grantAccess('owner:max', car, 'buyer:jo', [e.id], 1), Denied);
});

test('custody transfer needs staff confirmation, moves control, and ends the old owner\'s shares', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  reg.grantAccess('owner:max', car, 'adviser:kim', [e.id], 100);

  await assert.rejects(reg.transferCustody('owner:max', car, 'owner:eva', 'owner:max'), Denied);
  await assert.rejects(reg.transferCustody('buyer:jo', car, 'buyer:jo', 'staff:anna'), Denied);
  const t = await reg.transferCustody('owner:max', car, 'owner:eva', 'staff:anna');
  assert.equal(t.epoch, 2);
  assert.equal(reg.ownerOf(car), 'owner:eva');
  assert.throws(() => reg.readEvidence('owner:max', e.id), Denied, 'previous owner loses access');
  assert.throws(() => reg.readEvidence('adviser:kim', e.id), Denied, 'previous owner\'s shares end');
  assert.ok(reg.readEvidence('owner:eva', e.id), 'history travels with the car');
  assert.ok(!JSON.stringify(reg.anchors(car)).includes('owner:'), 'no owner identities on-chain');
});

test('tag scans: genuine accepted, replay and unknown chips rejected', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1', make: 'Porsche', model: '911', year: 1973 });
  const uid = randomBytes(7);
  reg.bindTag('staff:anna', car, uid.toString('hex'));
  const chip = new SimulatedTag(uid, reg.tagKeysFor(uid));

  const first = chip.tap();
  const ok = reg.scanTag(first);
  assert.ok(ok.ok && ok.vehicleId === car && ok.make === 'Porsche');
  assert.equal(reg.scanTag(first).ok, false, 'same URL twice is a replay');
  assert.ok(reg.scanTag(chip.tap()).ok);

  // A clone made by copying a URL seen earlier: counter is behind the real chip.
  const stale = chip.tap();
  assert.ok(reg.scanTag(chip.tap()).ok);
  const r = reg.scanTag(stale);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /replayed/);

  const strayUid = randomBytes(7);
  const stray = new SimulatedTag(strayUid, reg.tagKeysFor(strayUid));
  assert.equal(reg.scanTag(stray.tap()).ok, false, 'genuine chip, but not bound to a car');

  const forged = new SimulatedTag(uid, { metaKey: reg.tagKeysFor(uid).metaKey, fileKey: randomBytes(16) }, 1000);
  assert.equal(reg.scanTag(forged.tap()).ok, false, 'right UID, wrong key');
});

test('a chip whose first tap reports counter 0 is accepted once', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const uid = randomBytes(7);
  reg.bindTag('staff:anna', car, uid.toString('hex'));
  const first = new SimulatedTag(uid, reg.tagKeysFor(uid), -1).tap(); // counter 0
  const r = reg.scanTag(first);
  assert.ok(r.ok && r.counter === 0);
  assert.equal(reg.scanTag(first).ok, false);
});

test('grants need items and a positive duration; transfers need a different owner', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  assert.throws(() => reg.grantAccess('owner:max', car, 'buyer:jo', [e.id], 0));
  assert.throws(() => reg.grantAccess('owner:max', car, 'buyer:jo', [e.id], -5));
  assert.throws(() => reg.grantAccess('owner:max', car, 'buyer:jo', [], 24));
  await assert.rejects(reg.transferCustody('owner:max', car, 'owner:max', 'staff:anna'));
  assert.equal(reg.ownerOf(car), 'owner:max');
});

test('history verification walks the on-chain chain and catches local tampering', async () => {
  const { reg, db } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  await reg.revokeEvidence('owner:max', e.id, 'x');
  await reg.transferCustody('owner:max', car, 'owner:eva', 'staff:anna');

  const ok = await reg.verifyHistory(car);
  assert.ok(ok.ok, JSON.stringify(ok.checks));
  assert.equal(ok.events, 4);

  // Someone with database access edits a local memo to hide the revocation.
  const row = db.prepare("SELECT sig, memo FROM anchors WHERE type = 'revoke'").get() as { sig: string; memo: string };
  db.prepare('UPDATE anchors SET memo = ? WHERE sig = ?').run(row.memo.replace('"revoke"', '"evidence"'), row.sig);
  const bad = await reg.verifyHistory(car);
  assert.equal(bad.ok, false);
});

test('history verification notices a local event that never reached the chain', async () => {
  const { reg, db } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  db.prepare("INSERT INTO anchors (sig, vehicle_id, type, ref, memo, created_at) SELECT 'fake', vehicle_id, 'evidence', 'x', memo, created_at FROM anchors WHERE type = 'register'").run();
  db.prepare("UPDATE anchors SET rowid = 0 WHERE sig = 'fake'").run();
  const r = await reg.verifyHistory(car);
  assert.equal(r.ok, false);
});

test('history verification notices the newest events were deleted locally', async () => {
  const { reg, db } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  await reg.revokeEvidence('owner:max', e.id, 'x');
  // Hide the revocation by deleting it locally and flipping the item back to active.
  db.prepare("DELETE FROM anchors WHERE type = 'revoke'").run();
  db.prepare("UPDATE evidence SET status = 'active' WHERE id = ?").run(e.id);
  const r = await reg.verifyHistory(car);
  assert.equal(r.ok, false);
  assert.ok(r.checks.some((c) => c.name === 'local history is up to date with the chain' && !c.ok));
});

test('an anchor written by a different key is not trusted', async () => {
  const { reg, chain, db } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const prev = reg.anchors(car).at(-1).sig;
  const forged = chain.forge({ app: 'vpr-poc', v: 1, t: 'transfer', rec: car, prev, epoch: 2 }, 'attacker-key');
  db.prepare("INSERT INTO anchors (sig, vehicle_id, type, ref, memo, created_at) VALUES (?, ?, 'transfer', '2', ?, 'now')")
    .run(forged, car, JSON.stringify((await chain.fetch(forged))!.memo));
  const r = await reg.verifyHistory(car);
  assert.equal(r.ok, false);
  assert.ok(r.checks.some((c) => c.name === 'signed by the registry key' && !c.ok));
});

test('crypto-shredding makes a file unreadable while the history stays verifiable', async () => {
  const { reg } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  assert.throws(() => reg.shredEvidence('owner:max', e.id, 'gdpr'), Denied);
  reg.shredEvidence('staff:anna', e.id, 'retention period ended');
  assert.throws(() => reg.readEvidence('owner:max', e.id), Denied);
  assert.ok((await reg.verifyHistory(car)).ok);
});

test('audit log records denials and detects edits', async () => {
  const { reg, db } = setup();
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: pdf('a') });
  assert.throws(() => reg.readEvidence('stranger', e.id), Denied);
  assert.ok(reg.auditLog().some((r) => r.actor === 'stranger' && r.outcome === 'denied'));
  assert.ok(reg.verifyAuditLog().ok);
  db.prepare("UPDATE audit SET actor = 'someone-else' WHERE actor = 'stranger'").run();
  assert.equal(reg.verifyAuditLog().ok, false);
});
