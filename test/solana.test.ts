import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { APP, LocalChain } from '../src/chain.js';
import { openDb } from '../src/db.js';
import { Registry } from '../src/registry.js';

// Same flow as the unit tests, but every anchor is a real transaction executed by the
// Solana Memo program inside LiteSVM, and every read comes back out of the runtime.
// LiteSVM has native builds for macOS and Linux only.
const skip = process.platform === 'win32' && 'LiteSVM has no Windows build (use WSL)';

test('anchors round-trip through the real Memo program', { skip }, async () => {
  const chain = new LocalChain();
  const memo = { app: APP as typeof APP, v: 1 as const, t: 'register' as const, rec: 'veh_x', prev: null, note: 'quotes " and \\ survive' };
  const sig = await chain.anchor(memo);
  const back = await chain.fetch(sig);
  assert.deepEqual(back?.memo, memo);
  assert.equal(back?.signer, chain.signer);
  assert.equal(await chain.fetch('1111111111111111111111111111111111111111111111111111111111111111'), null);
});

test('full registry flow verifies against the Solana runtime', { skip }, async () => {
  const reg = new Registry({
    db: openDb(), chain: new LocalChain(), kek: randomBytes(32), tagMetaKey: randomBytes(16), tagMasterKey: randomBytes(16),
    storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'vpr-svm-')), admins: ['staff:anna'], engineers: ['eng:paul'],
  });
  const { id: car } = await reg.registerVehicle('owner:max', { vin: 'V1' });
  const e = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'a.jpg', data: Buffer.from('a') });
  const e2 = await reg.addEvidence('owner:max', car, { kind: 'photo', filename: 'b.jpg', data: Buffer.from('a') }); // identical bytes
  await reg.revokeEvidence('owner:max', e2.id, 'duplicate');
  await reg.transferCustody('owner:max', car, 'owner:eva', 'staff:anna');

  assert.ok((await reg.verifyEvidence('owner:eva', e.id)).ok);
  const h = await reg.verifyHistory(car);
  assert.ok(h.ok, JSON.stringify(h.checks));
  assert.equal(h.events, 5);
});
