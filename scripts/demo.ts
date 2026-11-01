import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import type { Chain } from '../src/chain.js';
import { type Network, ROOT, network, openRegistry, solana } from '../src/env.js';
import { Denied, type Registry } from '../src/registry.js';
import { SimulatedTag } from '../src/tag.js';

// The whole lifecycle of one car's record, end to end:
// register -> bind hallmark -> upload evidence -> engineer assessment (v1, v2)
// -> share with a buyer -> tap the hallmark (genuine, replayed, cloned) -> revoke a mistake
// -> transfer custody -> verify everything against the chain.

const sample = (f: string) => fs.readFileSync(path.join(ROOT, 'samples', f));

export interface DemoState {
  vehicleId: string;
  tagUid: string;
  tagCounter: number;
  lastTap: { picc: string; cmac: string } | null;
}

export async function runDemo(reg: Registry, chain: Chain, log: (s: string) => void = console.log): Promise<DemoState> {
  const link = (sig: string) => chain.explorerUrl(sig);
  const step = (s: string) => log(`\n== ${s}`);
  const ok = (s: string) => log(`   ok    ${s}`);
  const no = (s: string) => log(`   DENY  ${s}`);
  const info = (s: string) => log(`   note  ${s}`);
  const expectDenied = async (what: string, fn: () => unknown) => {
    try {
      await fn();
      throw new Error(`expected denial: ${what}`);
    } catch (err) {
      if (!(err instanceof Denied)) throw err;
      no(`${what} (${err.message})`);
    }
  };

  step('1. Owner registers a 1973 Porsche 911 Carrera RS');
  const car = await reg.registerVehicle('owner:max', { vin: 'WP0ZZZ91ZDS100001', make: 'Porsche', model: '911 Carrera RS 2.7', year: 1973 });
  ok(`record ${car.id} anchored: ${link(car.sig)}`);
  ok('on-chain memo contains the opaque record id only (no VIN, no owner)');

  step('2. Registry staff fit an NTAG 424 DNA hallmark at inspection');
  const uid = randomBytes(7);
  reg.bindTag('staff:anna', car.id, uid.toString('hex'));
  const chip = new SimulatedTag(uid, reg.tagKeysFor(uid));
  ok(`chip ${uid.toString('hex')} bound; its key is derived from the master key + UID, nothing per-tag stored`);

  step('3. Owner uploads evidence (encrypted at rest, salted commitment anchored)');
  const history = await reg.addEvidence('owner:max', car.id, { kind: 'service_record', filename: 'service-history-1973-1998.txt', data: sample('service-history-1973-1998.txt') });
  ok(`service history  ${link(history.sig)}`);
  const photo = await reg.addEvidence('owner:max', car.id, { kind: 'photo', filename: 'chassis-photo-2026.txt', data: sample('chassis-photo-2026.txt') });
  ok(`chassis photo    ${link(photo.sig)}`);
  const wrong = await reg.addEvidence('owner:max', car.id, { kind: 'photo', filename: 'wrong-photo.txt', data: sample('wrong-photo.txt') });
  ok(`another photo    ${link(wrong.sig)}`);
  const valuation = await reg.addEvidence('owner:max', car.id, { kind: 'valuation', filename: 'valuation-2026.txt', data: sample('valuation-2026.txt') });
  ok(`valuation        ${link(valuation.sig)}`);

  step('4. Engineer files the assessment, then revises it');
  await expectDenied('owner tries to file an assessment', () =>
    reg.addEvidence('owner:max', car.id, { kind: 'assessment', filename: 'my-own-report.txt', data: Buffer.from('all original, trust me') }));
  const a1 = await reg.addEvidence('eng:paul', car.id, { kind: 'assessment', filename: 'assessment-v1-draft.txt', data: sample('assessment-v1-draft.txt') });
  ok(`assessment v1    ${link(a1.sig)}`);
  const a2 = await reg.addEvidence('eng:paul', car.id, { kind: 'assessment', filename: 'assessment-v2-final.txt', data: sample('assessment-v2-final.txt'), supersedes: a1.id });
  ok(`assessment v2    ${link(a2.sig)} (links to v1 on-chain)`);
  await expectDenied('owner tries to revoke the assessment', () => reg.revokeEvidence('owner:max', a2.id, 'prefer the draft'));

  step('5. Owner shares selected items with a prospective buyer for 48 hours');
  const grant = reg.grantAccess('owner:max', car.id, 'buyer:jo', [history.id, a2.id], 48);
  ok(`grant ${grant.id} until ${grant.expiresAt}`);
  reg.readEvidence('buyer:jo', a2.id);
  ok('buyer reads the final assessment');
  await expectDenied('buyer opens the valuation', () => reg.readEvidence('buyer:jo', valuation.id));
  const buyerCheck = await reg.verifyEvidence('buyer:jo', a2.id);
  ok(`buyer verifies the assessment against the chain: ${buyerCheck.ok ? 'VALID' : 'INVALID'}`);

  step('6. Someone taps the hallmark');
  const tap1 = chip.tap();
  const s1 = reg.scanTag(tap1, 'phone:buyer');
  if (!s1.ok) throw new Error(s1.reason);
  ok(`genuine tap, counter ${s1.counter}: ${s1.year} ${s1.make} ${s1.model}, ${s1.activeEvidence} active items on record`);
  const r1 = reg.scanTag(tap1, 'phone:attacker');
  no(`same URL replayed: ${r1.ok ? 'ACCEPTED?!' : r1.reason}`);
  const clone = new SimulatedTag(uid, { metaKey: reg.tagKeysFor(uid).metaKey, fileKey: randomBytes(16) }, 50);
  const r2 = reg.scanTag(clone.tap(), 'phone:attacker');
  no(`cloned chip with copied UID but no key: ${r2.ok ? 'ACCEPTED?!' : r2.reason}`);
  const tap2 = chip.tap();
  const s2 = reg.scanTag(tap2, 'phone:buyer');
  ok(`genuine tap again, counter ${s2.ok ? s2.counter : '?'}`);

  step('7. Owner withdraws the photo uploaded by mistake');
  const rv = await reg.revokeEvidence('owner:max', wrong.id, 'wrong car in photo');
  ok(`revocation anchored ${link(rv.sig)} (reason kept off-chain)`);

  step('8. Car is sold: custody of the record moves to the new owner');
  await expectDenied('transfer without staff confirmation', () => reg.transferCustody('owner:max', car.id, 'owner:eva', 'owner:max'));
  const t = await reg.transferCustody('owner:max', car.id, 'owner:eva', 'staff:anna');
  ok(`custody epoch ${t.epoch} anchored ${link(t.sig)}`);
  await expectDenied('previous owner opens the valuation', () => reg.readEvidence('owner:max', valuation.id));
  await expectDenied('buyer:jo\'s grant from the previous owner', () => reg.readEvidence('buyer:jo', a2.id));
  reg.readEvidence('owner:eva', history.id);
  ok('new owner reads the full history');
  const g2 = reg.grantAccess('owner:eva', car.id, 'adviser:kim', [history.id, a2.id], 72);
  ok(`new owner shares history + assessment with adviser:kim until ${g2.expiresAt}`);

  step('9. Independent verification against the chain');
  for (const [name, id] of [['service history', history.id], ['assessment v2', a2.id], ['assessment v1 (superseded)', a1.id], ['wrong photo (revoked)', wrong.id]] as const) {
    const v = await reg.verifyEvidence('owner:eva', id);
    const why = v.checks.filter((c) => !c.ok).map((c) => (c.name === 'not revoked' ? 'withdrawn by its uploader' : c.detail ?? c.name));
    (v.ok ? ok : info)(`${name}: ${v.ok ? 'VALID' : `authentic but not current (${why.join(', ')})`}`);
  }
  const h = await reg.verifyHistory(car.id);
  for (const c of h.checks) (c.ok ? ok : no)(`${c.name}${c.detail ? `: ${c.detail}` : ''}`);
  const a = reg.verifyAuditLog();
  (a.ok ? ok : no)(`${a.name}: ${a.detail}`);
  if (!h.ok || !a.ok) throw new Error('verification failed');

  return { vehicleId: car.id, tagUid: uid.toString('hex'), tagCounter: s2.ok ? s2.counter : 0, lastTap: tap2 };
}

export function saveState(dir: string, s: DemoState) {
  fs.writeFileSync(path.join(dir, 'demo-state.json'), JSON.stringify(s, null, 2));
}

// Run only when invoked directly (the web server imports runDemo). pathToFileURL handles
// spaces and special characters in the path.
if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  const net: Network = network();
  if (net === 'devnet') {
    const balance = await solana().balance();
    if (balance < 0.001) {
      console.log(`Devnet address ${solana().signer} has no SOL. Run \`npm run fund\`, or try the local runtime: npm run demo:local`);
      process.exit(1);
    }
  }
  const { registry, chain, dir } = openRegistry(net, { fresh: true });
  console.log(`Network: ${net}${net === 'devnet' ? ` (registry key ${chain.signer})` : ' (in-process Solana runtime, nothing leaves this machine)'}`);
  const state = await runDemo(registry, chain);
  saveState(dir, state);
  console.log(net === 'local'
    ? '\nDone. The local runtime ends with this process; `npm run serve:local` replays the demo and serves it.'
    : '\nDone. Browse it with: npm run serve');
}
