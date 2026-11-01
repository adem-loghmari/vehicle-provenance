import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { type Chain, LocalChain, SolanaChain, loadOrCreateKeypair } from './chain.js';
import { openDb } from './db.js';
import { Registry } from './registry.js';

// Local stand-ins for what would live in a KMS/HSM in production. Created on first run,
// kept in .keys/ (gitignored).
export const ROOT = path.resolve(import.meta.dirname, '..');
const KEYS = path.join(ROOT, '.keys');

export type Network = 'devnet' | 'local';
export const network = (): Network =>
  process.argv.includes('--local') || process.env.VPR_CHAIN === 'local' ? 'local' : 'devnet';

function secrets() {
  const file = path.join(KEYS, 'secrets.json');
  if (!fs.existsSync(file)) {
    fs.mkdirSync(KEYS, { recursive: true });
    const s = { kek: randomBytes(32).toString('hex'), tagMetaKey: randomBytes(16).toString('hex'), tagMasterKey: randomBytes(16).toString('hex') };
    fs.writeFileSync(file, JSON.stringify(s, null, 2), { mode: 0o600 });
  }
  const s = JSON.parse(fs.readFileSync(file, 'utf8'));
  return { kek: Buffer.from(s.kek, 'hex'), tagMetaKey: Buffer.from(s.tagMetaKey, 'hex'), tagMasterKey: Buffer.from(s.tagMasterKey, 'hex') };
}

export function solana() {
  return new SolanaChain(loadOrCreateKeypair(path.join(KEYS, 'registry-keypair.json')), process.env.SOLANA_RPC_URL);
}

export const ADMINS = ['staff:anna'];
export const ENGINEERS = ['eng:paul'];

export function dataDir(net: Network) {
  return path.join(ROOT, 'data', net);
}

/**
 * devnet: anchors are public and permanent, data persists between runs.
 * local: an in-process Solana runtime that lives only as long as the process, so its
 * data directory is wiped on every start.
 */
export function openRegistry(net: Network = network(), { fresh = false } = {}) {
  const dir = dataDir(net);
  if (fresh || net === 'local') fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const chain: Chain = net === 'local' ? new LocalChain() : solana();
  const db = openDb(path.join(dir, 'registry.db'));
  const registry = new Registry({ db, chain, ...secrets(), storageDir: path.join(dir, 'storage'), admins: ADMINS, engineers: ENGINEERS });
  return { registry, chain, db, dir };
}
