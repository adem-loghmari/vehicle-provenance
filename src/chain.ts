import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import {
  Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, Transaction, TransactionInstruction, clusterApiUrl,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import bs58 from 'bs58';
import type * as LiteSvmModule from 'litesvm';

// Anchors are small JSON memos written with Solana's Memo program and signed by the
// registry's key. The memo is public and permanent, so it carries only opaque ids and
// salted commitments: no names, no VINs, no document contents.

export const MEMO_PROGRAM = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
export const APP = 'vpr-poc' as const;

export interface Memo {
  app: typeof APP;
  v: 1;
  t: 'register' | 'evidence' | 'revoke' | 'transfer';
  rec: string; // vehicle record id
  prev: string | null; // previous anchor signature for this record
  [k: string]: unknown;
}

export interface FetchedAnchor {
  memo: Memo;
  signer: string;
  slot: number;
  blockTime: number | null;
}

/** One Memo instruction, signed by the registry key. */
export function anchorTx(memo: Memo, signer: PublicKey): Transaction {
  const data = Buffer.from(JSON.stringify(memo), 'utf8');
  if (data.length > 500) throw new Error(`memo too large (${data.length} bytes)`);
  return new Transaction().add(new TransactionInstruction({
    programId: MEMO_PROGRAM,
    keys: [{ pubkey: signer, isSigner: true, isWritable: false }],
    data,
  }));
}

/** Memos written by other apps (or garbage) are ignored rather than misread. */
function parseMemo(text: string): Memo | null {
  try {
    const m = JSON.parse(text);
    return m && typeof m === 'object' && m.app === APP && m.v === 1 && typeof m.rec === 'string' ? m : null;
  } catch {
    return null;
  }
}

export interface Chain {
  readonly signer: string;
  anchor(memo: Memo): Promise<string>;
  fetch(sig: string): Promise<FetchedAnchor | null>;
  /** Signatures of transactions signed by the registry key, newest first. */
  signatures(): Promise<string[]>;
  explorerUrl(sig: string): string;
}

export class SolanaChain implements Chain {
  readonly connection: Connection;
  constructor(private keypair: Keypair, rpcUrl = clusterApiUrl('devnet')) {
    this.connection = new Connection(rpcUrl, 'confirmed');
  }

  get signer() {
    return this.keypair.publicKey.toBase58();
  }

  async anchor(memo: Memo): Promise<string> {
    return sendAndConfirmTransaction(this.connection, anchorTx(memo, this.keypair.publicKey), [this.keypair], {
      commitment: 'confirmed',
    });
  }

  async fetch(sig: string): Promise<FetchedAnchor | null> {
    const tx = await this.connection.getParsedTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    if (!tx || tx.meta?.err) return null;
    const ix = tx.transaction.message.instructions.find((i) => i.programId.equals(MEMO_PROGRAM));
    if (!ix || !('parsed' in ix) || typeof ix.parsed !== 'string') return null;
    // The fee payer is the first account and always a signer. Anyone can write a memo
    // that looks like ours, so the signer is what makes an anchor authoritative.
    const signer = tx.transaction.message.accountKeys.find((k) => k.signer)?.pubkey.toBase58() ?? '';
    const memo = parseMemo(ix.parsed);
    return memo && { memo, signer, slot: tx.slot, blockTime: tx.blockTime ?? null };
  }

  async signatures(limit = 1000) {
    const out: string[] = [];
    let before: string | undefined;
    while (out.length < limit) {
      const page = await this.connection.getSignaturesForAddress(this.keypair.publicKey, { before, limit: 1000 });
      out.push(...page.filter((s) => !s.err).map((s) => s.signature));
      if (page.length < 1000) break;
      before = page.at(-1)!.signature;
    }
    return out;
  }

  explorerUrl(sig: string) {
    return `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
  }

  async balance() {
    return (await this.connection.getBalance(this.keypair.publicKey)) / LAMPORTS_PER_SOL;
  }

  async airdrop(sol = 1) {
    const sig = await this.connection.requestAirdrop(this.keypair.publicKey, sol * LAMPORTS_PER_SOL);
    await this.connection.confirmTransaction(sig, 'confirmed');
  }
}

/**
 * A real Solana runtime running in-process (LiteSVM): the actual Memo program executes,
 * signatures and fees are checked. Used when devnet isn't funded. Reads go through the
 * runtime's own transaction history and program logs, not a copy we kept ourselves.
 */
export class LocalChain implements Chain {
  // Required only when a LocalChain is created: LiteSVM ships native builds for macOS and
  // Linux only, and the devnet path must keep working without it.
  private lib: typeof LiteSvmModule = createRequire(import.meta.url)('litesvm');
  private svm = new this.lib.LiteSVM();
  private keypair = Keypair.generate();
  private slot = 0n;
  private sent: string[] = []; // LiteSVM has no per-address index like an RPC node, so keep one

  constructor() {
    this.svm.airdrop(this.keypair.publicKey, BigInt(LAMPORTS_PER_SOL));
  }

  get signer() {
    return this.keypair.publicKey.toBase58();
  }

  async anchor(memo: Memo) {
    const tx = anchorTx(memo, this.keypair.publicKey);
    tx.recentBlockhash = this.svm.latestBlockhash();
    tx.feePayer = this.keypair.publicKey;
    tx.sign(this.keypair);
    const res = this.svm.sendTransaction(tx);
    if (res instanceof this.lib.FailedTransactionMetadata) throw new Error(`anchor failed: ${res.err()}`);
    this.svm.warpToSlot(++this.slot); // fresh blockhash, so identical memos don't collide
    this.svm.expireBlockhash();
    const sig = bs58.encode(tx.signature!);
    this.sent.unshift(sig);
    return sig;
  }

  async signatures() {
    return [...this.sent];
  }

  async fetch(sig: string): Promise<FetchedAnchor | null> {
    const res = this.svm.getTransaction(bs58.decode(sig));
    if (!res || res instanceof this.lib.FailedTransactionMetadata) return null;
    const logs = res.logs();
    const signer = logs.map((l) => /^Program log: Signed by (\w+)$/.exec(l)?.[1]).find(Boolean);
    const body = logs.map((l) => /^Program log: Memo \(len \d+\): (".*")$/.exec(l)?.[1]).find(Boolean);
    if (!signer || !body) return null;
    const memo = parseMemo(JSON.parse(body));
    return memo && { memo, signer, slot: 0, blockTime: null };
  }

  explorerUrl(sig: string) {
    return `local://${sig}`;
  }
}

/** In-memory chain for tests: same interface, no network. */
export class MemoryChain implements Chain {
  readonly signer = 'memory-registry';
  private txs = new Map<string, FetchedAnchor>();
  private n = 0;

  async anchor(memo: Memo) {
    const sig = `memsig${++this.n}`;
    this.txs.set(sig, { memo: structuredClone(memo), signer: this.signer, slot: this.n, blockTime: null });
    return sig;
  }

  async fetch(sig: string) {
    return this.txs.get(sig) ?? null;
  }

  async signatures() {
    return [...this.txs.entries()].filter(([, a]) => a.signer === this.signer).map(([sig]) => sig).reverse();
  }

  explorerUrl(sig: string) {
    return `memory://${sig}`;
  }

  /** Test helper: plant an anchor signed by someone else. */
  forge(memo: Memo, signer: string) {
    const sig = `forged${++this.n}`;
    this.txs.set(sig, { memo, signer, slot: this.n, blockTime: null });
    return sig;
  }
}

export function loadOrCreateKeypair(file: string): Keypair {
  if (fs.existsSync(file)) return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, 'utf8'))));
  const kp = Keypair.generate();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
  return kp;
}
