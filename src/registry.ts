import fs from 'node:fs';
import path from 'node:path';
import { APP, type Chain, type Memo } from './chain.js';
import { commitment, decryptFile, encryptFile, newId, newSalt, sha256 } from './crypto.js';
import type { Db } from './db.js';
import { decodeSun, diversify, type SunMessage } from './tag.js';

export class Denied extends Error {}
export class NotFound extends Error {}
export class IntegrityError extends Error {}

export interface RegistryOptions {
  db: Db;
  chain: Chain;
  kek: Buffer; // 32 bytes, wraps per-file data keys
  tagMetaKey: Buffer; // 16 bytes, shared SDMMetaReadKey
  tagMasterKey: Buffer; // 16 bytes, per-tag file keys are derived from it
  storageDir: string;
  admins?: string[];
  engineers?: string[];
  now?: () => Date;
}

type Evidence = {
  id: string; vehicle_id: string; kind: string; filename: string; version: number; supersedes: string | null;
  file_sha256: string; salt: string; commitment: string; wrapped_key: Buffer | null; status: string;
  uploaded_by: string; created_at: string;
};
type Grant = {
  id: string; vehicle_id: string; granted_by: string; grantee: string; evidence_ids: string;
  expires_at: string; revoked_at: string | null; created_at: string;
};

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export class Registry {
  private db: Db;
  private chain: Chain;
  private admins: Set<string>;
  private engineers: Set<string>;
  private now: () => Date;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private o: RegistryOptions) {
    this.db = o.db;
    this.chain = o.chain;
    this.admins = new Set(o.admins ?? []);
    this.engineers = new Set(o.engineers ?? []);
    this.now = o.now ?? (() => new Date());
    fs.mkdirSync(o.storageDir, { recursive: true });
  }

  private ts() {
    return this.now().toISOString();
  }

  // ---------- audit ----------

  private audit(actor: string, action: string, target: string | null, outcome: 'ok' | 'denied' | 'error', detail?: string) {
    const prev = (this.db.prepare('SELECT hash FROM audit ORDER BY id DESC LIMIT 1').get() as { hash: string } | undefined)?.hash ?? 'genesis';
    const at = this.ts();
    const hash = sha256(JSON.stringify([prev, at, actor, action, target, outcome, detail ?? null]));
    this.db.prepare('INSERT INTO audit (at, actor, action, target, outcome, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)')
      .run(at, actor, action, target, outcome, detail ?? null, prev, hash);
  }

  /** Recomputes the audit hash chain. Any edited or deleted row breaks it from that point on. */
  verifyAuditLog(): Check {
    const rows = this.db.prepare('SELECT * FROM audit ORDER BY id').all() as any[];
    let prev = 'genesis';
    for (const r of rows) {
      const hash = sha256(JSON.stringify([prev, r.at, r.actor, r.action, r.target, r.outcome, r.detail]));
      if (r.prev_hash !== prev || r.hash !== hash) return { name: 'audit log chain', ok: false, detail: `broken at entry ${r.id}` };
      prev = r.hash;
    }
    return { name: 'audit log chain', ok: true, detail: `${rows.length} entries intact` };
  }

  auditLog(limit = 100) {
    return this.db.prepare('SELECT id, at, actor, action, target, outcome, detail FROM audit ORDER BY id DESC LIMIT ?').all(limit) as any[];
  }

  // ---------- helpers ----------

  /** Run anchoring operations one at a time so `prev` links can't fork. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async anchor(vehicleId: string, t: Memo['t'], ref: string | null, extra: Record<string, unknown> = {}) {
    const last = this.db.prepare('SELECT sig FROM anchors WHERE vehicle_id = ? ORDER BY rowid DESC LIMIT 1').get(vehicleId) as { sig: string } | undefined;
    const memo: Memo = { app: APP, v: 1, t, rec: vehicleId, prev: last?.sig ?? null, ...extra };
    const sig = await this.chain.anchor(memo);
    this.db.prepare('INSERT INTO anchors (sig, vehicle_id, type, ref, memo, created_at) VALUES (?,?,?,?,?,?)')
      .run(sig, vehicleId, t, ref, JSON.stringify(memo), this.ts());
    return sig;
  }

  private anchorFor(ref: string, type: Memo['t']) {
    return (this.db.prepare('SELECT sig FROM anchors WHERE ref = ? AND type = ?').get(ref, type) as { sig: string } | undefined)?.sig ?? null;
  }

  ownerOf(vehicleId: string): string | null {
    const row = this.db.prepare('SELECT owner FROM custody WHERE vehicle_id = ? AND until IS NULL').get(vehicleId) as { owner: string } | undefined;
    return row?.owner ?? null;
  }

  private evidence(id: string): Evidence {
    const e = this.db.prepare('SELECT * FROM evidence WHERE id = ?').get(id) as Evidence | undefined;
    if (!e) throw new NotFound(`no evidence ${id}`);
    return e;
  }

  private deny(actor: string, action: string, target: string, why: string): never {
    this.audit(actor, action, target, 'denied', why);
    throw new Denied(why);
  }

  private activeGrantsFor(actor: string, vehicleId: string): Grant[] {
    return this.db.prepare('SELECT * FROM grants WHERE vehicle_id = ? AND grantee = ? AND revoked_at IS NULL AND expires_at > ?')
      .all(vehicleId, actor, this.ts()) as Grant[];
  }

  /** Owner, staff and engineers see everything on a record; others only what a live grant covers. */
  canRead(actor: string, e: Evidence): boolean {
    if (this.ownerOf(e.vehicle_id) === actor || this.admins.has(actor) || this.engineers.has(actor)) return true;
    return this.activeGrantsFor(actor, e.vehicle_id).some((g) => (JSON.parse(g.evidence_ids) as string[]).includes(e.id));
  }

  // ---------- vehicles ----------

  registerVehicle(owner: string, v: { vin: string; make?: string; model?: string; year?: number }) {
    return this.serial(async () => {
      const id = newId('veh');
      const at = this.ts();
      this.db.transaction(() => {
        this.db.prepare('INSERT INTO vehicles (id, vin, make, model, year, created_at) VALUES (?,?,?,?,?,?)')
          .run(id, v.vin, v.make ?? null, v.model ?? null, v.year ?? null, at);
        this.db.prepare('INSERT INTO custody (vehicle_id, owner, since) VALUES (?,?,?)').run(id, owner, at);
      })();
      const sig = await this.anchor(id, 'register', id);
      this.audit(owner, 'register_vehicle', id, 'ok', sig);
      return { id, sig };
    });
  }

  vehicle(id: string) {
    return this.db.prepare('SELECT * FROM vehicles WHERE id = ?').get(id) as any;
  }

  // ---------- evidence ----------

  addEvidence(actor: string, vehicleId: string, f: { kind: string; filename: string; data: Buffer; supersedes?: string }) {
    return this.serial(async () => {
      const isOwner = this.ownerOf(vehicleId) === actor;
      const isEngineer = this.engineers.has(actor);
      if (!isOwner && !isEngineer) this.deny(actor, 'add_evidence', vehicleId, 'only the owner or a registry engineer can add evidence');
      // The engineering assessment is the registry's responsibility, so owners cannot file one.
      if (f.kind === 'assessment' && !isEngineer) this.deny(actor, 'add_evidence', vehicleId, 'assessments can only be filed by registry engineers');

      let version = 1;
      if (f.supersedes) {
        const old = this.evidence(f.supersedes);
        if (old.vehicle_id !== vehicleId || old.status !== 'active') this.deny(actor, 'add_evidence', vehicleId, 'can only supersede an active item on the same record');
        if (old.kind === 'assessment' && !isEngineer) this.deny(actor, 'add_evidence', vehicleId, 'only engineers can revise an assessment');
        version = old.version + 1;
      }

      const id = newId('ev');
      const fileSha = sha256(f.data);
      const salt = newSalt();
      const c = commitment(salt, fileSha);
      const { ciphertext, wrappedKey } = encryptFile(this.o.kek, f.data);
      fs.writeFileSync(path.join(this.o.storageDir, `${id}.bin`), ciphertext);

      this.db.transaction(() => {
        this.db.prepare(`INSERT INTO evidence (id, vehicle_id, kind, filename, version, supersedes, file_sha256, salt, commitment,
          wrapped_key, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
          .run(id, vehicleId, f.kind, f.filename, version, f.supersedes ?? null, fileSha, salt, c, wrappedKey, actor, this.ts());
        if (f.supersedes) this.db.prepare("UPDATE evidence SET status = 'superseded' WHERE id = ?").run(f.supersedes);
      })();

      const extra: Record<string, unknown> = { c, kind: f.kind, ver: version };
      if (f.supersedes) extra.sup = this.anchorFor(f.supersedes, 'evidence');
      const sig = await this.anchor(vehicleId, 'evidence', id, extra);
      this.audit(actor, 'add_evidence', id, 'ok', `${f.kind} v${version} ${sig}`);
      return { id, sig, version };
    });
  }

  revokeEvidence(actor: string, evidenceId: string, reason: string) {
    return this.serial(async () => {
      const e = this.evidence(evidenceId);
      // Owners may withdraw what they uploaded, but never an engineer's finding.
      const allowed = this.engineers.has(actor) || this.admins.has(actor) || (e.uploaded_by === actor && e.kind !== 'assessment');
      if (!allowed) this.deny(actor, 'revoke_evidence', evidenceId, 'not allowed to revoke this item');
      if (e.status !== 'active') this.deny(actor, 'revoke_evidence', evidenceId, `item is ${e.status}`);
      this.db.prepare("UPDATE evidence SET status = 'revoked' WHERE id = ?").run(evidenceId);
      // The reason stays off-chain; it may contain personal or confidential detail.
      const sig = await this.anchor(e.vehicle_id, 'revoke', evidenceId, { of: this.anchorFor(evidenceId, 'evidence') });
      this.audit(actor, 'revoke_evidence', evidenceId, 'ok', `${reason} ${sig}`);
      return { sig };
    });
  }

  readEvidence(actor: string, evidenceId: string): Buffer {
    const e = this.evidence(evidenceId);
    if (!this.canRead(actor, e)) this.deny(actor, 'read_evidence', evidenceId, 'no access');
    if (!e.wrapped_key) this.deny(actor, 'read_evidence', evidenceId, 'item was shredded');
    let data: Buffer | null = null;
    try {
      data = decryptFile(this.o.kek, e.wrapped_key, fs.readFileSync(path.join(this.o.storageDir, `${e.id}.bin`)));
    } catch {
      // AES-GCM refuses to decrypt modified ciphertext; a missing file lands here too.
    }
    if (!data || sha256(data) !== e.file_sha256) {
      this.audit(actor, 'read_evidence', evidenceId, 'error', 'integrity check failed');
      throw new IntegrityError('the stored file failed its integrity check (modified, corrupted or missing)');
    }
    this.audit(actor, 'read_evidence', evidenceId, 'ok');
    return data;
  }

  /** What `actor` may see on a record. Metadata only; contents go through readEvidence. */
  listEvidence(actor: string, vehicleId: string) {
    const rows = this.db.prepare('SELECT * FROM evidence WHERE vehicle_id = ? ORDER BY created_at').all(vehicleId) as Evidence[];
    return rows.filter((e) => this.canRead(actor, e)).map((e) => ({
      id: e.id, kind: e.kind, filename: e.filename, version: e.version, supersedes: e.supersedes, status: e.status,
      uploadedBy: e.uploaded_by, createdAt: e.created_at, anchor: this.anchorFor(e.id, 'evidence'), revokeAnchor: this.anchorFor(e.id, 'revoke'),
    }));
  }

  /** Crypto-shredding: destroy the data key and ciphertext. The on-chain commitment reveals nothing on its own. */
  shredEvidence(actor: string, evidenceId: string, reason: string) {
    if (!this.admins.has(actor)) this.deny(actor, 'shred_evidence', evidenceId, 'only staff can shred');
    this.db.prepare("UPDATE evidence SET wrapped_key = NULL, status = 'shredded' WHERE id = ?").run(evidenceId);
    fs.rmSync(path.join(this.o.storageDir, `${evidenceId}.bin`), { force: true });
    this.audit(actor, 'shred_evidence', evidenceId, 'ok', reason);
  }

  // ---------- sharing ----------

  grantAccess(actor: string, vehicleId: string, grantee: string, evidenceIds: string[], hours: number) {
    if (this.ownerOf(vehicleId) !== actor) this.deny(actor, 'grant_access', vehicleId, 'only the current owner can share');
    if (!(hours > 0) || evidenceIds.length === 0) throw new Error('a grant needs at least one item and a positive duration');
    for (const id of evidenceIds) {
      const e = this.evidence(id);
      if (e.vehicle_id !== vehicleId) this.deny(actor, 'grant_access', vehicleId, `${id} is not on this record`);
    }
    const id = newId('gr');
    const expires = new Date(this.now().getTime() + hours * 3600_000).toISOString();
    this.db.prepare('INSERT INTO grants (id, vehicle_id, granted_by, grantee, evidence_ids, expires_at, created_at) VALUES (?,?,?,?,?,?,?)')
      .run(id, vehicleId, actor, grantee, JSON.stringify(evidenceIds), expires, this.ts());
    this.audit(actor, 'grant_access', id, 'ok', `${grantee}: ${evidenceIds.length} item(s) until ${expires}`);
    return { id, expiresAt: expires };
  }

  revokeAccess(actor: string, grantId: string) {
    const g = this.db.prepare('SELECT * FROM grants WHERE id = ?').get(grantId) as Grant | undefined;
    if (!g) throw new NotFound(`no grant ${grantId}`);
    if (g.granted_by !== actor && this.ownerOf(g.vehicle_id) !== actor) this.deny(actor, 'revoke_access', grantId, 'not your grant');
    this.db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(this.ts(), grantId);
    this.audit(actor, 'revoke_access', grantId, 'ok');
  }

  grants(vehicleId: string) {
    return this.db.prepare('SELECT * FROM grants WHERE vehicle_id = ? ORDER BY created_at').all(vehicleId) as Grant[];
  }

  // ---------- custody ----------

  /**
   * Hands control of the digital record to a new owner. This is deliberately not called
   * "change of ownership": the legal sale happens off-platform (contract, papers), and a
   * registry admin or both parties confirm it before the record follows.
   */
  transferCustody(actor: string, vehicleId: string, newOwner: string, confirmedBy: string) {
    return this.serial(async () => {
      const current = this.ownerOf(vehicleId);
      if (current !== actor) this.deny(actor, 'transfer_custody', vehicleId, 'only the current owner can start a transfer');
      if (newOwner === current) throw new Error('new owner is already the custodian');
      if (!this.admins.has(confirmedBy)) this.deny(actor, 'transfer_custody', vehicleId, 'transfer must be confirmed by registry staff');
      const at = this.ts();
      let custodyId = 0;
      this.db.transaction(() => {
        this.db.prepare('UPDATE custody SET until = ? WHERE vehicle_id = ? AND until IS NULL').run(at, vehicleId);
        custodyId = Number(this.db.prepare('INSERT INTO custody (vehicle_id, owner, since) VALUES (?,?,?)').run(vehicleId, newOwner, at).lastInsertRowid);
        // Shares made by the previous owner end with their custody.
        this.db.prepare('UPDATE grants SET revoked_at = ? WHERE vehicle_id = ? AND granted_by = ? AND revoked_at IS NULL').run(at, vehicleId, current);
      })();
      const epoch = (this.db.prepare('SELECT COUNT(*) n FROM custody WHERE vehicle_id = ?').get(vehicleId) as { n: number }).n;
      const sig = await this.anchor(vehicleId, 'transfer', String(custodyId), { epoch });
      this.audit(actor, 'transfer_custody', vehicleId, 'ok', `to ${newOwner}, confirmed by ${confirmedBy}, ${sig}`);
      return { sig, epoch };
    });
  }

  custodyHistory(vehicleId: string) {
    return this.db.prepare('SELECT owner, since, until FROM custody WHERE vehicle_id = ? ORDER BY id').all(vehicleId) as any[];
  }

  // ---------- physical tags ----------

  bindTag(actor: string, vehicleId: string, uidHex: string) {
    if (!this.admins.has(actor)) this.deny(actor, 'bind_tag', vehicleId, 'only staff can bind tags');
    this.db.prepare('INSERT INTO tags (uid, vehicle_id, bound_at) VALUES (?,?,?)').run(uidHex.toLowerCase(), vehicleId, this.ts());
    this.audit(actor, 'bind_tag', vehicleId, 'ok', uidHex);
  }

  /** Key material to program into a new chip at the workshop. */
  tagKeysFor(uid: Buffer) {
    return { metaKey: this.o.tagMetaKey, fileKey: diversify(this.o.tagMasterKey, uid) };
  }

  /**
   * Verifies a tap on the vehicle's hallmark. Rejects forged MACs, unknown chips, and
   * replays (a counter not higher than the last one seen, i.e. a copied URL or a clone).
   */
  scanTag(msg: SunMessage, scanner = 'public') {
    let scan;
    try {
      scan = decodeSun(msg, { metaKey: this.o.tagMetaKey, fileKey: (uid) => diversify(this.o.tagMasterKey, uid) });
    } catch (err) {
      this.audit(scanner, 'scan_tag', null, 'denied', (err as Error).message);
      return { ok: false as const, reason: (err as Error).message };
    }
    const tag = this.db.prepare('SELECT * FROM tags WHERE uid = ?').get(scan.uid) as { vehicle_id: string; last_counter: number } | undefined;
    if (!tag) {
      this.audit(scanner, 'scan_tag', scan.uid, 'denied', 'genuine chip but not bound to any record');
      return { ok: false as const, reason: 'tag not bound to a vehicle' };
    }
    const updated = this.db.prepare('UPDATE tags SET last_counter = ? WHERE uid = ? AND last_counter < ?').run(scan.counter, scan.uid, scan.counter);
    if (updated.changes === 0) {
      this.audit(scanner, 'scan_tag', tag.vehicle_id, 'denied', `replayed counter ${scan.counter} (last seen ${tag.last_counter})`);
      return { ok: false as const, reason: `replayed scan: counter ${scan.counter} already used (last seen ${tag.last_counter})` };
    }
    this.audit(scanner, 'scan_tag', tag.vehicle_id, 'ok', `counter ${scan.counter}`);
    const v = this.vehicle(tag.vehicle_id);
    const anchored = (this.db.prepare("SELECT COUNT(*) n FROM evidence WHERE vehicle_id = ? AND status = 'active'").get(tag.vehicle_id) as { n: number }).n;
    // A public tap reveals only what a prospective buyer should see: the car and that a record exists.
    return { ok: true as const, vehicleId: v.id, make: v.make, model: v.model, year: v.year, counter: scan.counter, activeEvidence: anchored };
  }

  // ---------- verification ----------

  /** Re-derives an item's commitment from its decrypted contents and checks it against the chain. */
  async verifyEvidence(actor: string, evidenceId: string): Promise<{ ok: boolean; checks: Check[] }> {
    const e = this.evidence(evidenceId);
    const data = this.readEvidence(actor, evidenceId);
    const checks: Check[] = [];
    const sig = this.anchorFor(evidenceId, 'evidence');
    const onChain = sig ? await this.chain.fetch(sig) : null;
    checks.push({ name: 'anchor found on-chain', ok: !!onChain, detail: sig ?? 'no anchor recorded' });
    if (onChain) {
      checks.push({ name: 'signed by the registry key', ok: onChain.signer === this.chain.signer, detail: onChain.signer });
      checks.push({ name: 'anchor is for this record', ok: onChain.memo.rec === e.vehicle_id && onChain.memo.t === 'evidence' });
      checks.push({ name: 'contents match on-chain commitment', ok: commitment(e.salt, sha256(data)) === onChain.memo.c });
    }
    const revoked = this.anchorFor(evidenceId, 'revoke');
    checks.push({ name: 'not revoked', ok: !revoked, detail: revoked ? `withdrawn, see anchor ${revoked}` : undefined });
    if (e.status === 'superseded') checks.push({ name: 'latest version', ok: false, detail: 'superseded by a newer version' });
    return { ok: checks.every((c) => c.ok), checks };
  }

  /**
   * Walks the record's anchor chain on-chain from the newest anchor back to registration
   * and compares it with the local database. Catches local edits, deleted events, and
   * memos planted by someone other than the registry.
   */
  async verifyHistory(vehicleId: string): Promise<{ ok: boolean; checks: Check[]; events: number }> {
    const local = this.db.prepare('SELECT sig, memo FROM anchors WHERE vehicle_id = ? ORDER BY rowid').all(vehicleId) as { sig: string; memo: string }[];
    const checks: Check[] = [];
    let sig: string | null = local.at(-1)?.sig ?? null;
    const walked: string[] = [];
    while (sig) {
      const a = await this.chain.fetch(sig);
      if (!a) { checks.push({ name: 'anchor reachable', ok: false, detail: sig }); break; }
      if (a.signer !== this.chain.signer) { checks.push({ name: 'signed by the registry key', ok: false, detail: sig }); break; }
      if (a.memo.rec !== vehicleId) { checks.push({ name: 'anchor belongs to record', ok: false, detail: sig }); break; }
      const mine = local.find((l) => l.sig === sig);
      if (!mine || mine.memo !== JSON.stringify(a.memo)) { checks.push({ name: 'local copy matches chain', ok: false, detail: sig }); break; }
      walked.unshift(sig);
      sig = a.memo.prev;
    }
    if (checks.length === 0) {
      // Walking back from our newest anchor can't see events newer than it. If someone
      // deleted the latest local rows (say, a revocation), the walk would still pass, so
      // ask the chain for the registry key's newest anchor on this record and compare.
      const tip = await this.latestOnChain(vehicleId);
      checks.push({ name: 'local history is up to date with the chain', ok: tip === (local.at(-1)?.sig ?? null), detail: tip && tip !== local.at(-1)?.sig ? `newest on-chain anchor ${tip} is missing locally` : undefined });
      checks.push({ name: 'every anchor signed by the registry', ok: true });
      checks.push({ name: 'chain reaches registration', ok: walked.length > 0 && JSON.parse(local[0].memo).t === 'register' && walked[0] === local[0].sig });
      checks.push({ name: 'no local events missing from the chain', ok: walked.length === local.length, detail: `${walked.length} on-chain, ${local.length} local` });
    }
    return { ok: checks.every((c) => c.ok), checks, events: walked.length };
  }

  private async latestOnChain(vehicleId: string): Promise<string | null> {
    for (const sig of await this.chain.signatures()) {
      const a = await this.chain.fetch(sig);
      if (a && a.signer === this.chain.signer && a.memo.rec === vehicleId) return sig;
    }
    return null;
  }

  anchors(vehicleId: string) {
    return (this.db.prepare('SELECT sig, type, ref, memo, created_at FROM anchors WHERE vehicle_id = ? ORDER BY rowid').all(vehicleId) as any[])
      .map((a) => ({ ...a, memo: JSON.parse(a.memo), url: this.chain.explorerUrl(a.sig) }));
  }
}
