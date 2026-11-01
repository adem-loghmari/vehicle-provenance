import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { ADMINS, ENGINEERS, network, openRegistry } from './env.js';
import { Denied, IntegrityError, NotFound } from './registry.js';
import { SimulatedTag } from './tag.js';
import { type DemoState, runDemo, saveState } from '../scripts/demo.js';

// A small read-mostly web view over the registry, for looking at a record through each
// participant's eyes. No auth: the "viewing as" switcher stands in for logged-in users.

const net = network();
const { registry: reg, chain, dir } = openRegistry(net);
const stateFile = path.join(dir, 'demo-state.json');
let state: DemoState;
if (net === 'local') {
  console.log('Local runtime: seeding the demo record...');
  state = await runDemo(reg, chain, () => {});
  saveState(dir, state);
} else if (fs.existsSync(stateFile)) {
  state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
} else {
  console.log('No devnet demo data yet. Run `npm run demo` first.');
  process.exit(1);
}

const PEOPLE = ['owner:eva', 'owner:max', 'buyer:jo', 'adviser:kim', ...ENGINEERS, ...ADMINS, 'stranger'];
const ROLE: Record<string, string> = {
  'owner:eva': 'current owner', 'owner:max': 'previous owner', 'buyer:jo': 'prospective buyer', 'adviser:kim': 'owner\'s adviser',
  'eng:paul': 'registry engineer', 'staff:anna': 'registry staff', stranger: 'not involved',
};

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const short = (sig: string) => `${sig.slice(0, 6)}…${sig.slice(-6)}`;
const sigLink = (sig: string | null) => (sig ? (net === 'devnet' ? `<a class="mono" href="${esc(chain.explorerUrl(sig))}" target="_blank" rel="noopener">${esc(short(sig))}</a>` : `<span class="mono" title="${esc(sig)}">${esc(short(sig))}</span>`) : '');
const time = (iso: string) => esc(iso.replace('T', ' ').slice(0, 16));

const CSS = `
:root{--bg:#f6f5f2;--card:#fff;--ink:#1d1d1b;--muted:#6b6a65;--line:#e4e2dc;--ok:#1f7a4d;--okbg:#e5f3ea;--bad:#a8321e;--badbg:#f8e7e3;--warn:#8a5a00;--warnbg:#fbf0d9;--accent:#1d3d5c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
header{background:var(--accent);color:#fff;padding:18px 24px}header h1{margin:0;font-size:20px;font-weight:600}header p{margin:2px 0 0;opacity:.8;font-size:13px}
main{max-width:1100px;margin:0 auto;padding:20px 16px 60px;display:grid;gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
h2{font-size:15px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.b{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.ok{background:var(--okbg);color:var(--ok)}.bad{background:var(--badbg);color:var(--bad)}.warn{background:var(--warnbg);color:var(--warn)}.neutral{background:#eceae4;color:var(--muted)}
.row{display:flex;gap:16px;flex-wrap:wrap;align-items:center}.grow{flex:1}
.people a{display:inline-block;margin:2px 4px 2px 0;padding:4px 10px;border:1px solid var(--line);border-radius:99px;text-decoration:none;color:var(--ink);font-size:13px;background:#fff}
.people a.on{background:var(--accent);color:#fff;border-color:var(--accent)}
button{font:inherit;font-size:13px;padding:6px 12px;border-radius:6px;border:1px solid var(--accent);background:#fff;color:var(--accent);cursor:pointer}button.primary{background:var(--accent);color:#fff}
form{display:inline}.checks div{padding:3px 0}.flash{border-left:4px solid var(--accent)}
pre{background:#f3f2ee;border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font-size:12.5px;margin:6px 0 0;white-space:pre-wrap}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.grid2{grid-template-columns:1fr}}
a{color:var(--accent)}.muted{color:var(--muted)}`;

function page(title: string, body: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${CSS}</style></head><body>
<header><h1>Vehicle Provenance Registry <span style="opacity:.6;font-weight:400">prototype</span></h1><p>Network: ${net === 'devnet' ? 'Solana devnet (public test network)' : 'local Solana runtime (in-process)'} · registry key <span class="mono">${esc(short(chain.signer))}</span></p></header>
<main>${body}</main></body></html>`;
}

const statusBadge = (s: string) => `<span class="b ${({ active: 'ok', superseded: 'warn', revoked: 'bad', shredded: 'neutral' } as Record<string, string>)[s] ?? 'neutral'}">${esc(s)}</span>`;
const checksHtml = (checks: { name: string; ok: boolean; detail?: string }[]) =>
  `<div class="checks">${checks.map((c) => `<div><span class="b ${c.ok ? 'ok' : 'bad'}">${c.ok ? 'pass' : 'fail'}</span> ${esc(c.name)}${c.detail ? ` <span class="muted mono">${esc(c.detail.length > 70 ? short(c.detail) : c.detail)}</span>` : ''}</div>`).join('')}</div>`;

function vehiclePage(vid: string, as: string, flash = '') {
  const v = reg.vehicle(vid);
  if (!v) throw new NotFound(`no record ${vid}`);
  const owner = reg.ownerOf(vid);
  const evidence = reg.listEvidence(as, vid);
  const isStaff = ADMINS.includes(as);
  const people = PEOPLE.map((p) => `<a class="${p === as ? 'on' : ''}" href="/v/${vid}?as=${encodeURIComponent(p)}">${esc(p)} <span style="opacity:.65">· ${esc(ROLE[p])}</span></a>`).join('');
  const grants = reg.grants(vid);
  const anchors = reg.anchors(vid);
  return page(`${v.year} ${v.make} ${v.model}`, `
${flash ? `<div class="card flash">${flash}</div>` : ''}
<div class="card"><div class="row"><div class="grow"><h2>Record</h2>
<div style="font-size:22px;font-weight:600">${esc(v.year)} ${esc(v.make)} ${esc(v.model)}</div>
<div class="muted">Record <span class="mono">${esc(vid)}</span> · ${as === owner || isStaff || ENGINEERS.includes(as) ? `VIN <span class="mono">${esc(v.vin)}</span> · ` : ''}current custodian: <b>${esc(owner)}</b></div></div>
<div><form method="post" action="/v/${vid}/verify?as=${encodeURIComponent(as)}"><button class="primary">Verify full history on-chain</button></form></div></div>
<div style="margin-top:12px" class="people"><span class="muted" style="font-size:13px;margin-right:6px">Viewing as</span>${people}</div></div>

<div class="card"><h2>Evidence visible to ${esc(as)}</h2>
${evidence.length ? `<table><tr><th>Item</th><th>Kind</th><th>Ver.</th><th>Status</th><th>Uploaded by</th><th>Anchor</th><th></th></tr>
${evidence.map((e) => `<tr><td>${esc(e.filename)}</td><td>${esc(e.kind)}</td><td>v${e.version}</td><td>${statusBadge(e.status)}</td><td>${esc(e.uploadedBy)}</td><td>${sigLink(e.anchor)}</td>
<td>${e.status === 'shredded' ? '' : `<a href="/e/${e.id}?as=${encodeURIComponent(as)}">open &amp; verify</a>`}</td></tr>`).join('')}</table>`
    : `<p class="muted">Nothing on this record is shared with ${esc(as)}. Owners, registry engineers and staff see the full record; anyone else only sees items covered by a live grant.</p>`}
</div>

<div class="grid2">
<div class="card"><h2>Hallmark (NTAG 424 DNA, simulated)</h2>
<p class="muted" style="margin-top:0">Chip <span class="mono">${esc(state.tagUid)}</span> · last counter seen: ${state.tagCounter}</p>
<div class="row"><form method="post" action="/v/${vid}/tap?as=${encodeURIComponent(as)}"><button>Tap genuine chip</button></form>
<form method="post" action="/v/${vid}/replay?as=${encodeURIComponent(as)}"><button>Replay last tap URL</button></form>
<form method="post" action="/v/${vid}/clone?as=${encodeURIComponent(as)}"><button>Tap a cloned chip</button></form></div></div>

<div class="card"><h2>Custody of the record</h2><table><tr><th>Custodian</th><th>Since</th><th>Until</th></tr>
${reg.custodyHistory(vid).map((c) => `<tr><td>${esc(c.owner)}</td><td>${time(c.since)}</td><td>${c.until ? time(c.until) : '<span class="b ok">current</span>'}</td></tr>`).join('')}</table>
<p class="muted" style="font-size:13px;margin-bottom:0">Custody of the digital record, not legal title. Transfers follow a confirmed sale.</p></div>
</div>

<div class="card"><h2>Sharing grants</h2>${grants.length ? `<table><tr><th>Grantee</th><th>Granted by</th><th>Items</th><th>Expires</th><th>Status</th></tr>
${grants.map((g) => {
    const live = !g.revoked_at && g.expires_at > new Date().toISOString();
    return `<tr><td>${esc(g.grantee)}</td><td>${esc(g.granted_by)}</td><td>${(JSON.parse(g.evidence_ids) as string[]).length}</td><td>${time(g.expires_at)}</td><td>${live ? '<span class="b ok">live</span>' : g.revoked_at ? '<span class="b bad">revoked</span>' : '<span class="b neutral">expired</span>'}</td></tr>`;
  }).join('')}</table>` : '<p class="muted">No grants.</p>'}</div>

<div class="card"><h2>On-chain anchors (public)</h2>
<p class="muted" style="margin-top:0;font-size:13px">Everything below is all the public chain knows: opaque ids and salted commitments. Each anchor points at the previous one for this record.</p>
<table><tr><th>#</th><th>Type</th><th>Transaction</th><th>Memo</th></tr>
${anchors.map((a, i) => `<tr><td>${i + 1}</td><td><span class="b neutral">${esc(a.type)}</span></td><td>${sigLink(a.sig)}</td><td class="mono" style="word-break:break-all">${esc(JSON.stringify(a.memo))}</td></tr>`).join('')}</table></div>

<div class="card"><h2>Audit log ${isStaff ? '' : '(staff view)'}</h2>
${isStaff ? `<p class="muted" style="margin-top:0;font-size:13px">${esc(reg.verifyAuditLog().detail)} · hash-chained, includes denied attempts.</p><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Outcome</th><th>Detail</th></tr>
${reg.auditLog(40).map((r) => `<tr><td class="mono" style="white-space:nowrap">${time(r.at)}</td><td>${esc(r.actor)}</td><td>${esc(r.action)}</td><td><span class="b ${r.outcome === 'ok' ? 'ok' : 'bad'}">${esc(r.outcome)}</span></td><td class="mono" style="word-break:break-all">${esc((r.detail || r.target || '').slice(0, 90))}</td></tr>`).join('')}</table>`
    : `<p class="muted">Only registry staff can see the audit log. <a href="/v/${vid}?as=staff%3Aanna">View as staff:anna</a></p>`}</div>`);
}

// Revoked or superseded items are still authentic; any other failed check means they are not.
const STALE = new Set(['not revoked', 'latest version']);
function verdict(checks: { name: string; ok: boolean }[]) {
  const failed = checks.filter((c) => !c.ok);
  const [cls, text] = failed.length === 0 ? ['ok', 'Verified against the chain']
    : failed.every((c) => STALE.has(c.name)) ? ['warn', 'Authentic, but not the current version']
    : ['bad', 'Verification failed: contents or anchor do not match'];
  return `<span class="b ${cls}" style="font-size:14px">${text}</span>`;
}

async function evidencePage(eid: string, as: string) {
  try {
    const data = reg.readEvidence(as, eid);
    const v = await reg.verifyEvidence(as, eid);
    const item = reg.listEvidence(as, state.vehicleId).find((e) => e.id === eid);
    return page('Evidence', `<div class="card"><p><a href="/v/${state.vehicleId}?as=${encodeURIComponent(as)}">&larr; back to record</a></p>
<h2>${esc(item?.filename ?? eid)} ${item ? statusBadge(item.status) : ''}</h2>
<div style="margin:10px 0">${verdict(v.checks)}</div>
${checksHtml(v.checks)}<h2 style="margin-top:16px">Decrypted contents (viewing as ${esc(as)})</h2><pre>${esc(data.toString('utf8'))}</pre></div>`);
  } catch (err) {
    if (err instanceof IntegrityError) {
      return page('Integrity check failed', `<div class="card"><p><a href="/v/${state.vehicleId}?as=${encodeURIComponent(as)}">&larr; back to record</a></p><h2>Integrity check failed</h2><p><span class="b bad">failed</span> ${esc(err.message)}. The file was not shown, and the event was written to the audit log.</p></div>`);
    }
    if (!(err instanceof Denied)) throw err;
    return page('Access denied', `<div class="card"><p><a href="/v/${state.vehicleId}?as=${encodeURIComponent(as)}">&larr; back to record</a></p><h2>Access denied</h2><p><span class="b bad">denied</span> ${esc(as)}: ${esc(err.message)}. The attempt was written to the audit log.</p></div>`);
  }
}

function tag(kind: 'tap' | 'replay' | 'clone', as: string) {
  const uid = Buffer.from(state.tagUid, 'hex');
  let msg;
  if (kind === 'tap') {
    msg = new SimulatedTag(uid, reg.tagKeysFor(uid), state.tagCounter).tap();
  } else if (kind === 'replay') {
    msg = state.lastTap!;
  } else {
    msg = new SimulatedTag(uid, { metaKey: reg.tagKeysFor(uid).metaKey, fileKey: randomBytes(16) }, state.tagCounter + 5).tap();
  }
  const r = reg.scanTag(msg, `phone:${as}`);
  if (kind === 'tap' && r.ok) {
    state = { ...state, tagCounter: r.counter, lastTap: msg };
    saveState(dir, state);
  }
  const url = `https://registry.example/t?picc=${msg.picc}&amp;cmac=${msg.cmac}`;
  const label = { tap: 'Genuine chip tapped', replay: 'Replayed a previously seen tap URL', clone: 'Cloned chip (copied UID, no secret key)' }[kind];
  return `<b>${label}</b><div class="mono muted" style="word-break:break-all;margin:4px 0">${url}</div>${r.ok
    ? `<span class="b ok">accepted</span> counter ${r.counter}: ${esc(r.year)} ${esc(r.make)} ${esc(r.model)}, ${r.activeEvidence} active items on record`
    : `<span class="b bad">rejected</span> ${esc(r.reason)}`}`;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://x');
    const as = url.searchParams.get('as') || 'owner:eva';
    const send = (html: string, code = 200) => { res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' }); res.end(html); };
    let m;
    if (url.pathname === '/') {
      res.writeHead(302, { location: `/v/${state.vehicleId}` });
      return res.end();
    }
    if ((m = /^\/v\/([\w]+)$/.exec(url.pathname)) && req.method === 'GET') return send(vehiclePage(m[1], as));
    if ((m = /^\/v\/([\w]+)\/verify$/.exec(url.pathname)) && req.method === 'POST') {
      if (!reg.vehicle(m[1])) throw new NotFound(`no record ${m[1]}`);
      const h = await reg.verifyHistory(m[1]);
      return send(vehiclePage(m[1], as, `<b>${h.ok ? 'History verified' : 'History verification FAILED'}</b> · ${h.events} anchors walked on-chain, newest to registration${checksHtml(h.checks)}`));
    }
    if ((m = /^\/v\/([\w]+)\/(tap|replay|clone)$/.exec(url.pathname)) && req.method === 'POST') {
      if (!reg.vehicle(m[1])) throw new NotFound(`no record ${m[1]}`);
      return send(vehiclePage(m[1], as, tag(m[2] as 'tap', as)));
    }
    if ((m = /^\/e\/([\w]+)$/.exec(url.pathname))) return send(await evidencePage(m[1], as));
    send(page('Not found', '<div class="card">Not found</div>'), 404);
  } catch (err) {
    if (err instanceof NotFound) {
      res.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(page('Not found', '<div class="card">Not found. <a href="/">Back to the record</a></div>'));
    }
    console.error(err);
    res.writeHead(500, { 'content-type': 'text/plain' });
    res.end('Something went wrong; details are in the server log.');
  }
});

const port = Number(process.env.PORT ?? 7077);
server.listen(port, '127.0.0.1', () => console.log(`Open http://localhost:${port}`));
