// MSP Server Tracker — Cloudflare Worker
// Deploy target : digsyndemos.com/server
// DB binding    : DB  (D1)
// Initialize DB : npx wrangler d1 execute msp-tracker --file=schema.sql --remote
// Deploy        : npx wrangler deploy

const BASE = '/server';

// ── CORS & response helpers ──────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const J = (data, status = 200) =>
  Response.json(data, { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
const E = (msg, status = 400) => J({ error: msg }, status);

// ── Worker entry ─────────────────────────────────────────────────────────────
export default {
  async fetch(req, env) {
    const url  = new URL(req.url);
    const path = url.pathname.replace(/\/$/, '') || '/';

    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    // Serve HTML at /server or /server/
    if (path === BASE || path === BASE + '/') {
      return new Response(HTML, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }

    // API routes under /server/api/
    if (path.startsWith(BASE + '/api')) {
      const sub = path.slice((BASE + '/api').length) || '/';
      return route(req, env, sub, url);
    }

    return new Response('Not found', { status: 404 });
  }
};

// ── API router ───────────────────────────────────────────────────────────────
async function route(req, env, path, url) {
  const m  = req.method;
  const db = env.DB;

  try {

    // ── GET /servers ──────────────────────────────────────────────────────
    if (path === '/servers' && m === 'GET') {
      const r = await db.prepare(
        'SELECT * FROM servers ORDER BY server_name COLLATE NOCASE'
      ).all();
      return J(r.results);
    }

    // ── POST /servers ─────────────────────────────────────────────────────
    if (path === '/servers' && m === 'POST') {
      const b = await req.json();
      if (!b.server_name?.trim()) return E('server_name is required');
      const r = await db.prepare(
        `INSERT INTO servers (server_name, type, environment, status, enabled, enabled_date, monthly_cost, notes)
         VALUES (?,?,?,'active',0,null,?,?)`
      ).bind(
        b.server_name.trim(),
        (b.type || '').trim(),
        (b.environment || '').trim(),
        parseFloat(b.monthly_cost) || 0,
        (b.notes || '').trim()
      ).run();
      return J({ id: r.meta.last_row_id }, 201);
    }

    // ── PUT /servers/:id ──────────────────────────────────────────────────
    const mEdit = path.match(/^\/servers\/(\d+)$/);
    if (mEdit && m === 'PUT') {
      const id = mEdit[1];
      const b  = await req.json();
      if (!b.server_name?.trim()) return E('server_name is required');
      await db.prepare(
        `UPDATE servers SET server_name=?, type=?, environment=?, monthly_cost=?, notes=? WHERE id=?`
      ).bind(
        b.server_name.trim(),
        (b.type || '').trim(),
        (b.environment || '').trim(),
        parseFloat(b.monthly_cost) || 0,
        (b.notes || '').trim(),
        id
      ).run();
      return J({ ok: true });
    }

    // ── DELETE /servers/:id ───────────────────────────────────────────────
    if (mEdit && m === 'DELETE') {
      await db.prepare('DELETE FROM servers WHERE id=?').bind(mEdit[1]).run();
      return J({ ok: true });
    }

    // ── POST /servers/:id/toggle ──────────────────────────────────────────
    const mToggle = path.match(/^\/servers\/(\d+)\/toggle$/);
    if (mToggle && m === 'POST') {
      const id      = mToggle[1];
      const b       = await req.json();
      const enabled = b.enabled ? 1 : 0;
      const eDate   = enabled ? new Date().toISOString().slice(0, 10) : null;

      await db.prepare(
        'UPDATE servers SET enabled=?, enabled_date=? WHERE id=?'
      ).bind(enabled, eDate, id).run();

      const srv = await db.prepare('SELECT server_name FROM servers WHERE id=?').bind(id).first();
      await db.prepare(
        'INSERT INTO status_logs (server_id, server_name, action, notes) VALUES (?,?,?,?)'
      ).bind(id, srv?.server_name || '', enabled ? 'enabled' : 'disabled', b.notes || '').run();

      return J({ ok: true });
    }

    // ── POST /servers/:id/decommission ────────────────────────────────────
    const mDecomm = path.match(/^\/servers\/(\d+)\/decommission$/);
    if (mDecomm && m === 'POST') {
      const id = mDecomm[1];
      const b  = await req.json();
      await db.prepare(
        `UPDATE servers SET status='decommissioned', enabled=0, enabled_date=null WHERE id=?`
      ).bind(id).run();
      const srv = await db.prepare('SELECT server_name FROM servers WHERE id=?').bind(id).first();
      await db.prepare(
        'INSERT INTO status_logs (server_id, server_name, action, notes) VALUES (?,?,?,?)'
      ).bind(id, srv?.server_name || '', 'decommissioned', b.notes || '').run();
      return J({ ok: true });
    }

    // ── GET /logs ─────────────────────────────────────────────────────────
    if (path === '/logs' && m === 'GET') {
      const sid = url.searchParams.get('server_id');
      let q = 'SELECT * FROM status_logs';
      const p = [];
      if (sid) { q += ' WHERE server_id=?'; p.push(sid); }
      q += ' ORDER BY timestamp DESC LIMIT 2000';
      const r = p.length
        ? await db.prepare(q).bind(...p).all()
        : await db.prepare(q).all();
      return J(r.results);
    }

    // ── GET /transactions ─────────────────────────────────────────────────
    if (path === '/transactions' && m === 'GET') {
      const params = [];
      let q = 'SELECT * FROM transactions WHERE 1=1';
      const sid   = url.searchParams.get('server_id');
      const start = url.searchParams.get('start');
      const end   = url.searchParams.get('end');
      const txnid = url.searchParams.get('txn_id');
      if (sid)   { q += ' AND server_id=?';  params.push(sid); }
      if (start) { q += ' AND date>=?';       params.push(start); }
      if (end)   { q += ' AND date<=?';       params.push(end); }
      if (txnid) { q += ' AND txn_id=?';      params.push(txnid); }
      q += ' ORDER BY created_at DESC LIMIT 5000';
      const r = params.length
        ? await db.prepare(q).bind(...params).all()
        : await db.prepare(q).all();
      return J(r.results);
    }

    // ── POST /transactions ────────────────────────────────────────────────
    if (path === '/transactions' && m === 'POST') {
      const body  = await req.json();
      const items = Array.isArray(body) ? body : [body];
      if (!items.length) return E('No items');
      const stmt = db.prepare(
        `INSERT INTO transactions
          (txn_id, server_id, server_name, action, amount, days_billed, period_start, period_end, date, notes)
         VALUES (?,?,?,?,?,?,?,?,?,?)`
      );
      const batch = items.map(t => stmt.bind(
        t.txn_id,
        t.server_id || null,
        t.server_name,
        t.action || 'billing',
        parseFloat(t.amount) || 0,
        parseInt(t.days_billed) || 0,
        t.period_start || null,
        t.period_end   || null,
        t.date || new Date().toISOString().slice(0, 10),
        t.notes || ''
      ));
      await db.batch(batch);
      return J({ ok: true, count: items.length }, 201);
    }

    // ── POST /import ──────────────────────────────────────────────────────
    if (path === '/import' && m === 'POST') {
      const items = await req.json();
      if (!Array.isArray(items) || !items.length) return E('No rows to import');
      const stmt = db.prepare(
        `INSERT INTO servers (server_name, type, environment, status, enabled, enabled_date, monthly_cost, notes)
         VALUES (?,?,?,'active',0,null,?,?)`
      );
      const batch = items.map(row => {
        const name = (row.server_name || row['Server Name'] || row['ServerName'] || '').trim();
        return stmt.bind(
          name || 'Unnamed',
          (row.type        || row['Type']         || '').trim(),
          (row.environment || row['Environment']   || '').trim(),
          parseFloat(row.monthly_cost || row['Monthly Cost'] || row['MonthlyCost'] || 0),
          (row.notes       || row['Notes']         || '').trim()
        );
      });
      await db.batch(batch);
      return J({ ok: true, imported: items.length }, 201);
    }

    return E('Not found', 404);

  } catch (err) {
    console.error(err);
    return E(err.message || 'Server error', 500);
  }
}

// ── Embedded HTML ─────────────────────────────────────────────────────────────
// NOTE: The embedded <script> block uses plain string concatenation (no JS template
// literals) so this outer template literal stays clean with no escaping needed.
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MSP Server Tracker</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></scr` + `ipt>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0d;--sur:#181818;--sur2:#222;--sur3:#2c2c2c;
  --bd:#363636;--tx:#e4e4e4;--tx2:#999;--tx3:#555;
  --ac:#4f8ef7;--ach:#3a75d4;
  --grn:#22c55e;--grnd:rgba(34,197,94,.12);
  --red:#ef4444;--redd:rgba(239,68,68,.12);
  --ylw:#fbbf24;--org:#f97316;
  --trkon:#22c55e;--trkoff:#484848;
  --r:6px;--sh:0 2px 10px rgba(0,0,0,.55);
}
body{background:var(--bg);color:var(--tx);font:14px/1.5 'Segoe UI',system-ui,sans-serif;min-height:100vh}

/* Header */
header{background:var(--sur);border-bottom:1px solid var(--bd);padding:10px 20px;display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}
header h1{font-size:17px;font-weight:700;white-space:nowrap;letter-spacing:-.3px}
header h1 span{color:var(--ac)}
.srch{flex:1;max-width:380px}
.srch input{width:100%;background:var(--sur2);border:1px solid var(--bd);color:var(--tx);padding:7px 12px;border-radius:var(--r);font-size:13px}
.srch input:focus{outline:none;border-color:var(--ac)}
.srch input::placeholder{color:var(--tx3)}

/* Tabs */
.tabbar{background:var(--sur);border-bottom:1px solid var(--bd);padding:0 20px;display:flex;overflow-x:auto;gap:0}
.tabbar::-webkit-scrollbar{height:3px}
.tabbar::-webkit-scrollbar-thumb{background:var(--bd)}
.tb{padding:11px 18px;background:none;border:none;border-bottom:2px solid transparent;color:var(--tx2);cursor:pointer;font-size:13px;font-weight:500;white-space:nowrap;transition:color .15s}
.tb:hover{color:var(--tx)}
.tb.active{color:var(--ac);border-bottom-color:var(--ac)}

/* Layout */
main{padding:18px 20px;max-width:1440px;margin:0 auto}
.tab{display:none}
.tab.active{display:block}

/* Toolbar */
.toolbar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.tright{margin-left:auto;display:flex;gap:6px;align-items:center}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.filters select,.filters input[type=date],.filters input[type=text]{
  background:var(--sur2);border:1px solid var(--bd);color:var(--tx);
  padding:6px 10px;border-radius:var(--r);font-size:13px}
.filters select:focus,.filters input:focus{outline:none;border-color:var(--ac)}

/* Table */
.twrap{overflow-x:auto;border-radius:var(--r);border:1px solid var(--bd)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead{background:var(--sur2)}
th{padding:9px 12px;text-align:left;color:var(--tx2);font-weight:600;white-space:nowrap;border-bottom:1px solid var(--bd);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td{padding:9px 12px;border-bottom:1px solid var(--bd);vertical-align:middle}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--sur2)}
.nc{max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sum td{font-weight:700;background:var(--sur2);border-top:2px solid var(--bd)}

/* Badges */
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.badge-active{background:var(--grnd);color:var(--grn)}
.badge-decommissioned{background:var(--redd);color:var(--red)}
.badge-enabled{background:var(--grnd);color:var(--grn)}
.badge-disabled{background:rgba(80,80,80,.2);color:var(--tx2)}

/* Toggle */
.toggle{position:relative;width:38px;height:21px;flex-shrink:0;display:inline-flex}
.toggle input{opacity:0;width:0;height:0;position:absolute}
.trk{position:absolute;inset:0;background:var(--trkoff);border-radius:11px;cursor:pointer;transition:background .2s}
.trk::after{content:'';position:absolute;left:3px;top:3px;width:15px;height:15px;background:#fff;border-radius:50%;transition:transform .2s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.toggle input:checked+.trk{background:var(--trkon)}
.toggle input:checked+.trk::after{transform:translateX(17px)}
.toggle input:disabled+.trk{opacity:.35;cursor:not-allowed}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 13px;border-radius:var(--r);font-size:13px;font-weight:500;cursor:pointer;border:none;transition:all .15s;white-space:nowrap}
.btn-pri{background:var(--ac);color:#fff}
.btn-pri:hover{background:var(--ach)}
.btn-ok{background:#16a34a;color:#fff}
.btn-ok:hover{background:#15803d}
.btn-del{background:#dc2626;color:#fff}
.btn-del:hover{background:#b91c1c}
.btn-warn{background:#b45309;color:#fff}
.btn-warn:hover{background:#92400e}
.btn-gh{background:var(--sur2);color:var(--tx2);border:1px solid var(--bd)}
.btn-gh:hover{background:var(--sur3);color:var(--tx)}
.btn-sm{padding:4px 9px;font-size:12px}
.actions{display:flex;gap:5px;align-items:center}

/* Highlight */
mark{background:var(--ylw);color:#000;padding:0 2px;border-radius:2px}

/* Modal */
.moverlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.78);z-index:200;align-items:center;justify-content:center;padding:20px}
.moverlay.open{display:flex}
.modal{background:var(--sur);border:1px solid var(--bd);border-radius:8px;padding:22px;width:100%;max-width:460px;box-shadow:var(--sh)}
.modal h2{font-size:15px;font-weight:700;margin-bottom:18px}
.fg{margin-bottom:13px}
.fg label{display:block;color:var(--tx2);font-size:11px;font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.fg input,.fg select,.fg textarea{width:100%;background:var(--sur2);border:1px solid var(--bd);color:var(--tx);padding:8px 11px;border-radius:var(--r);font-size:13px;font-family:inherit}
.fg textarea{height:68px;resize:vertical}
.fg input:focus,.fg select:focus,.fg textarea:focus{outline:none;border-color:var(--ac)}
.mfoot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}

/* Toast */
#toast{position:fixed;bottom:22px;right:22px;padding:11px 18px;background:var(--sur3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx);font-size:13px;box-shadow:var(--sh);z-index:999;opacity:0;transform:translateY(8px);transition:all .22s;pointer-events:none}
#toast.show{opacity:1;transform:translateY(0)}
#toast.ok{border-color:var(--grn)}
#toast.err{border-color:var(--red)}

/* Spinner / empty */
.spin{display:inline-block;width:15px;height:15px;border:2px solid var(--bd);border-top-color:var(--ac);border-radius:50%;animation:sp .6s linear infinite;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
.empty{text-align:center;padding:36px;color:var(--tx2)}

/* TXN pill */
.pill{display:inline-block;padding:2px 7px;background:rgba(79,142,247,.15);color:var(--ac);border-radius:8px;font-size:11px;font-family:monospace;font-weight:700;letter-spacing:.3px}

/* Billing total */
.btotal{background:var(--sur);border:1px solid var(--bd);border-radius:var(--r);padding:14px 18px;margin-top:14px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.btotal .lbl{color:var(--tx2);font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px}
.btotal .amt{color:var(--ylw);font-size:22px;font-weight:700}
.btotal .sub{color:var(--tx2);font-size:12px}

/* Footer */
footer{text-align:center;padding:18px;color:var(--tx3);font-size:12px;margin-top:36px}
footer a{color:var(--ac);text-decoration:none}

/* Responsive */
@media(max-width:768px){
  header{flex-wrap:wrap}
  header h1{font-size:15px}
  .srch{width:100%;max-width:100%}
  main{padding:12px}
  .tright{margin-left:0;width:100%}
  .toolbar{gap:6px}
}
</style>
</head>
<body>

<header>
  <h1>MSP <span>Server</span> Tracker</h1>
  <div class="srch">
    <input type="text" id="gSearch" placeholder="Search across all tabs..." oninput="onSearch(this.value)">
  </div>
</header>

<nav class="tabbar">
  <button class="tb active" data-tab="dashboard" onclick="showTab('dashboard')">&#128202; Dashboard</button>
  <button class="tb" data-tab="logs"      onclick="showTab('logs')">&#128203; Status Log</button>
  <button class="tb" data-tab="txn"       onclick="showTab('txn')">&#128176; Transactions</button>
  <button class="tb" data-tab="billing"   onclick="showTab('billing')">&#129534; Monthly Billing</button>
</nav>

<main>

<!-- ── DASHBOARD ─────────────────────────────────────────────────────────── -->
<div id="tab-dashboard" class="tab active">
  <div class="toolbar">
    <button class="btn btn-pri" onclick="openAdd()">&#43; Add Server</button>
    <button class="btn btn-gh"  onclick="openImport()">&#8659; Import CSV / Excel</button>
    <div class="tright">
      <select id="fStatus" onchange="renderDash()">
        <option value="">All Status</option>
        <option value="active">Active</option>
        <option value="decommissioned">Decommissioned</option>
      </select>
      <select id="fEnabled" onchange="renderDash()">
        <option value="">All</option>
        <option value="1">Enabled</option>
        <option value="0">Disabled</option>
      </select>
      <button class="btn btn-gh btn-sm" onclick="xCSV('dashTbl','servers')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('dashTbl','servers')">XLS</button>
    </div>
  </div>
  <div class="twrap">
    <table id="dashTbl">
      <thead><tr>
        <th>#</th><th>Server Name</th><th>Type</th><th>Environment</th>
        <th>Status</th><th>Enabled</th><th>Since</th>
        <th>Monthly Cost</th><th>Notes</th><th>Actions</th>
      </tr></thead>
      <tbody id="dashBody"><tr><td colspan="10" class="empty"><span class="spin"></span> Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ── STATUS LOG ─────────────────────────────────────────────────────────── -->
<div id="tab-logs" class="tab">
  <div class="toolbar">
    <div class="filters">
      <input type="text" id="fLogSrv" placeholder="Filter by server..." oninput="renderLogs()">
      <select id="fLogAct" onchange="renderLogs()">
        <option value="">All Actions</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
        <option value="decommissioned">Decommissioned</option>
      </select>
    </div>
    <div class="tright">
      <button class="btn btn-gh btn-sm" onclick="xCSV('logsTbl','status_log')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('logsTbl','status_log')">XLS</button>
    </div>
  </div>
  <div class="twrap">
    <table id="logsTbl">
      <thead><tr><th>#</th><th>Timestamp (UTC)</th><th>Server</th><th>Action</th><th>Notes</th></tr></thead>
      <tbody id="logsBody"><tr><td colspan="5" class="empty"><span class="spin"></span> Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ── TRANSACTIONS ──────────────────────────────────────────────────────── -->
<div id="tab-txn" class="tab">
  <div class="toolbar">
    <div class="filters">
      <input type="text" id="fTxnSrv" placeholder="Filter by server..." oninput="renderTxn()">
      <input type="text" id="fTxnId"  placeholder="TXN ID..."           oninput="renderTxn()">
      <input type="date" id="fTxnS"   onchange="renderTxn()">
      <input type="date" id="fTxnE"   onchange="renderTxn()">
    </div>
    <div class="tright">
      <button class="btn btn-gh btn-sm" onclick="xCSV('txnTbl','transactions')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('txnTbl','transactions')">XLS</button>
    </div>
  </div>
  <div class="twrap">
    <table id="txnTbl">
      <thead><tr>
        <th>#</th><th>TXN ID</th><th>Server</th><th>Action</th>
        <th>Days</th><th>Amount</th><th>Period</th><th>Date</th><th>Notes</th>
      </tr></thead>
      <tbody id="txnBody"><tr><td colspan="9" class="empty"><span class="spin"></span> Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ── MONTHLY BILLING ───────────────────────────────────────────────────── -->
<div id="tab-billing" class="tab">
  <div class="toolbar">
    <label style="color:var(--tx2);font-size:13px">From</label>
    <input type="date" id="bStart" style="background:var(--sur2);border:1px solid var(--bd);color:var(--tx);padding:6px 10px;border-radius:var(--r);font-size:13px">
    <label style="color:var(--tx2);font-size:13px">To</label>
    <input type="date" id="bEnd"   style="background:var(--sur2);border:1px solid var(--bd);color:var(--tx);padding:6px 10px;border-radius:var(--r);font-size:13px">
    <button class="btn btn-pri" onclick="runBilling()">Calculate</button>
    <div class="tright">
      <button class="btn btn-ok" id="saveTxnBtn" onclick="saveAsTxn()" style="display:none">&#128190; Save as Transaction</button>
      <button class="btn btn-gh btn-sm" onclick="xCSV('billTbl','billing')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('billTbl','billing')">XLS</button>
    </div>
  </div>
  <div class="twrap">
    <table id="billTbl">
      <thead><tr>
        <th>#</th><th>Server Name</th><th>Type</th><th>Environment</th>
        <th>Enabled Since</th><th>Days Active</th><th>Month Days</th>
        <th>Monthly Cost</th><th>Amount Due</th>
      </tr></thead>
      <tbody id="billBody"><tr><td colspan="9" class="empty">Set a date range and click Calculate</td></tr></tbody>
    </table>
  </div>
  <div class="btotal" id="billTotal" style="display:none">
    <div>
      <div class="lbl">Total Amount Due</div>
      <div class="amt" id="billAmt">$0.00</div>
    </div>
    <div style="text-align:right">
      <div class="sub" id="billMeta"></div>
    </div>
  </div>
</div>

</main>
<footer>Designed by <a href="https://digsyn.ai" target="_blank">digsyn.ai</a></footer>

<!-- ── SERVER MODAL ──────────────────────────────────────────────────────── -->
<div class="moverlay" id="srvModal">
  <div class="modal">
    <h2 id="mTitle">Add Server</h2>
    <div class="fg"><label>Server Name *</label><input type="text" id="mName" placeholder="e.g. WEB-PROD-01"></div>
    <div class="fg"><label>Type</label><input type="text" id="mType" placeholder="e.g. Virtual, Physical, Cloud"></div>
    <div class="fg"><label>Environment</label><input type="text" id="mEnv" placeholder="e.g. Production, Staging, Dev"></div>
    <div class="fg"><label>Monthly Cost ($)</label><input type="number" id="mCost" placeholder="0.00" step="0.01" min="0"></div>
    <div class="fg"><label>Notes</label><textarea id="mNotes" placeholder="Optional notes..."></textarea></div>
    <div class="mfoot">
      <button class="btn btn-gh" onclick="closeModal('srvModal')">Cancel</button>
      <button class="btn btn-pri" onclick="saveSrv()">Save</button>
    </div>
  </div>
</div>

<!-- ── IMPORT MODAL ──────────────────────────────────────────────────────── -->
<div class="moverlay" id="impModal">
  <div class="modal">
    <h2>Import Servers — CSV / Excel</h2>
    <p style="color:var(--tx2);font-size:13px;margin-bottom:14px">
      Expected columns: <strong>Server Name, Type, Environment, Monthly Cost, Notes</strong><br>
      Every row is inserted as a <strong>new</strong> server (no deduplication).
    </p>
    <div class="fg">
      <label>Select File (.csv, .xlsx, .xls)</label>
      <input type="file" id="impFile" accept=".csv,.xlsx,.xls"
        style="color:var(--tx);background:var(--sur2);border:1px solid var(--bd);padding:8px;border-radius:var(--r);width:100%;font-size:13px">
    </div>
    <div id="impPreview" style="display:none;margin-top:8px;color:var(--tx2);font-size:13px"></div>
    <div class="mfoot">
      <button class="btn btn-gh" onclick="closeModal('impModal')">Cancel</button>
      <button class="btn btn-pri" id="impBtn" onclick="doImport()" disabled>Import</button>
    </div>
  </div>
</div>

<!-- ── DECOMMISSION MODAL ────────────────────────────────────────────────── -->
<div class="moverlay" id="dcModal">
  <div class="modal">
    <h2>Decommission Server</h2>
    <p style="color:var(--tx2);font-size:13px;margin-bottom:14px">
      The server will be disabled and marked as decommissioned. Recorded in Status Log.
    </p>
    <div class="fg"><label>Notes (optional)</label><textarea id="dcNotes" placeholder="Reason for decommission..."></textarea></div>
    <div class="mfoot">
      <button class="btn btn-gh" onclick="closeModal('dcModal')">Cancel</button>
      <button class="btn btn-del" onclick="confirmDecomm()">Decommission</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── Constants ────────────────────────────────────────────────────────────────
var API = '/server/api';

// ── State ────────────────────────────────────────────────────────────────────
var ST = {
  servers: [], logs: [], txns: [],
  billingRows: [], search: '',
  editId: null, dcId: null, importRows: []
};

// ── Boot ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', function() {
  setDefaultDates();
  document.getElementById('impFile').addEventListener('change', onFileChange);
  loadAll();
});

function loadAll() {
  return Promise.all([loadServers(), loadLogs(), loadTxns()]);
}

function setDefaultDates() {
  var n = new Date();
  var y = n.getFullYear();
  var m = String(n.getMonth() + 1).padStart(2, '0');
  var last = new Date(y, n.getMonth() + 1, 0).getDate();
  document.getElementById('bStart').value = y + '-' + m + '-01';
  document.getElementById('bEnd').value   = y + '-' + m + '-' + String(last).padStart(2, '0');
}

// ── Tabs ─────────────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll('.tab').forEach(function(el) { el.classList.remove('active'); });
  document.querySelectorAll('.tb').forEach(function(el)  { el.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector('[data-tab="' + name + '"]').classList.add('active');
}

// ── API helper ───────────────────────────────────────────────────────────────
function api(path, opts) {
  opts = opts || {};
  var fetchOpts = {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json' }
  };
  if (opts.body !== undefined) fetchOpts.body = JSON.stringify(opts.body);
  return fetch(API + path, fetchOpts).then(function(r) {
    return r.json().then(function(data) {
      if (!r.ok) throw new Error(data.error || 'Request failed (' + r.status + ')');
      return data;
    });
  });
}

// ── Servers ──────────────────────────────────────────────────────────────────
function loadServers() {
  return api('/servers').then(function(d) {
    ST.servers = d;
    renderDash();
  }).catch(function(e) { toast('Load failed: ' + e.message, 'err'); });
}

function renderDash() {
  var sf = document.getElementById('fStatus').value;
  var ef = document.getElementById('fEnabled').value;
  var q  = ST.search.toLowerCase();

  var rows = ST.servers.filter(function(s) {
    if (sf && s.status !== sf) return false;
    if (ef !== '' && String(s.enabled) !== ef) return false;
    if (q && !srvMatch(s, q)) return false;
    return true;
  });

  var body = document.getElementById('dashBody');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="10" class="empty">No servers found</td></tr>';
    return;
  }

  var html = '';
  rows.forEach(function(s, i) {
    var tog = '';
    if (s.status === 'decommissioned') {
      tog = '<span class="badge badge-decommissioned">N/A</span>';
    } else {
      tog = '<label class="toggle">' +
        '<input type="checkbox"' + (s.enabled ? ' checked' : '') +
        ' onchange="toggleSrv(' + s.id + ',this.checked)">' +
        '<span class="trk"></span></label>';
    }
    var acts = '<button class="btn btn-gh btn-sm" onclick="openEdit(' + s.id + ')">Edit</button>';
    if (s.status !== 'decommissioned') {
      acts += ' <button class="btn btn-warn btn-sm" onclick="openDc(' + s.id + ')">Decomm</button>';
    }
    acts += ' <button class="btn btn-del btn-sm" onclick="delSrv(' + s.id + ')">Del</button>';

    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td>' + hl(s.server_name) + '</td>' +
      '<td>' + hl(s.type || '—') + '</td>' +
      '<td>' + hl(s.environment || '—') + '</td>' +
      '<td><span class="badge badge-' + s.status + '">' + s.status + '</span></td>' +
      '<td>' + tog + '</td>' +
      '<td style="white-space:nowrap">' + (s.enabled_date || '—') + '</td>' +
      '<td>' + fc(s.monthly_cost) + '</td>' +
      '<td class="nc" title="' + ea(s.notes) + '">' + hl(s.notes || '—') + '</td>' +
      '<td><div class="actions">' + acts + '</div></td>' +
      '</tr>';
  });
  body.innerHTML = html;
}

function srvMatch(s, q) {
  return [s.server_name, s.type, s.environment, s.status, s.notes]
    .some(function(v) { return v && v.toLowerCase().indexOf(q) !== -1; });
}

function toggleSrv(id, enabled) {
  api('/servers/' + id + '/toggle', { method: 'POST', body: { enabled: enabled } })
    .then(function() {
      return Promise.all([loadServers(), loadLogs()]);
    })
    .then(function() { toast(enabled ? 'Server enabled' : 'Server disabled', 'ok'); })
    .catch(function(e) { toast('Toggle failed: ' + e.message, 'err'); loadServers(); });
}

function delSrv(id) {
  if (!confirm('Delete this server? This cannot be undone.')) return;
  api('/servers/' + id, { method: 'DELETE' })
    .then(function() {
      ST.servers = ST.servers.filter(function(s) { return s.id !== id; });
      renderDash();
      toast('Server deleted', 'ok');
    })
    .catch(function(e) { toast('Delete failed: ' + e.message, 'err'); });
}

// ── Server modal ─────────────────────────────────────────────────────────────
function openAdd() {
  ST.editId = null;
  document.getElementById('mTitle').textContent = 'Add Server';
  clearForm();
  openModal('srvModal');
}

function openEdit(id) {
  var s = ST.servers.find(function(x) { return x.id === id; });
  if (!s) return;
  ST.editId = id;
  document.getElementById('mTitle').textContent = 'Edit Server';
  document.getElementById('mName').value  = s.server_name;
  document.getElementById('mType').value  = s.type || '';
  document.getElementById('mEnv').value   = s.environment || '';
  document.getElementById('mCost').value  = s.monthly_cost || '';
  document.getElementById('mNotes').value = s.notes || '';
  openModal('srvModal');
}

function clearForm() {
  ['mName','mType','mEnv','mCost','mNotes'].forEach(function(id) {
    document.getElementById(id).value = '';
  });
}

function saveSrv() {
  var name = document.getElementById('mName').value.trim();
  if (!name) { toast('Server name is required', 'err'); return; }
  var body = {
    server_name:  name,
    type:         document.getElementById('mType').value.trim(),
    environment:  document.getElementById('mEnv').value.trim(),
    monthly_cost: parseFloat(document.getElementById('mCost').value) || 0,
    notes:        document.getElementById('mNotes').value.trim()
  };
  var isEdit = ST.editId !== null;
  var p = isEdit
    ? api('/servers/' + ST.editId, { method: 'PUT', body: body })
    : api('/servers', { method: 'POST', body: body });
  p.then(function() {
    closeModal('srvModal');
    clearForm();
    return loadServers();
  }).then(function() {
    toast(isEdit ? 'Server updated' : 'Server added', 'ok');
  }).catch(function(e) { toast('Save failed: ' + e.message, 'err'); });
}

// ── Decommission ──────────────────────────────────────────────────────────────
function openDc(id) {
  ST.dcId = id;
  document.getElementById('dcNotes').value = '';
  openModal('dcModal');
}

function confirmDecomm() {
  if (!ST.dcId) return;
  var notes = document.getElementById('dcNotes').value.trim();
  api('/servers/' + ST.dcId + '/decommission', { method: 'POST', body: { notes: notes } })
    .then(function() {
      closeModal('dcModal');
      ST.dcId = null;
      return Promise.all([loadServers(), loadLogs()]);
    })
    .then(function() { toast('Server decommissioned', 'ok'); })
    .catch(function(e) { toast('Failed: ' + e.message, 'err'); });
}

// ── Import ────────────────────────────────────────────────────────────────────
function openImport() {
  ST.importRows = [];
  document.getElementById('impFile').value = '';
  document.getElementById('impPreview').style.display = 'none';
  document.getElementById('impBtn').disabled = true;
  openModal('impModal');
}

function onFileChange(e) {
  var file = e.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(ev) {
    try {
      var wb   = XLSX.read(ev.target.result, { type: 'binary' });
      var ws   = wb.Sheets[wb.SheetNames[0]];
      var data = XLSX.utils.sheet_to_json(ws);
      ST.importRows = data;
      var prev = document.getElementById('impPreview');
      prev.style.display = 'block';
      prev.textContent = data.length + ' rows found and ready to import.';
      document.getElementById('impBtn').disabled = data.length === 0;
    } catch (err) {
      toast('Could not parse file: ' + err.message, 'err');
    }
  };
  reader.readAsBinaryString(file);
}

function doImport() {
  if (!ST.importRows.length) return;
  api('/import', { method: 'POST', body: ST.importRows })
    .then(function(r) {
      closeModal('impModal');
      return loadServers().then(function() {
        toast('Imported ' + r.imported + ' servers', 'ok');
      });
    })
    .catch(function(e) { toast('Import failed: ' + e.message, 'err'); });
}

// ── Status Log ────────────────────────────────────────────────────────────────
function loadLogs() {
  return api('/logs').then(function(d) {
    ST.logs = d;
    renderLogs();
  }).catch(function(e) { toast('Load logs failed: ' + e.message, 'err'); });
}

function renderLogs() {
  var sf = document.getElementById('fLogSrv').value.toLowerCase();
  var af = document.getElementById('fLogAct').value;
  var q  = ST.search.toLowerCase();

  var rows = ST.logs.filter(function(l) {
    if (sf && (!l.server_name || l.server_name.toLowerCase().indexOf(sf) === -1)) return false;
    if (af && l.action !== af) return false;
    if (q) {
      var hit = [l.server_name, l.action, l.notes]
        .some(function(v) { return v && v.toLowerCase().indexOf(q) !== -1; });
      if (!hit) return false;
    }
    return true;
  });

  var body = document.getElementById('logsBody');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No log entries</td></tr>';
    return;
  }

  var html = '';
  rows.forEach(function(l, i) {
    var cls = l.action === 'enabled' ? 'badge-enabled' :
              l.action === 'disabled' ? 'badge-disabled' : 'badge-decommissioned';
    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td style="white-space:nowrap">' + fmtTs(l.timestamp) + '</td>' +
      '<td>' + hl(l.server_name) + '</td>' +
      '<td><span class="badge ' + cls + '">' + l.action + '</span></td>' +
      '<td>' + hl(l.notes || '—') + '</td>' +
      '</tr>';
  });
  body.innerHTML = html;
}

// ── Transactions ──────────────────────────────────────────────────────────────
function loadTxns() {
  return api('/transactions').then(function(d) {
    ST.txns = d;
    renderTxn();
  }).catch(function(e) { toast('Load transactions failed: ' + e.message, 'err'); });
}

function renderTxn() {
  var sf  = document.getElementById('fTxnSrv').value.toLowerCase();
  var idf = document.getElementById('fTxnId').value.toLowerCase();
  var ds  = document.getElementById('fTxnS').value;
  var de  = document.getElementById('fTxnE').value;
  var q   = ST.search.toLowerCase();

  var rows = ST.txns.filter(function(t) {
    if (sf  && (!t.server_name || t.server_name.toLowerCase().indexOf(sf) === -1)) return false;
    if (idf && (!t.txn_id      || t.txn_id.toLowerCase().indexOf(idf)      === -1)) return false;
    if (ds  && t.date < ds) return false;
    if (de  && t.date > de) return false;
    if (q) {
      var hit = [t.server_name, t.txn_id, t.action, t.notes]
        .some(function(v) { return v && v.toLowerCase().indexOf(q) !== -1; });
      if (!hit) return false;
    }
    return true;
  });

  var body = document.getElementById('txnBody');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="9" class="empty">No transactions</td></tr>';
    return;
  }

  var total = rows.reduce(function(s, t) { return s + (t.amount || 0); }, 0);
  var html  = '';

  rows.forEach(function(t, i) {
    var period = (t.period_start && t.period_end)
      ? t.period_start + ' &#8594; ' + t.period_end : '—';
    var shortId = t.txn_id ? t.txn_id.slice(0, 8) : '—';
    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td><span class="pill">' + shortId + '</span></td>' +
      '<td>' + hl(t.server_name) + '</td>' +
      '<td>' + hl(t.action) + '</td>' +
      '<td>' + (t.days_billed || '—') + '</td>' +
      '<td>' + fc(t.amount) + '</td>' +
      '<td style="white-space:nowrap">' + period + '</td>' +
      '<td>' + (t.date || '—') + '</td>' +
      '<td>' + hl(t.notes || '—') + '</td>' +
      '</tr>';
  });

  html += '<tr class="sum">' +
    '<td colspan="5">Total (' + rows.length + ' transactions)</td>' +
    '<td colspan="4">' + fc(total) + '</td>' +
    '</tr>';

  body.innerHTML = html;
}

// ── Billing ───────────────────────────────────────────────────────────────────
var lastBilling = [];

function runBilling() {
  var startStr = document.getElementById('bStart').value;
  var endStr   = document.getElementById('bEnd').value;
  if (!startStr || !endStr) { toast('Please select a date range', 'err'); return; }
  if (startStr > endStr)    { toast('Start date must be before end date', 'err'); return; }

  var startDate = new Date(startStr + 'T00:00:00');
  var endDate   = new Date(endStr   + 'T00:00:00');
  var today     = new Date(); today.setHours(0, 0, 0, 0);

  // Period days (inclusive)
  var periodDays = Math.round((endDate - startDate) / 86400000) + 1;

  // Days in the month of the billing period's start (e.g. 30 for September)
  var daysInMonth = new Date(startDate.getFullYear(), startDate.getMonth() + 1, 0).getDate();

  var results = [];

  ST.servers.forEach(function(s) {
    if (s.status !== 'active' || !s.enabled || !s.enabled_date) return;

    var enabledDate   = new Date(s.enabled_date + 'T00:00:00');
    var effectiveStart = enabledDate > startDate ? enabledDate : startDate;
    // KEY: cap end at today so a server enabled today doesn't bill future days
    var effectiveEnd   = today < endDate ? today : endDate;

    if (effectiveStart > effectiveEnd) return;

    var daysActive = Math.round((effectiveEnd - effectiveStart) / 86400000) + 1;
    if (daysActive <= 0) return;

    var dailyRate = s.monthly_cost / daysInMonth;
    var amount    = dailyRate * daysActive;

    results.push({
      id: s.id, server_name: s.server_name, type: s.type,
      environment: s.environment, enabled_date: s.enabled_date,
      monthly_cost: s.monthly_cost, daysActive: daysActive,
      daysInMonth: daysInMonth, periodDays: periodDays,
      amount: amount
    });
  });

  results.sort(function(a, b) { return a.server_name.localeCompare(b.server_name); });
  lastBilling = results;

  var body = document.getElementById('billBody');
  if (!results.length) {
    body.innerHTML = '<tr><td colspan="9" class="empty">No active servers in this period</td></tr>';
    document.getElementById('billTotal').style.display = 'none';
    document.getElementById('saveTxnBtn').style.display = 'none';
    return;
  }

  var totalAmt = results.reduce(function(s, r) { return s + r.amount; }, 0);
  var html = '';

  results.forEach(function(r, i) {
    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td>' + eh(r.server_name) + '</td>' +
      '<td>' + eh(r.type || '—') + '</td>' +
      '<td>' + eh(r.environment || '—') + '</td>' +
      '<td>' + (r.enabled_date || '—') + '</td>' +
      '<td><strong>' + r.daysActive + '</strong></td>' +
      '<td>' + r.daysInMonth + '</td>' +
      '<td>' + fc(r.monthly_cost) + '</td>' +
      '<td><strong>' + fc(r.amount) + '</strong></td>' +
      '</tr>';
  });

  html += '<tr class="sum">' +
    '<td colspan="8">Total (' + results.length + ' servers · ' + periodDays + '-day period)</td>' +
    '<td>' + fc(totalAmt) + '</td>' +
    '</tr>';

  body.innerHTML = html;

  document.getElementById('billAmt').textContent = fc(totalAmt);
  document.getElementById('billMeta').textContent =
    results.length + ' servers · ' + daysInMonth + '-day month · ' + periodDays + '-day period';
  document.getElementById('billTotal').style.display = 'flex';
  document.getElementById('saveTxnBtn').style.display = 'inline-flex';
}

function saveAsTxn() {
  if (!lastBilling.length) return;
  var startStr = document.getElementById('bStart').value;
  var endStr   = document.getElementById('bEnd').value;
  var txnId    = uuid();
  var today    = new Date().toISOString().slice(0, 10);

  var items = lastBilling.map(function(r) {
    return {
      txn_id: txnId, server_id: r.id, server_name: r.server_name,
      action: 'billing', amount: r.amount, days_billed: r.daysActive,
      period_start: startStr, period_end: endStr, date: today,
      notes: r.daysActive + 'd / ' + r.daysInMonth + 'd @ ' + fc(r.monthly_cost) + '/mo'
    };
  });

  api('/transactions', { method: 'POST', body: items })
    .then(function() {
      return loadTxns();
    })
    .then(function() {
      toast('Saved TXN ' + txnId.slice(0, 8) + ' — ' + items.length + ' entries', 'ok');
      document.getElementById('saveTxnBtn').style.display = 'none';
    })
    .catch(function(e) { toast('Save failed: ' + e.message, 'err'); });
}

// ── Search ────────────────────────────────────────────────────────────────────
function onSearch(val) {
  ST.search = val;
  renderDash();
  renderLogs();
  renderTxn();
}

// ── Export ────────────────────────────────────────────────────────────────────
function xCSV(tblId, name) {
  var tbl  = document.getElementById(tblId);
  var rows = Array.prototype.slice.call(tbl.querySelectorAll('tr'));
  var csv  = rows.map(function(row) {
    var cells = Array.prototype.slice.call(row.querySelectorAll('th,td'));
    return cells.map(function(c) {
      return '"' + c.innerText.replace(/"/g, '""') + '"';
    }).join(',');
  }).join('\n');
  dl(new Blob([csv], { type: 'text/csv' }), name + '_' + td() + '.csv');
}

function xXLS(tblId, name) {
  var wb = XLSX.utils.book_new();
  var ws = XLSX.utils.table_to_sheet(document.getElementById(tblId));
  XLSX.utils.book_append_sheet(wb, ws, name);
  XLSX.writeFile(wb, name + '_' + td() + '.xlsx');
}

function dl(blob, filename) {
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// ── Modal helpers ─────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── Toast ─────────────────────────────────────────────────────────────────────
var _tt;
function toast(msg, type) {
  var el = document.getElementById('toast');
  el.textContent = msg;
  el.className   = 'show ' + (type || 'ok');
  clearTimeout(_tt);
  _tt = setTimeout(function() { el.classList.remove('show'); }, 3200);
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function eh(s) { // HTML escape
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function ea(s) { // attribute escape
  return eh(s).replace(/'/g,'&#39;');
}
function hl(text) { // highlight search term
  if (text == null) return '—';
  var t = String(text);
  if (!ST.search) return eh(t);
  var q    = ST.search;
  var re   = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')', 'gi');
  var parts = t.split(re);
  return parts.map(function(p, i) {
    return (i % 2 === 1) ? '<mark>' + eh(p) + '</mark>' : eh(p);
  }).join('');
}
function fc(v) { // format currency (CAD)
  if (v == null || v === '') return '—';
  return '$' + parseFloat(v).toLocaleString('en-CA', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function fmtTs(ts) {
  if (!ts) return '—';
  return ts.replace('T',' ').slice(0,16);
}
function td() {
  return new Date().toISOString().slice(0,10);
}
function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}
</script>
</body>
</html>`;
