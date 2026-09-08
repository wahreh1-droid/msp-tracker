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
const J = (data, status = 200, extraHeaders) =>
  Response.json(data, { status, headers: { ...CORS, 'Content-Type': 'application/json', ...(extraHeaders || {}) } });
const E = (msg, status = 400) => J({ error: msg }, status);

// ── Auth: crypto helpers ─────────────────────────────────────────────────────
const enc = new TextEncoder();

function toHex(buf) {
  return Array.prototype.map.call(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}
function randomHex(nBytes) {
  const arr = new Uint8Array(nBytes);
  crypto.getRandomValues(arr);
  return toHex(arr);
}

// PBKDF2-SHA256, 100k iterations — password never stored or logged in plain text
async function hashPassword(password, saltHex) {
  const salt = fromHex(saltHex);
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return toHex(bits);
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return toHex(sig);
}

function b64url(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function fromB64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

async function makeSessionCookie(secret, payload) {
  const body = b64url(JSON.stringify(payload));
  const sig  = await hmac(secret, body);
  const token = body + '.' + sig;
  return `session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`;
}
const clearSessionCookie = 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0';

async function verifySessionToken(secret, token) {
  if (!token || token.indexOf('.') === -1) return null;
  const [body, sig] = token.split('.');
  const expected = await hmac(secret, body);
  if (expected !== sig) return null;
  try {
    const payload = JSON.parse(fromB64url(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function getCookie(req, name) {
  const header = req.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}

// Verifies the session cookie AND re-checks the user still exists in D1 —
// so a deleted account loses access immediately, not just at next password change.
async function getSessionUser(req, env, db) {
  if (!env.SESSION_SECRET) return null;
  const token = getCookie(req, 'session');
  const payload = await verifySessionToken(env.SESSION_SECRET, token);
  if (!payload || !payload.uid) return null;
  const row = await db.prepare('SELECT id, username, role FROM users WHERE id=?').bind(payload.uid).first();
  if (!row) return null;
  return row;
}

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

    // ── GET /auth/status — public: tells frontend whether to bootstrap, login, or proceed
    if (path === '/auth/status' && m === 'GET') {
      const count = await db.prepare('SELECT COUNT(*) AS n FROM users').first();
      const needsBootstrap = (count?.n || 0) === 0;
      if (needsBootstrap) return J({ needsBootstrap: true, loggedIn: false, user: null });
      const user = await getSessionUser(req, env, db);
      return J({ needsBootstrap: false, loggedIn: !!user, user: user || null });
    }

    // ── POST /auth/bootstrap — public, but only works while users table is empty
    if (path === '/auth/bootstrap' && m === 'POST') {
      if (!env.SESSION_SECRET) return E('Server misconfigured: SESSION_SECRET not set', 500);
      const count = await db.prepare('SELECT COUNT(*) AS n FROM users').first();
      if ((count?.n || 0) > 0) return E('Setup already completed', 409);
      const b = await req.json();
      const username = (b.username || '').trim();
      const password = b.password || '';
      if (!username) return E('Username is required');
      if (password.length < 8) return E('Password must be at least 8 characters');
      const salt = randomHex(16);
      const hash = await hashPassword(password, salt);
      const r = await db.prepare(
        `INSERT INTO users (username, password_hash, salt, role) VALUES (?,?,?,'admin')`
      ).bind(username, hash, salt).run();
      const uid = r.meta.last_row_id;
      const cookie = await makeSessionCookie(env.SESSION_SECRET, { uid, exp: Date.now() + SESSION_MAX_AGE * 1000 });
      return J({ ok: true, user: { id: uid, username, role: 'admin' } }, 201, { 'Set-Cookie': cookie });
    }

    // ── POST /auth/login — public
    if (path === '/auth/login' && m === 'POST') {
      if (!env.SESSION_SECRET) return E('Server misconfigured: SESSION_SECRET not set', 500);
      const b = await req.json();
      const username = (b.username || '').trim();
      const password = b.password || '';
      const row = await db.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
      if (!row) return E('Invalid username or password', 401);
      const hash = await hashPassword(password, row.salt);
      if (hash !== row.password_hash) return E('Invalid username or password', 401);
      const cookie = await makeSessionCookie(env.SESSION_SECRET, { uid: row.id, exp: Date.now() + SESSION_MAX_AGE * 1000 });
      return J({ ok: true, user: { id: row.id, username: row.username, role: row.role } }, 200, { 'Set-Cookie': cookie });
    }

    // ── POST /auth/logout — public (no-op if not logged in)
    if (path === '/auth/logout' && m === 'POST') {
      return J({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie });
    }

    // ── Everything below requires a valid session ──────────────────────────
    const user = await getSessionUser(req, env, db);
    if (!user) return E('Not authenticated', 401);

    // ── GET /me — confirms current session, used by frontend on load
    if (path === '/me' && m === 'GET') {
      return J({ user });
    }

    // ── GET /auth/users — admin only
    if (path === '/auth/users' && m === 'GET') {
      if (user.role !== 'admin') return E('Admins only', 403);
      const r = await db.prepare('SELECT id, username, role, created_at FROM users ORDER BY username COLLATE NOCASE').all();
      return J(r.results);
    }

    // ── POST /auth/users — admin only, create a team member account
    if (path === '/auth/users' && m === 'POST') {
      if (user.role !== 'admin') return E('Admins only', 403);
      const b = await req.json();
      const username = (b.username || '').trim();
      const password = b.password || '';
      const role = b.role === 'admin' ? 'admin' : 'user';
      if (!username) return E('Username is required');
      if (password.length < 8) return E('Password must be at least 8 characters');
      const existing = await db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (existing) return E('That username is already taken', 409);
      const salt = randomHex(16);
      const hash = await hashPassword(password, salt);
      const r = await db.prepare(
        'INSERT INTO users (username, password_hash, salt, role) VALUES (?,?,?,?)'
      ).bind(username, hash, salt, role).run();
      return J({ id: r.meta.last_row_id }, 201);
    }

    // ── DELETE /auth/users/:id — admin only
    const mUserDel = path.match(/^\/auth\/users\/(\d+)$/);
    if (mUserDel && m === 'DELETE') {
      if (user.role !== 'admin') return E('Admins only', 403);
      const targetId = mUserDel[1];
      if (Number(targetId) === user.id) return E("You can't delete your own account while logged in as it");
      const target = await db.prepare('SELECT role FROM users WHERE id=?').bind(targetId).first();
      if (!target) return E('User not found', 404);
      if (target.role === 'admin') {
        const admins = await db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first();
        if ((admins?.n || 0) <= 1) return E('Cannot delete the last remaining admin');
      }
      await db.prepare('DELETE FROM users WHERE id=?').bind(targetId).run();
      return J({ ok: true });
    }

    // ── POST /auth/password — any logged-in user changes their OWN password
    // Requires the current password, so a hijacked session can't silently lock the owner out.
    if (path === '/auth/password' && m === 'POST') {
      const b = await req.json();
      const current = b.current_password || '';
      const next    = b.new_password || '';
      if (next.length < 8) return E('New password must be at least 8 characters');
      const row = await db.prepare('SELECT * FROM users WHERE id=?').bind(user.id).first();
      if (!row) return E('User not found', 404);
      const curHash = await hashPassword(current, row.salt);
      if (curHash !== row.password_hash) return E('Current password is incorrect', 401);
      const salt = randomHex(16);
      const hash = await hashPassword(next, salt);
      await db.prepare('UPDATE users SET password_hash=?, salt=? WHERE id=?').bind(hash, salt, user.id).run();
      return J({ ok: true });
    }

    // ── POST /auth/users/:id/password — admin resets someone else's password
    // No current password needed (the admin doesn't know it) — this is the
    // "team member forgot their password" path.
    const mUserPwd = path.match(/^\/auth\/users\/(\d+)\/password$/);
    if (mUserPwd && m === 'POST') {
      if (user.role !== 'admin') return E('Admins only', 403);
      const targetId = mUserPwd[1];
      const b = await req.json();
      const next = b.new_password || '';
      if (next.length < 8) return E('New password must be at least 8 characters');
      const target = await db.prepare('SELECT id FROM users WHERE id=?').bind(targetId).first();
      if (!target) return E('User not found', 404);
      const salt = randomHex(16);
      const hash = await hashPassword(next, salt);
      await db.prepare('UPDATE users SET password_hash=?, salt=? WHERE id=?').bind(hash, salt, targetId).run();
      return J({ ok: true });
    }

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
        'INSERT INTO status_logs (server_id, server_name, action, notes, performed_by) VALUES (?,?,?,?,?)'
      ).bind(id, srv?.server_name || '', enabled ? 'enabled' : 'disabled', b.notes || '', user.username).run();

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
        'INSERT INTO status_logs (server_id, server_name, action, notes, performed_by) VALUES (?,?,?,?,?)'
      ).bind(id, srv?.server_name || '', 'decommissioned', b.notes || '', user.username).run();
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
          (txn_id, server_id, server_name, action, amount, days_billed, period_start, period_end, date, notes, performed_by)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`
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
        t.notes || '',
        user.username
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
      // Normalize headers so "Server Name", "SERVER NAME", "server_name", and
      // "ServerName" all resolve the same way — matches our own export output
      // and any reasonably-named spreadsheet a person hands in.
      const norm = row => {
        const out = {};
        for (const k in row) out[k.toLowerCase().replace(/[^a-z0-9]/g, '')] = row[k];
        return out;
      };
      const str = v => (v === undefined || v === null ? '' : String(v)).trim();
      const num = v => parseFloat(str(v).replace(/[^0-9.\-]/g, '')) || 0;
      const batch = items.map(row => {
        const n = norm(row);
        const name = str(n.servername);
        return stmt.bind(
          name || 'Unnamed',
          str(n.type),
          str(n.environment),
          num(n.monthlycost),
          str(n.notes)
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
.acct{display:flex;align-items:center;gap:10px;white-space:nowrap}
.acct-name{color:var(--tx2);font-size:13px}

/* Auth screen */
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);padding:20px}
.auth-card{background:var(--sur);border:1px solid var(--bd);border-radius:12px;padding:32px;width:100%;max-width:380px}
.auth-title{font-size:20px;font-weight:700;text-align:center;margin-bottom:4px;letter-spacing:-.3px}
.auth-title span{color:var(--ac)}
.auth-sub{color:var(--tx2);font-size:13px;text-align:center;margin-bottom:24px}
.auth-label{display:block;color:var(--tx2);font-size:12px;margin:14px 0 5px}
.auth-input{width:100%;background:var(--sur2);border:1px solid var(--bd);color:var(--tx);padding:9px 12px;border-radius:var(--r);font-size:14px}
.auth-input:focus{outline:none;border-color:var(--ac)}
.auth-submit{width:100%;margin-top:20px;justify-content:center}
.auth-error{background:rgba(220,38,38,.12);border:1px solid rgba(220,38,38,.4);color:#f87171;padding:9px 12px;border-radius:var(--r);font-size:13px;margin-bottom:6px}
.auth-hint{color:var(--tx3);font-size:12px;margin-top:10px;line-height:1.4}

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

<!-- ── AUTH SCREEN (login / first-time bootstrap) ───────────────────────────── -->
<div id="authScreen" class="auth-wrap" style="display:none">
  <div class="auth-card">
    <h1 class="auth-title">MSP <span>Server</span> Tracker</h1>
    <p id="authSubtitle" class="auth-sub">Sign in to continue</p>
    <div id="authError" class="auth-error" style="display:none"></div>
    <form id="authForm" onsubmit="return submitAuthForm(event)">
      <label class="auth-label">Username</label>
      <input type="text" id="authUsername" class="auth-input" autocomplete="username" required>
      <label class="auth-label">Password</label>
      <input type="password" id="authPassword" class="auth-input" autocomplete="current-password" required>
      <p id="authBootstrapHint" class="auth-hint" style="display:none">
        No account exists yet — this creates the first admin account for the whole team.
      </p>
      <button type="submit" class="btn btn-pri auth-submit" id="authSubmitBtn">Sign In</button>
    </form>
  </div>
</div>

<div id="app" style="display:none">

<header>
  <h1>MSP <span>Server</span> Tracker</h1>
  <div class="srch">
    <input type="text" id="gSearch" placeholder="Search across all tabs..." oninput="onSearch(this.value)">
  </div>
  <div class="acct">
    <span id="acctName" class="acct-name"></span>
    <button class="btn btn-gh btn-sm" onclick="openChangePwd()">Change Password</button>
    <button class="btn btn-gh btn-sm" onclick="doLogout()">Logout</button>
  </div>
</header>

<nav class="tabbar">
  <button class="tb active" data-tab="dashboard" onclick="showTab('dashboard')">&#128202; Dashboard</button>
  <button class="tb" data-tab="logs"      onclick="showTab('logs')">&#128203; Status Log</button>
  <button class="tb" data-tab="txn"       onclick="showTab('txn')">&#128176; Transactions</button>
  <button class="tb" data-tab="billing"   onclick="showTab('billing')">&#129534; Monthly Billing</button>
  <button class="tb" data-tab="users" id="usersTabBtn" onclick="showTab('users')" style="display:none">&#128101; Users</button>
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
      <button class="btn btn-gh btn-sm" onclick="xCSV('servers')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('servers')">XLS</button>
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
      <button class="btn btn-gh btn-sm" onclick="xCSV('status_log')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('status_log')">XLS</button>
    </div>
  </div>
  <div class="twrap">
    <table id="logsTbl">
      <thead><tr><th>#</th><th>Timestamp (UTC)</th><th>Server</th><th>Action</th><th>By</th><th>Notes</th></tr></thead>
      <tbody id="logsBody"><tr><td colspan="6" class="empty"><span class="spin"></span> Loading...</td></tr></tbody>
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
      <button class="btn btn-gh btn-sm" onclick="xCSV('transactions')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('transactions')">XLS</button>
    </div>
  </div>
  <div class="twrap">
    <table id="txnTbl">
      <thead><tr>
        <th>#</th><th>TXN ID</th><th>Server</th><th>Action</th>
        <th>Days</th><th>Amount</th><th>Period</th><th>Date</th><th>By</th><th>Notes</th>
      </tr></thead>
      <tbody id="txnBody"><tr><td colspan="10" class="empty"><span class="spin"></span> Loading...</td></tr></tbody>
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
      <button class="btn btn-gh btn-sm" onclick="xCSV('billing')">CSV</button>
      <button class="btn btn-gh btn-sm" onclick="xXLS('billing')">XLS</button>
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

<!-- ── USERS (admin only) ───────────────────────────────────────────────────── -->
<div id="tab-users" class="tab">
  <div class="toolbar">
    <button class="btn btn-pri" onclick="openAddUser()">&#43; Add User</button>
  </div>
  <div class="twrap">
    <table id="usersTbl">
      <thead><tr>
        <th>#</th><th>Username</th><th>Role</th><th>Created</th><th>Actions</th>
      </tr></thead>
      <tbody id="usersBody"><tr><td colspan="5" class="empty"><span class="spin"></span> Loading...</td></tr></tbody>
    </table>
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

<!-- ── ADD USER MODAL (admin only) ───────────────────────────────────────── -->
<div class="moverlay" id="userModal">
  <div class="modal">
    <h2>Add User</h2>
    <div class="fg"><label>Username *</label><input type="text" id="uUsername" autocomplete="off"></div>
    <div class="fg"><label>Password *</label><input type="password" id="uPassword" autocomplete="new-password" placeholder="At least 8 characters"></div>
    <div class="fg">
      <label>Role</label>
      <select id="uRole">
        <option value="user">User — toggle servers, view billing</option>
        <option value="admin">Admin — full access, manage users</option>
      </select>
    </div>
    <div class="mfoot">
      <button class="btn btn-gh" onclick="closeModal('userModal')">Cancel</button>
      <button class="btn btn-pri" onclick="saveUser()">Create User</button>
    </div>
  </div>
</div>

<!-- ── CHANGE OWN PASSWORD MODAL ─────────────────────────────────────────── -->
<div class="moverlay" id="pwdModal">
  <div class="modal">
    <h2>Change Password</h2>
    <div class="fg"><label>Current Password *</label><input type="password" id="pCurrent" autocomplete="current-password"></div>
    <div class="fg"><label>New Password *</label><input type="password" id="pNew" autocomplete="new-password" placeholder="At least 8 characters"></div>
    <div class="fg"><label>Confirm New Password *</label><input type="password" id="pConfirm" autocomplete="new-password"></div>
    <div class="mfoot">
      <button class="btn btn-gh" onclick="closeModal('pwdModal')">Cancel</button>
      <button class="btn btn-pri" onclick="saveOwnPassword()">Change Password</button>
    </div>
  </div>
</div>

<!-- ── ADMIN RESET PASSWORD MODAL ────────────────────────────────────────── -->
<div class="moverlay" id="resetModal">
  <div class="modal">
    <h2>Reset Password</h2>
    <p style="color:var(--tx2);font-size:13px;margin-bottom:14px">
      Setting a new password for <strong id="resetWho"></strong>. Give it to them directly and ask them to change it after signing in.
    </p>
    <div class="fg"><label>New Password *</label><input type="password" id="rNew" autocomplete="new-password" placeholder="At least 8 characters"></div>
    <div class="mfoot">
      <button class="btn btn-gh" onclick="closeModal('resetModal')">Cancel</button>
      <button class="btn btn-pri" onclick="saveResetPassword()">Reset Password</button>
    </div>
  </div>
</div>

<script>
// ── Constants ────────────────────────────────────────────────────────────────
var API = '/server/api';

// ── State ────────────────────────────────────────────────────────────────────
var ST = {
  servers: [], logs: [], txns: [], users: [],
  billingRows: [], search: '',
  editId: null, dcId: null, importRows: [], resetId: null,
  viewServers: [], viewLogs: [], viewTxns: [],
  currentUser: null
};

// ── Boot ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', function() {
  setDefaultDates();
  document.getElementById('impFile').addEventListener('change', onFileChange);
  checkAuthAndBoot();
});

function checkAuthAndBoot() {
  fetch(API + '/auth/status').then(function(r) { return r.json(); }).then(function(s) {
    if (s.needsBootstrap) {
      showAuthScreen('bootstrap');
    } else if (!s.loggedIn) {
      showAuthScreen('login');
    } else {
      enterApp(s.user);
    }
  }).catch(function() {
    showAuthScreen('login');
  });
}

function showAuthScreen(mode) {
  document.getElementById('app').style.display = 'none';
  document.getElementById('authScreen').style.display = 'flex';
  document.getElementById('authScreen').dataset.mode = mode;
  var isBootstrap = mode === 'bootstrap';
  document.getElementById('authSubtitle').textContent = isBootstrap
    ? 'Set up the first admin account'
    : 'Sign in to continue';
  document.getElementById('authBootstrapHint').style.display = isBootstrap ? 'block' : 'none';
  document.getElementById('authSubmitBtn').textContent = isBootstrap ? 'Create Admin Account' : 'Sign In';
  document.getElementById('authError').style.display = 'none';
  document.getElementById('authUsername').focus();
}

function submitAuthForm(e) {
  e.preventDefault();
  var mode = document.getElementById('authScreen').dataset.mode;
  var username = document.getElementById('authUsername').value.trim();
  var password = document.getElementById('authPassword').value;
  var errEl = document.getElementById('authError');
  errEl.style.display = 'none';
  var endpoint = mode === 'bootstrap' ? '/auth/bootstrap' : '/auth/login';
  fetch(API + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, password: password })
  }).then(function(r) {
    return r.json().then(function(data) {
      if (!r.ok) throw new Error(data.error || 'Something went wrong');
      return data;
    });
  }).then(function(data) {
    enterApp(data.user);
  }).catch(function(err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  });
  return false;
}

// Wipes all loaded data and rendered rows, and returns to the Dashboard tab.
// Called on BOTH login and logout so nothing from one session is ever visible
// in the next — including a panel that was on screen when the last user left.
function resetAppState() {
  ST.servers = []; ST.logs = []; ST.txns = []; ST.users = [];
  ST.billingRows = []; ST.viewServers = []; ST.viewLogs = []; ST.viewTxns = [];
  ST.search = ''; ST.editId = null; ST.dcId = null; ST.resetId = null; ST.importRows = [];

  var g = document.getElementById('gSearch');
  if (g) g.value = '';

  // Clear every table body so nothing stays painted in the DOM
  [['dashBody', 10], ['logsBody', 6], ['txnBody', 10], ['billBody', 9], ['usersBody', 5]]
    .forEach(function(pair) {
      var el = document.getElementById(pair[0]);
      if (el) el.innerHTML = '<tr><td colspan="' + pair[1] + '" class="empty">&nbsp;</td></tr>';
    });

  var bt = document.getElementById('billTotal');
  if (bt) bt.style.display = 'none';
  var stb = document.getElementById('saveTxnBtn');
  if (stb) stb.style.display = 'none';

  // Close any modal left open
  ['srvModal','impModal','dcModal','userModal','pwdModal','resetModal'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.classList.remove('open');
  });

  // Force back to Dashboard
  document.querySelectorAll('.tab').forEach(function(el) { el.classList.remove('active'); });
  document.querySelectorAll('.tb').forEach(function(el)  { el.classList.remove('active'); });
  var dt = document.getElementById('tab-dashboard');
  if (dt) dt.classList.add('active');
  var db = document.querySelector('[data-tab="dashboard"]');
  if (db) db.classList.add('active');
}

function doLogout() {
  fetch(API + '/auth/logout', { method: 'POST' }).then(function() {
    ST.currentUser = null;
    resetAppState();
    document.getElementById('usersTabBtn').style.display = 'none';
    document.getElementById('acctName').textContent = '';
    document.getElementById('authPassword').value = '';
    showAuthScreen('login');
  });
}

function enterApp(user) {
  resetAppState();
  ST.currentUser = user;
  document.getElementById('authScreen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  document.getElementById('acctName').textContent = user.username + ' (' + user.role + ')';
  document.getElementById('usersTabBtn').style.display = user.role === 'admin' ? '' : 'none';
  document.getElementById('authPassword').value = '';
  loadAll();
}

function loadAll() {
  var tasks = [loadServers(), loadLogs(), loadTxns()];
  if (ST.currentUser && ST.currentUser.role === 'admin') tasks.push(loadUsers());
  return Promise.all(tasks);
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
  if (name === 'users' && (!ST.currentUser || ST.currentUser.role !== 'admin')) return;
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
      if (r.status === 401) {
        ST.currentUser = null;
        resetAppState();
        document.getElementById('usersTabBtn').style.display = 'none';
        document.getElementById('acctName').textContent = '';
        showAuthScreen('login');
        throw new Error('Session expired — please sign in again');
      }
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

  ST.viewServers = rows;

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

  ST.viewLogs = rows;

  var body = document.getElementById('logsBody');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No log entries</td></tr>';
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
      '<td>' + hl(l.performed_by || '—') + '</td>' +
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

  ST.viewTxns = rows;

  var body = document.getElementById('txnBody');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="10" class="empty">No transactions</td></tr>';
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
      '<td>' + hl(t.performed_by || '—') + '</td>' +
      '<td>' + hl(t.notes || '—') + '</td>' +
      '</tr>';
  });

  html += '<tr class="sum">' +
    '<td colspan="5">Total (' + rows.length + ' transactions)</td>' +
    '<td colspan="5">' + fc(total) + '</td>' +
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
  ST.billingRows = results;

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
// Builds export data straight from the underlying (filtered) data arrays —
// never scrapes the rendered table — so button labels, toggle switches, and
// other UI-only markup never leak into an exported file. Headers for the
// server export match what /import expects, so export -> import round-trips.
function exportData(kind) {
  if (kind === 'servers') {
    return {
      headers: ['Server Name', 'Type', 'Environment', 'Status', 'Enabled', 'Enabled Date', 'Monthly Cost', 'Notes'],
      rows: ST.viewServers.map(function(s) {
        return [
          s.server_name || '', s.type || '', s.environment || '',
          s.status || '', s.enabled ? 'Yes' : 'No', s.enabled_date || '',
          numOrBlank(s.monthly_cost), s.notes || ''
        ];
      })
    };
  }
  if (kind === 'status_log') {
    return {
      headers: ['Timestamp', 'Server Name', 'Action', 'By', 'Notes'],
      rows: ST.viewLogs.map(function(l) {
        return [fmtTs(l.timestamp), l.server_name || '', l.action || '', l.performed_by || '', l.notes || ''];
      })
    };
  }
  if (kind === 'transactions') {
    return {
      headers: ['TXN ID', 'Server Name', 'Action', 'Days Billed', 'Amount', 'Period Start', 'Period End', 'Date', 'By', 'Notes'],
      rows: ST.viewTxns.map(function(t) {
        return [
          t.txn_id || '', t.server_name || '', t.action || '',
          numOrBlank(t.days_billed), numOrBlank(t.amount),
          t.period_start || '', t.period_end || '', t.date || '', t.performed_by || '', t.notes || ''
        ];
      })
    };
  }
  if (kind === 'billing') {
    return {
      headers: ['Server Name', 'Type', 'Environment', 'Enabled Since', 'Days Active', 'Month Days', 'Monthly Cost', 'Amount Due'],
      rows: ST.billingRows.map(function(r) {
        return [
          r.server_name || '', r.type || '', r.environment || '', r.enabled_date || '',
          numOrBlank(r.daysActive), numOrBlank(r.daysInMonth),
          numOrBlank(r.monthly_cost), numOrBlank(r.amount)
        ];
      })
    };
  }
  return { headers: [], rows: [] };
}

function numOrBlank(v) {
  return (v === null || v === undefined || v === '') ? '' : v;
}

function xCSV(kind) {
  var Q  = String.fromCharCode(34);
  var NL = String.fromCharCode(10);
  var esc = function(v) { return Q + String(v).split(Q).join(Q + Q) + Q; };
  var data = exportData(kind);
  var lines = [data.headers.map(esc).join(',')].concat(
    data.rows.map(function(row) { return row.map(esc).join(','); })
  );
  var csv = lines.join(NL);
  dl(new Blob([csv], { type: 'text/csv' }), kind + '_' + td() + '.csv');
}

function xXLS(kind) {
  var data = exportData(kind);
  var wb = XLSX.utils.book_new();
  var ws = XLSX.utils.aoa_to_sheet([data.headers].concat(data.rows));
  XLSX.utils.book_append_sheet(wb, ws, kind);
  XLSX.writeFile(wb, kind + '_' + td() + '.xlsx');
}

function dl(blob, filename) {
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// ── Users (admin only) ───────────────────────────────────────────────────────
function loadUsers() {
  return api('/auth/users').then(function(d) {
    ST.users = d;
    renderUsers();
  }).catch(function(e) { toast('Load users failed: ' + e.message, 'err'); });
}

function renderUsers() {
  var body = document.getElementById('usersBody');
  if (!ST.users.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No users</td></tr>';
    return;
  }
  var html = '';
  ST.users.forEach(function(u, i) {
    var canDelete = !(ST.currentUser && u.id === ST.currentUser.id);
    var acts = '<button class="btn btn-gh btn-sm" onclick="openResetPwd(' + u.id + ',' + eaAttr(u.username) + ')">Reset Password</button>';
    if (canDelete) {
      acts += ' <button class="btn btn-del btn-sm" onclick="deleteUser(' + u.id + ',' + eaAttr(u.username) + ')">Del</button>';
    } else {
      acts += ' <span style="color:var(--tx3);font-size:12px">You</span>';
    }
    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td>' + eh(u.username) + '</td>' +
      '<td><span class="badge ' + (u.role === 'admin' ? 'badge-enabled' : '') + '">' + u.role + '</span></td>' +
      '<td style="white-space:nowrap">' + fmtTs(u.created_at) + '</td>' +
      '<td><div class="actions">' + acts + '</div></td>' +
      '</tr>';
  });
  body.innerHTML = html;
}

function eaAttr(s) { return "'" + String(s || '').replace(/'/g, "\\'") + "'"; }

function openAddUser() {
  document.getElementById('uUsername').value = '';
  document.getElementById('uPassword').value = '';
  document.getElementById('uRole').value = 'user';
  openModal('userModal');
}

function saveUser() {
  var username = document.getElementById('uUsername').value.trim();
  var password = document.getElementById('uPassword').value;
  var role     = document.getElementById('uRole').value;
  if (!username) { toast('Username is required', 'err'); return; }
  if (password.length < 8) { toast('Password must be at least 8 characters', 'err'); return; }
  api('/auth/users', { method: 'POST', body: { username: username, password: password, role: role } })
    .then(function() {
      closeModal('userModal');
      return loadUsers();
    })
    .then(function() { toast('User created', 'ok'); })
    .catch(function(e) { toast('Create failed: ' + e.message, 'err'); });
}

function deleteUser(id, username) {
  if (!confirm('Delete user "' + username + '"? This cannot be undone.')) return;
  api('/auth/users/' + id, { method: 'DELETE' })
    .then(function() { return loadUsers(); })
    .then(function() { toast('User deleted', 'ok'); })
    .catch(function(e) { toast('Delete failed: ' + e.message, 'err'); });
}

// ── Passwords ────────────────────────────────────────────────────────────────
function openChangePwd() {
  document.getElementById('pCurrent').value = '';
  document.getElementById('pNew').value     = '';
  document.getElementById('pConfirm').value = '';
  openModal('pwdModal');
}

function saveOwnPassword() {
  var cur = document.getElementById('pCurrent').value;
  var nw  = document.getElementById('pNew').value;
  var cf  = document.getElementById('pConfirm').value;
  if (!cur) { toast('Enter your current password', 'err'); return; }
  if (nw.length < 8) { toast('New password must be at least 8 characters', 'err'); return; }
  if (nw !== cf) { toast('New passwords do not match', 'err'); return; }
  api('/auth/password', { method: 'POST', body: { current_password: cur, new_password: nw } })
    .then(function() {
      closeModal('pwdModal');
      toast('Password changed', 'ok');
    })
    .catch(function(e) { toast(e.message, 'err'); });
}

function openResetPwd(id, username) {
  ST.resetId = id;
  document.getElementById('resetWho').textContent = username;
  document.getElementById('rNew').value = '';
  openModal('resetModal');
}

function saveResetPassword() {
  var nw = document.getElementById('rNew').value;
  if (nw.length < 8) { toast('Password must be at least 8 characters', 'err'); return; }
  api('/auth/users/' + ST.resetId + '/password', { method: 'POST', body: { new_password: nw } })
    .then(function() {
      closeModal('resetModal');
      toast('Password reset', 'ok');
    })
    .catch(function(e) { toast('Reset failed: ' + e.message, 'err'); });
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
  var re   = new RegExp('(' + q.replace(/[.*+?{}^$()|[\]\\]/g,'\\$&') + ')', 'gi');
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
</div>
</body>
</html>`;
