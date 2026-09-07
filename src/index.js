/* ===========================================================================
 * Rabia Khalid — Payment Tracker API
 *
 * Tracks three streams of money owed to Rabia under the Declaration of Asset
 * Distribution (IH-08 Falcon Complex, Karachi):
 *   share  — her 1/4 of each property sale instalment
 *   imad   — Imad Khalid's loan repayment
 *   aamer  — Aamer Khalid's loan repayment
 *
 * Reads are open: Imad and Aamer can see status at any time.
 * Writes require the PIN, checked here rather than only in the UI, so the
 * buttons cannot be bypassed from a console.
 *
 * Bindings (see wrangler.toml):
 *   TRACKER   KV namespace  — payment state, one key
 *   RECEIPTS  R2 bucket     — uploaded receipt files
 *   TRACKER_PIN  secret     — npx wrangler secret put TRACKER_PIN
 * ========================================================================= */

const STATE_KEY = "rabia:payments:v1";

/* The schedule is fixed by the declaration, so it lives in code rather than
 * the database. If a loan is settled early by deduction from a property share
 * under Clause 4.3, these figures need revising by hand. */
const SCHEDULE = [
  { month: "2026-08", label: "Aug 2026", share: 5187500, imad:  300000, aamer: 190417 },
  { month: "2026-09", label: "Sep 2026", share: 5187500, imad:  300000, aamer: 190417 },
  { month: "2026-10", label: "Oct 2026", share: 5187500, imad:  300000, aamer: 190417 },
  { month: "2026-11", label: "Nov 2026", share: 5187500, imad:  300000, aamer: 190417 },
  { month: "2026-12", label: "Dec 2026", share: 5187500, imad:  300000, aamer: 190417 },
  { month: "2027-01", label: "Jan 2027", share: 5187500, imad:  300000, aamer: 190417 },
  { month: "2027-02", label: "Feb 2027", share: 5187500, imad: 1085000, aamer: 190417 },
  { month: "2027-03", label: "Mar 2027", share: 5187500, imad: 1085000, aamer: 190417 },
  { month: "2027-04", label: "Apr 2027", share: 5187500, imad: 1085000, aamer: 190417 },
  { month: "2027-05", label: "May 2027", share: 5187500, imad: 1085000, aamer: 190417 },
  { month: "2027-06", label: "Jun 2027", share: 5187500, imad: 1085000, aamer: 190417 },
  { month: "2027-07", label: "Jul 2027", share: 5187500, imad: 1090000, aamer: 190413 },
];

const STREAMS = ["share", "imad", "aamer"];

/* "Deposits in Pak account" baseline (PKR). This is money already in Rabia's
 * Meezan account before any monthly table payment is marked:
 *   Pindi — PKR received (Meezan closing) ....... 5,611,300
 *   Pre-paid sale — 24 Jun 2026 ................ 250,000
 *   Pre-paid sale — 21 Jul 2026 .............. 5,000,000
 *                                             ----------
 *                                             10,861,300
 * The two pre-paid figures are NOT in SCHEDULE, so the accumulation loop below
 * (which only walks SCHEDULE months) can never double-count them. */
const PAK_BASELINE = 10861300;
const MAX_UPLOAD = 10 * 1024 * 1024;           // 10 MB per receipt
const OK_TYPES = [
  "image/jpeg", "image/png", "image/webp", "image/heic", "application/pdf",
];

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    try {
      if (path === "/api/health" && method === "GET") {
        return json({ ok: true, months: SCHEDULE.length });
      }

      if (path === "/api/rate/pkr-usd" && method === "GET") {
        try {
          const r = await fetch('https://api.frankfurter.app/latest?from=PKR&to=USD');
          const d = await r.json();
          return json({ rate: d.rates.USD, date: d.date });
        } catch {
          return json({ error: "rate_fetch_failed" }, 502);
        }
      }

      /* Full state — schedule joined with what has been marked paid. Open. */
      if (path === "/api/state" && method === "GET") {
        return json(await buildState(env));
      }

      /* Confirm a PIN without changing anything, so the UI can unlock. */
      if (path === "/api/unlock" && method === "POST") {
        const { pin } = await request.json();
        if (!pinOk(pin, env)) return json({ ok: false }, 401);
        return json({ ok: true });
      }

      /* Toggle one payment. Body: { month, stream, paid, paid_on?, pin } */
      if (path === "/api/toggle" && method === "POST") {
        const body = await request.json();
        if (!pinOk(body.pin, env)) return json({ error: "bad_pin" }, 401);

        const { month, stream } = body;
        if (!SCHEDULE.some(r => r.month === month)) return json({ error: "bad_month" }, 400);
        if (!STREAMS.includes(stream))              return json({ error: "bad_stream" }, 400);

        const state = await readState(env);
        state.payments[month] = state.payments[month] || {};

        if (body.paid) {
          state.payments[month][stream] = {
            paid:    true,
            paid_on: body.paid_on || today(),
            marked:  new Date().toISOString(),
          };
        } else {
          delete state.payments[month][stream];
        }

        await writeState(env, state);
        return json(await buildState(env));
      }

      /* Upload a receipt. Multipart: file, month, label, pin */
      if (path === "/api/receipt" && method === "POST") {
        const form = await request.formData();
        if (!pinOk(form.get("pin"), env)) return json({ error: "bad_pin" }, 401);

        const file    = form.get("file");
        const month   = form.get("month");
        const stream  = (form.get("stream")  || "").toString().trim();
        const label   = (form.get("label")   || "").toString().trim();
        const comment = (form.get("comment") || "").toString().trim();

        if (!file || typeof file === "string") return json({ error: "no_file" }, 400);
        if (!SCHEDULE.some(r => r.month === month)) return json({ error: "bad_month" }, 400);
        if (!label)                  return json({ error: "no_label" }, 400);
        if (file.size > MAX_UPLOAD)  return json({ error: "too_large" }, 413);
        if (file.type && !OK_TYPES.includes(file.type)) {
          return json({ error: "bad_type" }, 415);
        }

        const id  = crypto.randomUUID();
        const ext = (file.name || "").split(".").pop() || "bin";
        const key = `receipts/${month}/${id}.${ext}`;

        await env.RECEIPTS.put(key, file.stream(), {
          httpMetadata: { contentType: file.type || "application/octet-stream" },
        });

        const state = await readState(env);
        state.receipts[month] = state.receipts[month] || [];
        state.receipts[month].push({
          id,
          key,
          label,
          comment,
          stream,
          filename: file.name || "receipt",
          type:     file.type || "",
          size:     file.size,
          uploaded: new Date().toISOString(),
        });
        await writeState(env, state);

        return json(await buildState(env));
      }

      /* Serve a receipt file. Open — Imad and Aamer can view, not upload. */
      const getRcpt = path.match(/^\/api\/receipt\/([A-Za-z0-9-]+)$/);
      if (getRcpt && method === "GET") {
        const state = await readState(env);
        let found = null;
        for (const list of Object.values(state.receipts)) {
          const hit = list.find(r => r.id === getRcpt[1]);
          if (hit) { found = hit; break; }
        }
        if (!found) return json({ error: "not_found" }, 404);

        const obj = await env.RECEIPTS.get(found.key);
        if (!obj) return json({ error: "missing_file" }, 404);

        const h = new Headers();
        obj.writeHttpMetadata(h);
        h.set("Content-Disposition",
              `inline; filename="${found.filename.replace(/"/g, "")}"`);
        h.set("Cache-Control", "private, max-age=300");
        return cors(new Response(obj.body, { headers: h }));
      }

      /* Delete a receipt. PIN required. */
      const delRcpt = path.match(/^\/api\/receipt\/([A-Za-z0-9-]+)$/);
      if (delRcpt && method === "DELETE") {
        const { pin } = await request.json().catch(() => ({}));
        if (!pinOk(pin, env)) return json({ error: "bad_pin" }, 401);

        const state = await readState(env);
        for (const [month, list] of Object.entries(state.receipts)) {
          const i = list.findIndex(r => r.id === delRcpt[1]);
          if (i !== -1) {
            await env.RECEIPTS.delete(list[i].key).catch(() => {});
            list.splice(i, 1);
            if (!list.length) delete state.receipts[month];
            await writeState(env, state);
            return json(await buildState(env));
          }
        }
        return json({ error: "not_found" }, 404);
      }

      return json({ error: "not_found", path }, 404);

    } catch (err) {
      return json({ error: "server_error", message: err.message }, 500);
    }
  },
};

/* ------------------------------------------------------------------------ */

function pinOk(supplied, env) {
  const real = env.TRACKER_PIN;
  if (!real || !supplied) return false;
  const a = String(supplied), b = String(real);
  // Constant-time-ish compare so a wrong PIN cannot be found by timing.
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function readState(env) {
  const raw = await env.TRACKER.get(STATE_KEY);
  if (!raw) return { payments: {}, receipts: {} };
  const parsed = JSON.parse(raw);
  return { payments: parsed.payments || {}, receipts: parsed.receipts || {} };
}

async function writeState(env, state) {
  await env.TRACKER.put(STATE_KEY, JSON.stringify(state));
}

/* Join the fixed schedule with recorded payments and receipts, and compute
 * the running totals the page displays. */
async function buildState(env) {
  const state = await readState(env);

  const months = SCHEDULE.map(row => {
    const paid = state.payments[row.month] || {};
    const rcpt = state.receipts[row.month] || [];

    const streams = {};
    let receivedTotal = 0, paidCount = 0;
    for (const s of STREAMS) {
      const isPaid = !!(paid[s] && paid[s].paid);
      streams[s] = { due: row[s], paid: isPaid, paid_on: isPaid ? paid[s].paid_on : null };
      if (isPaid) { receivedTotal += row[s]; paidCount++; }
    }

    return {
      month: row.month,
      label: row.label,
      streams,
      due_total:      row.share + row.imad + row.aamer,
      received_total: receivedTotal,
      paid_count:     paidCount,
      receipts: rcpt.map(r => ({
        id: r.id, label: r.label, comment: r.comment || "",
        stream: r.stream || "", filename: r.filename,
        type: r.type, size: r.size, uploaded: r.uploaded,
      })),
    };
  });

  const totals = { share: 0, imad: 0, aamer: 0, due: 0, received: 0 };
  const outstanding = { share: 0, imad: 0, aamer: 0 };
  for (const m of months) {
    for (const s of STREAMS) {
      totals[s] += m.streams[s].due;
      if (!m.streams[s].paid) outstanding[s] += m.streams[s].due;
    }
    totals.due      += m.due_total;
    totals.received += m.received_total;
  }
  totals.outstanding = totals.due - totals.received;

  /* "Deposits in Pak account" = fixed baseline PLUS every individual stream
   * (share / imad / aamer) that has been marked received in the monthly table.
   * Because it is derived from the persisted payments each time buildState runs,
   * marking a payment adds its amount and un-marking subtracts it, automatically.
   * All amounts are PKR; the USD equivalent is computed on the client from the
   * live rate, so nothing USD is stored here. */
  const pakAccountDeposits = PAK_BASELINE + totals.received;

  return { months, totals, outstanding, streams: STREAMS,
           pakBaseline: PAK_BASELINE, pakAccountDeposits };
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function json(data, status = 200) {
  return cors(new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  }));
}

/* Tighten the origin to the GHL site before this goes live. */
function cors(res) {
  res.headers.set("Access-Control-Allow-Origin", "*");
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type");
  return res;
}
