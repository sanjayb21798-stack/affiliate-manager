// server.js — Affiliate Manager (JSON DB)
// Features: Admin login, Affiliate login (code+PIN), PIN reset (admin),
// Merchants + coupons, redirect with coupon injection, conversions, payouts, CSV exports,
// Razorpay webhook (verified), Manual UPI/offline conversion (admin).

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const { db, save } = require('./store');

const app = express();

/* -------------------- Config -------------------- */
const ADMIN_KEY = process.env.ADMIN_KEY || 'changeme-admin-key';   // legacy header support for scripts
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';           // optional global secret for webhooks (/webhooks/razorpay AND /api/convert)

const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-session-secret';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'plain:admin123'; // use 'plain:password' in dev

/* -------------------- Middleware (order matters!) -------------------- */
app.use(cors());

// IMPORTANT: For Razorpay, we must read the **raw body** to verify signature.
// So we install a path-specific raw parser BEFORE express.json().
app.use('/webhooks/razorpay', express.raw({ type: '*/*' })); // raw Buffer on req.body for this path only

// Normal parsers for the rest of the app
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'affsid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 3600 * 1000 // 7 days
    // secure: true // enable when serving over HTTPS
  }
}));

app.use(express.static('public'));

/* -------------------- Utils -------------------- */
const nowISO = () => new Date().toISOString();
const centsToRs = (c) => (c / 100).toFixed(2);

function getAffiliateByCode(code) {
  return (db.affiliates || []).find((a) => a.code === code);
}
function availableFor(code) {
  const earned = (db.commissions || []).filter((m) => m.code === code).reduce((s, m) => s + m.amount_cents, 0);
  const paid = (db.payouts || []).filter((p) => p.code === code && ['approved', 'paid'].includes(p.status))
                                 .reduce((s, p) => s + p.amount_cents, 0);
  return Math.max(0, earned - paid);
}
function getMerchant(id) {
  return (db.merchants || []).find(m => m.id === id);
}
function getCouponFor(merchantId, affiliateCode) {
  return (db.coupons || []).find(c => c.merchantId === merchantId && c.affiliateCode === affiliateCode);
}

/* --- Helper: add a conversion + commission (dedupe by code+orderId) --- */
function addConversion(code, orderId, amountCents) {
  const aff = getAffiliateByCode(code);
  if (!aff) return { ok:false, status:404, error:'unknown affiliate code' };

  if ((db.conversions || []).find(v => v.code === code && v.order_id === orderId)) {
    const dup = db.conversions.find(v => v.code === code && v.order_id === orderId);
    return { ok:false, status:409, error:'duplicate conversion', conversionId: dup.id };
  }

  const amt = Math.max(0, Number(amountCents || 0));
  const conv = { id: nanoid(), code, order_id: orderId, amount_cents: amt, ts: nowISO() };
  db.conversions.push(conv);

  const commission = Math.floor((amt * aff.rate_bps) / 10000);
  db.commissions.push({
    id: nanoid(),
    code,
    conversion_id: conv.id,
    amount_cents: commission,
    status: 'pending',
    ts: nowISO()
  });

  save(db);
  return { ok:true, conversionId: conv.id, commissionCents: commission };
}

/* -------------------- Admin auth helpers -------------------- */
let adminPassHash = null;
(function prepareAdminHash(){
  if (ADMIN_PASSWORD.startsWith('plain:')) {
    adminPassHash = bcrypt.hashSync(ADMIN_PASSWORD.slice(6), 10);
  } else {
    adminPassHash = ADMIN_PASSWORD; // pre-hashed bcrypt allowed
  }
})();
function isSessionAdmin(req) {
  return req.session?.user === ADMIN_USER && req.session?.role === 'admin';
}
function requireAdmin(req, res, next) {
  const headerOK = (req.headers['x-admin-key'] || '') === ADMIN_KEY;
  if (isSessionAdmin(req) || headerOK) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

/* -------------------- Affiliate session helper -------------------- */
function isAffiliate(req){
  return req.session?.role === 'affiliate' && !!req.session?.affCode;
}

/* -------------------- Admin auth routes -------------------- */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password || '', adminPassHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  req.session.user = ADMIN_USER;
  req.session.role = 'admin';
  res.json({ ok: true, user: ADMIN_USER });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => {
  if (!isSessionAdmin(req)) return res.json({ user: null });
  res.json({ user: ADMIN_USER, role: 'admin' });
});

/* -------------------- Create affiliate (with PIN) -------------------- */
app.post('/api/affiliates', (req, res) => {
  const name = (req.body.name || '').trim();
  const rateBps = Math.max(0, Math.min(10000, Number(req.body.rateBps ?? 1000)));
  if (!name) return res.status(400).json({ error: 'name is required' });

  const pin = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit PIN
  const pin_hash = bcrypt.hashSync(pin, 10);

  const affiliate = {
    id: nanoid(),
    name,
    code: nanoid(8),
    rate_bps: rateBps,
    pin_hash,
    created_at: nowISO(),
  };
  db.affiliates.push(affiliate);
  save(db);

  res.json({
    id: affiliate.id,
    name: affiliate.name,
    code: affiliate.code,
    pin, // show once so admin can share
    rateBps: affiliate.rate_bps,
    link: `http://localhost:3000/r/${affiliate.code}`,
    portal: `http://localhost:3000/affiliate-login.html`
  });
});

/* -------------------- Admin: reset affiliate PIN -------------------- */
app.post('/api/admin/affiliates/:code/reset-pin', requireAdmin, (req, res) => {
  const code = req.params.code;
  const a = getAffiliateByCode(code);
  if (!a) return res.status(404).json({ error: 'unknown affiliate code' });
  const newPin = Math.floor(100000 + Math.random() * 900000).toString();
  a.pin_hash = bcrypt.hashSync(newPin, 10);
  save(db);
  res.json({ ok: true, newPin });
});

/* -------------------- Affiliate session routes -------------------- */
app.post('/api/affiliate/login', async (req, res) => {
  const { code, pin } = req.body || {};
  const a = db.affiliates.find(x => x.code === String(code || '').trim());
  if (!a) return res.status(401).json({ error: 'invalid code or pin' });
  const ok = await bcrypt.compare(String(pin || '').trim(), a.pin_hash);
  if (!ok) return res.status(401).json({ error: 'invalid code or pin' });
  req.session.role = 'affiliate';
  req.session.affCode = a.code;
  res.json({ ok: true, code: a.code, name: a.name });
});
app.post('/api/affiliate/logout', (req, res) => {
  if (isAffiliate(req)) return req.session.destroy(() => res.json({ ok: true }));
  res.json({ ok: true });
});
app.get('/api/affiliate/me', (req, res) => {
  if (!isAffiliate(req)) return res.status(401).json({ error: 'not logged in' });
  const code = req.session.affCode;
  const a = getAffiliateByCode(code);
  if (!a) return res.status(404).json({ error: 'unknown code' });

  const clicks = (db.clicks || []).filter((c) => c.code === code).length;
  const convs = (db.conversions || []).filter((v) => v.code === code);
  const revenue = convs.reduce((s, v) => s + v.amount_cents, 0);
  const earned = (db.commissions || []).filter((m) => m.code === code).reduce((s, m) => s + m.amount_cents, 0);
  const paid = (db.payouts || []).filter((p) => p.code === code && ['approved','paid'].includes(p.status)).reduce((s, p) => s + p.amount_cents, 0);
  const avail = Math.max(0, earned - paid);

  res.json({
    name: a.name,
    code,
    rateBps: a.rate_bps,
    clicks,
    conversions: convs.length,
    revenue: (revenue/100).toFixed(2),
    earned: (earned/100).toFixed(2),
    paidOut: (paid/100).toFixed(2),
    available: (avail/100).toFixed(2),
    shareLink: `http://localhost:3000/r/${a.code}`
  });
});

/* -------------------- Merchants & coupons -------------------- */
app.post('/api/merchants', requireAdmin, (req, res) => {
  const { id, name, checkout_url, coupon_param, razorpay_webhook_secret } = req.body || {};
  if (!id || !name || !checkout_url || !coupon_param) {
    return res.status(400).json({ error: 'id, name, checkout_url, coupon_param required' });
  }
  db.merchants = db.merchants || [];
  if (db.merchants.some(m => m.id === id)) return res.status(409).json({ error: 'merchant id exists' });

  db.merchants.push({
    id, name, checkout_url, coupon_param,
    razorpay_webhook_secret: razorpay_webhook_secret || ''
  });
  save(db);
  res.json({ ok: true });
});
app.post('/api/coupons', requireAdmin, (req, res) => {
  const { merchantId, affiliateCode, coupon } = req.body || {};
  if (!merchantId || !affiliateCode || !coupon) {
    return res.status(400).json({ error: 'merchantId, affiliateCode, coupon required' });
  }
  if (!getMerchant(merchantId)) return res.status(404).json({ error: 'unknown merchantId' });
  if (!getAffiliateByCode(affiliateCode)) return res.status(404).json({ error: 'unknown affiliateCode' });

  db.coupons = db.coupons || [];
  const existing = db.coupons.find(c => c.merchantId === merchantId && c.affiliateCode === affiliateCode);
  if (existing) existing.coupon = coupon; else db.coupons.push({ merchantId, affiliateCode, coupon });

  save(db);
  res.json({ ok: true });
});

/* -------------------- Redirect with coupon injection -------------------- */
app.get('/r/:code', (req, res) => {
  const code = req.params.code;
  const aff = getAffiliateByCode(code);
  if (!aff) return res.status(404).send('Invalid affiliate code');

  // record click
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
  db.clicks = db.clicks || [];
  db.clicks.push({ id: nanoid(), code, ip, ua: req.headers['user-agent'] || '', ts: nowISO() });
  save(db);

  // merchant & coupon mapping
  const merchantId = (req.query.m || 'm1').toString().trim();
  const m = getMerchant(merchantId);
  if (!m) return res.status(404).send('Unknown merchant');

  const map = getCouponFor(merchantId, code);
  if (!map) return res.status(404).send('No coupon mapped for this affiliate and merchant');

  // build checkout URL with coupon + aff (invisible to customer)
  const u = new URL(m.checkout_url);
  const couponParam = m.coupon_param || 'coupon';
  u.searchParams.set(couponParam, map.coupon);
  u.searchParams.set('aff', code);

  res.redirect(u.toString());
});

/* -------------------- Optional HMAC verification for /api/convert -------------------- */
function verifyWebhook(req) {
  if (!WEBHOOK_SECRET) return true; // disabled for local demo
  const sig = req.headers['x-signature'];
  if (!sig) return false;
  const canonical = JSON.stringify({
    code: req.body?.code ?? null,
    orderId: req.body?.orderId ?? null,
    amountCents: Number(req.body?.amountCents ?? 0)
  });
  const h = crypto.createHmac('sha256', WEBHOOK_SECRET).update(canonical).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(sig));
}

/* -------------------- Conversion (generic/manual) -------------------- */
app.post('/api/convert', (req, res) => {
  const { code, orderId, amountCents } = req.body || {};
  if (!code || !orderId) return res.status(400).json({ error: 'code and orderId required' });
  if (!verifyWebhook(req)) return res.status(401).json({ error: 'invalid signature' });

  const r = addConversion(code, orderId, Number(amountCents || 0));
  if (!r.ok) return res.status(r.status || 400).json(r);
  res.json(r);
});

/* -------------------- Razorpay webhook (verified with raw body) -------------------- */
// Razorpay sends HMAC in X-Razorpay-Signature over raw body.
// We also support per-merchant secrets (merchant.razorpay_webhook_secret) with notes.merchantId.
app.post('/webhooks/razorpay', (req, res) => {
  try {
    const rpSig = req.headers['x-razorpay-signature'];
    const bodyBuf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    const bodyStr = bodyBuf.toString('utf8');

    // Parse event
    let evt;
    try { evt = JSON.parse(bodyStr); } catch { return res.status(400).send('bad json'); }
    const eventType = String(evt?.event || '');
    const payment = evt?.payload?.payment?.entity || null;

    // Determine merchant + secret
    const merchantId = payment?.notes?.merchantId || 'm1';
    const merchant = getMerchant(merchantId);
    const secret = merchant?.razorpay_webhook_secret || WEBHOOK_SECRET;
    if (!secret) return res.status(401).send('no secret');

    // Verify signature
    const h = crypto.createHmac('sha256', secret).update(bodyStr).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(h), Buffer.from(String(rpSig || ''), 'utf8'))) {
      return res.status(401).send('bad signature');
    }

    // Accept only success events
    if (!['payment.captured', 'order.paid'].includes(eventType)) {
      return res.status(200).json({ ok:true, ignored:true, event:eventType });
    }

    // Extract data
    let code = payment?.notes?.aff || null;            // preferred
    const coupon = payment?.notes?.coupon || null;     // optional fallback
    const orderId = payment?.order_id || payment?.id || `rp-${Date.now()}`;
    const amountCents = Number(payment?.amount || 0);  // paise

    // If no 'aff', try resolving via coupon mapping
    if (!code && coupon) {
      const map = (db.coupons || []).find(c => c.merchantId === merchantId && c.coupon === coupon);
      if (map) code = map.affiliateCode;
    }
    if (!code) return res.status(400).json({ error:'no affiliate code in notes and no coupon mapping' });

    const r = addConversion(code, orderId, amountCents);
    if (!r.ok) return res.status(r.status || 400).json(r);

    return res.status(200).json({ ok:true, event:eventType, ...r });
  } catch (e) {
    console.error('Razorpay webhook error', e);
    return res.status(400).send('bad payload');
  }
});

/* -------------------- Admin manual conversion (UPI/offline) -------------------- */
app.post('/api/admin/manual-convert', requireAdmin, (req, res) => {
  const { code, orderId, amountCents, amountRupees } = req.body || {};
  if (!code || !orderId) return res.status(400).json({ error: 'code and orderId required' });
  const cents = amountCents != null ? Number(amountCents) : Math.round(Number(amountRupees || 0) * 100);
  const r = addConversion(code, orderId, cents);
  if (!r.ok) return res.status(r.status || 400).json(r);
  res.json(r);
});

/* -------------------- Stats (admin overview) -------------------- */
app.get('/api/stats', (req, res) => {
  const rows = (db.affiliates || [])
    .slice()
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
    .map((a) => {
      const clicks = (db.clicks || []).filter((c) => c.code === a.code).length;
      const convs = (db.conversions || []).filter((v) => v.code === a.code);
      const revenue = convs.reduce((s, v) => s + v.amount_cents, 0);
      const earned = (db.commissions || []).filter((m) => m.code === a.code).reduce((s, m) => s + m.amount_cents, 0);
      const paid = (db.payouts || []).filter((p) => p.code === a.code && ['approved', 'paid'].includes(p.status)).reduce((s, p) => s + p.amount_cents, 0);
      const avail = Math.max(0, earned - paid);

      return {
        name: a.name,
        code: a.code,
        rateBps: a.rate_bps,
        clicks,
        conversions: convs.length,
        revenue: centsToRs(revenue),
        earned: centsToRs(earned),
        paidOut: centsToRs(paid),
        available: centsToRs(avail),
        shareLink: `http://localhost:3000/r/${a.code}`,
        portal: `http://localhost:3000/affiliate-login.html`
      };
    });

  res.json(rows);
});

/* -------------------- Affiliate public stats by code -------------------- */
app.get('/api/affiliate/:code', (req, res) => {
  const code = req.params.code;
  const a = getAffiliateByCode(code);
  if (!a) return res.status(404).json({ error: 'unknown code' });

  const clicks = (db.clicks || []).filter((c) => c.code === code).length;
  const convs = (db.conversions || []).filter((v) => v.code === code);
  const revenue = convs.reduce((s, v) => s + v.amount_cents, 0);
  const earned = (db.commissions || []).filter((m) => m.code === code).reduce((s, m) => s + m.amount_cents, 0);
  const paid = (db.payouts || []).filter((p) => p.code === code && ['approved', 'paid'].includes(p.status)).reduce((s, p) => s + p.amount_cents, 0);
  const avail = Math.max(0, earned - paid);

  res.json({
    name: a.name,
    code,
    rateBps: a.rate_bps,
    clicks,
    conversions: convs.length,
    revenue: centsToRs(revenue),
    earned: centsToRs(earned),
    paidOut: centsToRs(paid),
    available: centsToRs(avail),
    shareLink: `http://localhost:3000/r/${a.code}`
  });
});

/* -------------------- Payouts -------------------- */
app.post('/api/payouts/request', (req, res) => {
  const code = (req.body.code || '').trim();
  const a = getAffiliateByCode(code);
  if (!a) return res.status(404).json({ error: 'unknown code' });

  let amountCents = req.body.amountCents == null ? null : Number(req.body.amountCents);
  const avail = availableFor(code);
  if (amountCents == null) amountCents = avail;
  if (amountCents <= 0) return res.status(400).json({ error: 'nothing available to payout' });
  if (amountCents > avail) return res.status(400).json({ error: 'amount exceeds available' });

  const MIN_WITHDRAW_CENTS = 10000; // ₹100 minimum
  if (amountCents < MIN_WITHDRAW_CENTS) {
    return res.status(400).json({ error: 'minimum withdrawal is ₹100.00' });
  }

  db.payouts = db.payouts || [];
  const payout = { id: nanoid(), code, amount_cents: Math.floor(amountCents), status: 'requested', ts: nowISO() };
  db.payouts.push(payout);
  save(db);
  res.json({ ok: true, payoutId: payout.id });
});

app.get('/api/admin/payouts', requireAdmin, (req, res) => {
  const rows = (db.payouts || []).slice().sort((a, b) => (a.ts < b.ts ? 1 : -1));
  res.json(rows);
});
app.post('/api/admin/payouts/:id/approve', requireAdmin, (req, res) => {
  const id = req.params.id;
  const p = (db.payouts || []).find((x) => x.id === id);
  if (!p) return res.status(404).json({ error: 'not found' });
  if (p.status !== 'requested') return res.status(400).json({ error: 'not in requested state' });
  p.status = 'approved'; save(db); res.json({ ok: true });
});
app.post('/api/admin/payouts/:id/mark-paid', requireAdmin, (req, res) => {
  const id = req.params.id;
  const p = (db.payouts || []).find((x) => x.id === id);
  if (!p) return res.status(404).json({ error: 'not found' });
  if (!['approved', 'paid'].includes(p.status)) return res.status(400).json({ error: 'must be approved first' });
  p.status = 'paid'; save(db); res.json({ ok: true });
});

/* -------------------- CSV exports (admin) -------------------- */
function toCSV(rows, headers) {
  const esc = (v) => {
    const s = String(v ?? '');
    if (s.includes(',') || s.includes('"') || s.includes('\n')) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const head = headers.join(',');
  const body = rows.map((r) => headers.map((h) => esc(r[h])).join(',')).join('\n');
  return head + '\n' + body + '\n';
}
app.get('/api/admin/export/conversions.csv', requireAdmin, (req, res) => {
  const rows = (db.conversions || []).map((v) => ({
    id: v.id, code: v.code, order_id: v.order_id,
    amount_rupees: centsToRs(v.amount_cents), ts: v.ts
  }));
  const csv = toCSV(rows, ['id','code','order_id','amount_rupees','ts']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="conversions.csv"');
  res.send(csv);
});
app.get('/api/admin/export/payouts.csv', requireAdmin, (req, res) => {
  const rows = (db.payouts || []).map((p) => ({
    id: p.id, code: p.code, amount_rupees: centsToRs(p.amount_cents), status: p.status, ts: p.ts
  }));
  const csv = toCSV(rows, ['id','code','amount_rupees','status','ts']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="payouts.csv"');
  res.send(csv);
});

/* -------------------- Start -------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Affiliate manager running: http://localhost:${PORT}`));

