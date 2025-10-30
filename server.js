// server.js — Affiliate Manager (multi-role: Owner, Admin, Affiliate)

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');

const { db, save } = require('./store');

const app = express();

/* -------------------- Config -------------------- */
// Owner (Platform) creds (use 'plain:password' in dev)
const OWNER_USER = process.env.OWNER_USER || 'aidmd';
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || 'plain:eleven';

// For legacy script calls (optional)
const ADMIN_KEY = process.env.ADMIN_KEY || 'changeme-admin-key';
// Optional HMAC for /api/convert
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';

const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-session-secret';

// Backward compatibility bootstrap admin (used only if no admins exist)
const BOOT_ADMIN_USER = process.env.ADMIN_USER || 'admin';
const BOOT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'plain:admin123';

/* -------------------- Middleware -------------------- */
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'affsid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 }
}));

app.use(express.static(path.join(__dirname, 'public')));

/* -------------------- Utils -------------------- */
const nowISO = () => new Date().toISOString();
const centsToRs = (c) => (c / 100).toFixed(2);

function getAffiliateByCode(code) {
  return db.affiliates.find((a) => a.code === code);
}
function availableFor(code) {
  const earned = db.commissions.filter((m) => m.code === code).reduce((s, m) => s + m.amount_cents, 0);
  const paid = db.payouts.filter((p) => p.code === code && ['approved', 'paid'].includes(p.status))
                         .reduce((s, p) => s + p.amount_cents, 0);
  return Math.max(0, earned - paid);
}
function escLikeAdminScope(adminId) {
  // include rows with matching admin_id OR missing (old data) to not break MVP
  return (row) => (row.admin_id === adminId) || (row.admin_id == null);
}

/* -------------------- Bootstraps -------------------- */
let ownerPassHash = null;
(function prepOwner() {
  if (OWNER_PASSWORD.startsWith('plain:')) ownerPassHash = bcrypt.hashSync(OWNER_PASSWORD.slice(6), 10);
  else ownerPassHash = OWNER_PASSWORD;
})();

// If no admins in DB, create a bootstrap admin from env
(function ensureBootstrapAdmin() {
  if (!Array.isArray(db.admins)) db.admins = [];
  if (db.admins.length === 0) {
    const passHash = BOOT_ADMIN_PASSWORD.startsWith('plain:')
      ? bcrypt.hashSync(BOOT_ADMIN_PASSWORD.slice(6), 10)
      : BOOT_ADMIN_PASSWORD;
    db.admins.push({
      id: nanoid(),
      username: BOOT_ADMIN_USER,
      name: 'Default Admin',
      pass_hash: passHash,
      created_at: nowISO()
    });
    save(db);
    console.log(`Bootstrap admin created: ${BOOT_ADMIN_USER}`);
  }
})();

/* -------------------- Auth helpers -------------------- */
function isOwner(req){ return req.session?.role === 'owner'; }
function isAdmin(req){ return req.session?.role === 'admin' && !!req.session?.adminId; }
function isAffiliate(req){ return req.session?.role === 'affiliate' && !!req.session?.affCode; }

function requireOwner(req,res,next){ if (isOwner(req)) return next(); return res.status(401).json({error:'unauthorized'}); }
function requireAdmin(req,res,next){
  const headerOK = (req.headers['x-admin-key'] || '') === ADMIN_KEY; // legacy
  if (isAdmin(req) || headerOK) return next();
  return res.status(401).json({error:'unauthorized'});
}

/* -------------------- Health -------------------- */
app.get('/healthz', (_req,res) => res.json({ok:true}));

/* -------------------- Home + Static Landing -------------------- */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html'))); // admin login
app.get('/affiliate-login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'affiliate-login.html')));
app.get('/owner-login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'owner-login.html')));
app.get('/owner.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'owner.html')));

/* -------------------- Owner Auth -------------------- */
app.post('/api/owner/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== OWNER_USER) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password || '', ownerPassHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  req.session.role = 'owner';
  req.session.user = OWNER_USER;
  res.json({ ok: true, user: OWNER_USER, role: 'owner' });
});
app.post('/api/owner/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/owner/me', (req, res) => res.json(isOwner(req) ? { user: OWNER_USER, role:'owner' } : { user:null }));

/* -------------------- Owner: Admins CRUD -------------------- */
app.get('/api/owner/admins', requireOwner, (req, res) => {
  const rows = db.admins.map(a => ({ id:a.id, username:a.username, name:a.name, created_at:a.created_at }));
  res.json(rows);
});

app.post('/api/owner/admins', requireOwner, (req, res) => {
  const { username, name, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (db.admins.some(a => a.username === username)) return res.status(409).json({ error: 'username exists' });
  const pass_hash = bcrypt.hashSync(password, 10);
  const admin = { id: nanoid(), username, name: (name||username), pass_hash, created_at: nowISO() };
  db.admins.push(admin); save(db);
  res.json({ ok: true, id: admin.id });
});

app.post('/api/owner/admins/:id/reset-password', requireOwner, (req, res) => {
  const a = db.admins.find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });
  a.pass_hash = bcrypt.hashSync(password, 10);
  save(db);
  res.json({ ok: true });
});

/* -------------------- Owner: Overview -------------------- */
app.get('/api/owner/overview', requireOwner, (req, res) => {
  const totalAdmins = db.admins.length;
  const totalAffiliates = db.affiliates.length;
  res.json({ totalAdmins, totalAffiliates });
});

/* -------------------- Admin Auth (multi-tenant) -------------------- */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const a = db.admins.find(x => x.username === String(username||'').trim());
  if (!a) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(String(password||''), a.pass_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  req.session.role = 'admin';
  req.session.adminId = a.id;
  req.session.adminUsername = a.username;
  res.json({ ok: true, user: a.username, role: 'admin' });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok:true })));
app.get('/api/me', (req, res) => {
  if (!isAdmin(req)) return res.json({ user: null });
  res.json({ user: req.session.adminUsername, role: 'admin' });
});

/* -------------------- Create affiliate (scoped) -------------------- */
app.post('/api/affiliates', requireAdmin, (req, res) => {
  const name = (req.body.name || '').trim();
  const rateBps = Math.max(0, Math.min(10000, Number(req.body.rateBps ?? 1000)));
  if (!name) return res.status(400).json({ error: 'name is required' });

  const pin = Math.floor(100000 + Math.random() * 900000).toString();
  const pin_hash = bcrypt.hashSync(pin, 10);

  const affiliate = {
    id: nanoid(),
    admin_id: req.session.adminId,         // scope!
    name,
    code: nanoid(8),
    rate_bps: rateBps,
    pin_hash,
    created_at: nowISO(),
  };
  db.affiliates.push(affiliate); save(db);

  res.json({
    id: affiliate.id,
    name: affiliate.name,
    code: affiliate.code,
    pin,
    rateBps: affiliate.rate_bps,
    link: `http://localhost:3000/r/${affiliate.code}`,
    portal: `/affiliate-login.html`
  });
});

/* -------------------- Admin: reset affiliate PIN -------------------- */
app.post('/api/admin/affiliates/:code/reset-pin', requireAdmin, (req, res) => {
  const code = req.params.code;
  const a = db.affiliates.find(x => x.code === code && escLikeAdminScope(req.session.adminId)(x));
  if (!a) return res.status(404).json({ error: 'unknown affiliate code' });
  const newPin = Math.floor(100000 + Math.random() * 900000).toString();
  a.pin_hash = bcrypt.hashSync(newPin, 10);
  save(db);
  res.json({ ok: true, newPin });
});

/* -------------------- Affiliate session -------------------- */
app.post('/api/affiliate/login', async (req, res) => {
  const { code, pin } = req.body || {};
  const a = db.affiliates.find(x => x.code === String(code||'').trim());
  if (!a) return res.status(401).json({ error: 'invalid code or pin' });
  const ok = await bcrypt.compare(String(pin||'').trim(), a.pin_hash);
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

  const clicks = db.clicks.filter((c) => c.code === code).length;
  const convs = db.conversions.filter((v) => v.code === code);
  const revenue = convs.reduce((s, v) => s + v.amount_cents, 0);
  const earned = db.commissions.filter((m) => m.code === code).reduce((s, m) => s + m.amount_cents, 0);
  const paid = db.payouts.filter((p) => p.code === code && ['approved','paid'].includes(p.status)).reduce((s, p) => s + p.amount_cents, 0);
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
    shareLink: `/r/${a.code}`
  });
});

/* -------------------- Merchants + coupons (scoped) -------------------- */
function getMerchant(id) {
  return (db.merchants || []).find(m => m.id === id);
}
function getCouponFor(merchantId, affiliateCode) {
  return (db.coupons || []).find(c => c.merchantId === merchantId && c.affiliateCode === affiliateCode);
}

app.post('/api/merchants', requireAdmin, (req, res) => {
  const { id, name, checkout_url, coupon_param, razorpay_webhook_secret } = req.body || {};
  if (!id || !name || !checkout_url || !coupon_param) {
    return res.status(400).json({ error: 'id, name, checkout_url, coupon_param required' });
  }
  db.merchants = db.merchants || [];
  if (db.merchants.some(m => m.id === id && escLikeAdminScope(req.session.adminId)(m))) {
    return res.status(409).json({ error: 'merchant id exists' });
  }

  db.merchants.push({
    id, name, checkout_url, coupon_param,
    admin_id: req.session.adminId,          // scope!
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
  const m = db.merchants.find(x => x.id === merchantId && escLikeAdminScope(req.session.adminId)(x));
  if (!m) return res.status(404).json({ error: 'unknown merchantId' });

  const a = db.affiliates.find(x => x.code === affiliateCode && escLikeAdminScope(req.session.adminId)(x));
  if (!a) return res.status(404).json({ error: 'unknown affiliateCode' });

  db.coupons = db.coupons || [];
  const existing = db.coupons.find(c => c.merchantId === merchantId && c.affiliateCode === affiliateCode);
  if (existing) existing.coupon = coupon;
  else db.coupons.push({ merchantId, affiliateCode, coupon, admin_id: req.session.adminId }); // scope
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
  db.clicks.push({ id: nanoid(), code, ip, ua: req.headers['user-agent'] || '', ts: nowISO() });
  save(db);

  // merchant & coupon mapping
  const merchantId = (req.query.m || 'm1').toString().trim();
  const m = getMerchant(merchantId);
  if (!m) return res.status(404).send('Unknown merchant');

  const map = getCouponFor(merchantId, code);
  if (!map) return res.status(404).send('No coupon mapped for this affiliate and merchant');

  const u = new URL(m.checkout_url);
  const couponParam = m.coupon_param || 'coupon';
  u.searchParams.set(couponParam, map.coupon);
  u.searchParams.set('aff', code);

  res.redirect(u.toString());
});

/* -------------------- Conversion (sales only) -------------------- */
function verifyWebhook(req) {
  if (!WEBHOOK_SECRET) return true;
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

app.post('/api/convert', (req, res) => {
  const { code, orderId, amountCents } = req.body || {};
  if (!code || !orderId) return res.status(400).json({ error: 'code and orderId required' });
  if (!verifyWebhook(req)) return res.status(401).json({ error: 'invalid signature' });

  const aff = getAffiliateByCode(code);
  if (!aff) return res.status(404).json({ error: 'unknown affiliate code' });

  const dup = db.conversions.find((v) => v.code === code && v.order_id === orderId);
  if (dup) return res.status(409).json({ error: 'duplicate conversion', conversionId: dup.id });

  const amount = Math.max(0, Number(amountCents || 0));
  const conv = { id: nanoid(), code, order_id: orderId, amount_cents: amount, ts: nowISO(), admin_id: aff.admin_id || null };
  db.conversions.push(conv);

  const commission = Math.floor((amount * aff.rate_bps) / 10000);
  db.commissions.push({
    id: nanoid(),
    code,
    conversion_id: conv.id,
    amount_cents: commission,
    status: 'pending',
    ts: nowISO(),
    admin_id: aff.admin_id || null
  });

  save(db);
  res.json({ ok: true, conversionId: conv.id, commissionCents: commission });
});

/* -------------------- Stats -------------------- */
// Admin view (scoped)
app.get('/api/stats', requireAdmin, (req, res) => {
  const scope = escLikeAdminScope(req.session.adminId);
  const rows = db.affiliates
    .filter(scope)
    .slice()
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
    .map((a) => {
      const clicks = db.clicks.filter((c) => c.code === a.code).length;
      const convs = db.conversions.filter((v) => v.code === a.code);
      const revenue = convs.reduce((s, v) => s + v.amount_cents, 0);
      const earned = db.commissions.filter((m) => m.code === a.code).reduce((s, m) => s + m.amount_cents, 0);
      const paid = db.payouts.filter((p) => p.code === a.code && ['approved', 'paid'].includes(p.status)).reduce((s, p) => s + p.amount_cents, 0);
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
        shareLink: `/r/${a.code}`,
        portal: `/affiliate-login.html`
      };
    });

  res.json(rows);
});

// Public affiliate stats by code (unchanged)
app.get('/api/affiliate/:code', (req, res) => {
  const code = req.params.code;
  const a = getAffiliateByCode(code);
  if (!a) return res.status(404).json({ error: 'unknown code' });

  const clicks = db.clicks.filter((c) => c.code === code).length;
  const convs = db.conversions.filter((v) => v.code === code);
  const revenue = convs.reduce((s, v) => s + v.amount_cents, 0);
  const earned = db.commissions.filter((m) => m.code === code).reduce((s, m) => s + m.amount_cents, 0);
  const paid = db.payouts.filter((p) => p.code === code && ['approved','paid'].includes(p.status)).reduce((s, p) => s + p.amount_cents, 0);
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
    shareLink: `/r/${a.code}`
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

  const MIN_WITHDRAW_CENTS = 10000; // ₹100
  if (amountCents < MIN_WITHDRAW_CENTS) return res.status(400).json({ error: 'minimum withdrawal is ₹100.00' });

  const payout = { id: nanoid(), code, amount_cents: Math.floor(amountCents), status: 'requested', ts: nowISO(), admin_id: a.admin_id || null };
  db.payouts.push(payout); save(db);
  res.json({ ok: true, payoutId: payout.id });
});

app.get('/api/admin/payouts', requireAdmin, (req, res) => {
  const scope = escLikeAdminScope(req.session.adminId);
  res.json(db.payouts.filter(scope).slice().sort((a,b)=> (a.ts < b.ts ? 1 : -1)));
});
app.post('/api/admin/payouts/:id/approve', requireAdmin, (req, res) => {
  const p = db.payouts.find((x) => x.id === req.params.id && escLikeAdminScope(req.session.adminId)(x));
  if (!p) return res.status(404).json({ error: 'not found' });
  if (p.status !== 'requested') return res.status(400).json({ error: 'not in requested state' });
  p.status = 'approved'; save(db); res.json({ ok: true });
});
app.post('/api/admin/payouts/:id/mark-paid', requireAdmin, (req, res) => {
  const p = db.payouts.find((x) => x.id === req.params.id && escLikeAdminScope(req.session.adminId)(x));
  if (!p) return res.status(404).json({ error: 'not found' });
  if (!['approved','paid'].includes(p.status)) return res.status(400).json({ error: 'must be approved first' });
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
  const scope = escLikeAdminScope(req.session.adminId);
  const rows = db.conversions.filter(scope).map((v) => ({
    id: v.id, code: v.code, order_id: v.order_id,
    amount_rupees: centsToRs(v.amount_cents), ts: v.ts
  }));
  const csv = toCSV(rows, ['id','code','order_id','amount_rupees','ts']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="conversions.csv"');
  res.send(csv);
});
app.get('/api/admin/export/payouts.csv', requireAdmin, (req, res) => {
  const scope = escLikeAdminScope(req.session.adminId);
  const rows = db.payouts.filter(scope).map((p) => ({
    id: p.id, code: p.code, amount_rupees: centsToRs(p.amount_cents), status: p.status, ts: p.ts
  }));
  const csv = toCSV(rows, ['id','code','amount_rupees','status','ts']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="payouts.csv"');
  res.send(csv);
});

/* -------------------- Start server -------------------- */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Affiliate manager running: http://localhost:${PORT}`);
});


