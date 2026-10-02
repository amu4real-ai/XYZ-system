// XYZ Collection – inventory & sales server (Node.js + SQLite)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.13+ (no npm install needed)
const PORT = process.env.PORT || 3000;
const TZ = process.env.TZ_NAME || 'Africa/Dar_es_Salaam';
const SECURE = process.env.COOKIE_SECURE === '1'; // set to 1 when served over HTTPS
const db = new DatabaseSync(process.env.DB_FILE || path.join(__dirname, 'data.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
 CREATE TABLE IF NOT EXISTS docs(col TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(col,id));
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, role TEXT NOT NULL, hash TEXT NOT NULL, active INTEGER DEFAULT 1, created INTEGER);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user TEXT NOT NULL, exp INTEGER NOT NULL);`);

// ---------- helpers ----------
const COLS = ['ord', 'sal', 'sup', 'cou', 'rep', 'aud']; // orders/stock, sales, suppliers, couriers, daily reports, audit
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: TZ });
const rid = () => crypto.randomBytes(8).toString('hex');
const list = c => db.prepare('SELECT id,data FROM docs WHERE col=?').all(c).map(r => ({ id: r.id, ...JSON.parse(r.data) }));
const get = (c, id) => { const r = db.prepare('SELECT data FROM docs WHERE col=? AND id=?').get(c, id); return r && { id, ...JSON.parse(r.data) }; };
const put = (c, id, d) => { const { id: _x, ...x } = d; db.prepare('INSERT INTO docs(col,id,data) VALUES(?,?,?) ON CONFLICT(col,id) DO UPDATE SET data=excluded.data').run(c, id, JSON.stringify(x)); };
const del = (c, id) => db.prepare('DELETE FROM docs WHERE col=? AND id=?').run(c, id);
const counted = s => s.status === 'active' || s.status === 'requested';
const soldOf = oid => list('sal').filter(s => s.orderId === oid && counted(s)).reduce((a, s) => a + s.units, 0);
const audit = (user, action) => put('aud', rid(), { user, action, ts: Date.now() });
class HttpErr extends Error { constructor(code, msg) { super(msg); this.code = code; } }

const hashPw = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const checkPw = (p, h) => { const [s, x] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(x, 'hex'), crypto.scryptSync(p, s, 64)); };
const tries = new Map();
const tooMany = k => { const r = (tries.get(k) || []).filter(t => t > Date.now() - 9e5); tries.set(k, r); return r.length >= 10; };
const failed = k => tries.get(k).push(Date.now());

function startSession(res, user) {
  const t = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(t, user, Date.now() + 12 * 3600e3);
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200${SECURE ? '; Secure' : ''}`);
}
function sessionUser(req) {
  const m = /(?:^|;\s*)sid=(\w+)/.exec(req.headers.cookie || ''); if (!m) return null;
  const s = db.prepare('SELECT user,exp FROM sessions WHERE token=?').get(m[1]);
  if (!s || s.exp < Date.now()) return null;
  return db.prepare('SELECT id,role,active FROM users WHERE id=?').get(s.user) || null;
}
const send = (res, c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
const readBody = req => new Promise((ok, no) => {
  let b = ''; req.on('data', c => { b += c; if (b.length > 3e6) { no(new HttpErr(413, 'Too large')); req.destroy(); } });
  req.on('end', () => { try { ok(b ? JSON.parse(b) : {}); } catch (e) { no(new HttpErr(400, 'Bad JSON')); } });
});
const whole = n => { n = Number(n); if (!Number.isInteger(n) || n < 1) throw new HttpErr(400, 'Enter whole units.'); return n; };

// ---------- API ----------
async function api(req, res, url) {
  const m = req.method, p = url.pathname.split('/').slice(2);
  const b = ['POST', 'PUT', 'PATCH'].includes(m) ? await readBody(req) : {};

  if (p[0] === 'me') {
    const u = sessionUser(req);
    return send(res, 200, { user: u && u.active ? { id: u.id, role: u.role } : null, needsSetup: !db.prepare('SELECT COUNT(*) c FROM users').get().c });
  }
  if (p[0] === 'setup' && m === 'POST') {            // first run: create the Manager
    if (db.prepare('SELECT COUNT(*) c FROM users').get().c) throw new HttpErr(403, 'Already set up');
    const id = String(b.u || '').trim().toLowerCase().replace(/\s/g, '');
    if (!id || String(b.p || '').length < 6) throw new HttpErr(400, 'Username required and password must be at least 6 characters.');
    db.prepare('INSERT INTO users VALUES(?,?,?,1,?)').run(id, 'manager', hashPw(b.p), Date.now());
    startSession(res, id); audit(id, 'Manager account created');
    return send(res, 200, { user: { id, role: 'manager' } });
  }
  if (p[0] === 'login' && m === 'POST') {
    const id = String(b.u || '').trim().toLowerCase(), k = req.socket.remoteAddress + '|' + id;
    if (tooMany(k)) throw new HttpErr(429, 'Too many attempts. Try again in 15 minutes.');
    const t = db.prepare('SELECT * FROM users WHERE id=?').get(id);
    if (!t || !checkPw(String(b.p || ''), t.hash)) { failed(k); throw new HttpErr(401, 'Wrong username or password.'); }
    if (!t.active) throw new HttpErr(403, 'Your account is disabled. Contact your Manager.');
    startSession(res, id); audit(id, 'Signed in');
    return send(res, 200, { user: { id, role: t.role } });
  }
  if (p[0] === 'logout') {
    const c = /(?:^|;\s*)sid=(\w+)/.exec(req.headers.cookie || ''); if (c) db.prepare('DELETE FROM sessions WHERE token=?').run(c[1]);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); return send(res, 200, {});
  }

  // ---- everything below needs a valid session
  const u = sessionUser(req);
  if (!u) throw new HttpErr(401, 'auth');
  if (!u.active) throw new HttpErr(401, 'disabled');
  const mgr = u.role === 'manager';

  if (p[0] === 'state' && m === 'GET') {
    const sal = list('sal');
    const ord = list('ord').map(o => ({ ...o, _sold: sal.filter(s => s.orderId === o.id && counted(s)).reduce((a, s) => a + s.units, 0) }));
    if (mgr) return send(res, 200, {
      today: today(), ord, sal, sup: list('sup'), cou: list('cou'), rep: list('rep'),
      aud: list('aud').sort((a, b) => b.ts - a.ts).slice(0, 500),
      usr: db.prepare('SELECT id,role,active,created FROM users').all().map(x => ({ ...x, active: !!x.active }))
    });
    // salespeople: no costs, suppliers, other people's sales or audit data
    return send(res, 200, {
      today: today(), sup: [], cou: [], aud: [], usr: [],
      ord: ord.filter(o => o.status === 'For Sale').map(o => ({ id: o.id, no: o.no, name: o.name, img: o.img, cat: o.cat, qty: o.qty, price: o.price, old: o.old, status: o.status, _sold: o._sold })),
      sal: sal.filter(s => s.user === u.id), rep: list('rep').filter(r => r.user === u.id)
    });
  }

  // ---- sales actions (salesperson)
  if (p[0] === 'sell' && m === 'POST') {
    const o = get('ord', b.orderId), n = whole(b.units);
    if (!o || o.status !== 'For Sale' || !o.price) throw new HttpErr(400, 'Item is not available for sale.');
    if (get('rep', u.id + '_' + today())) throw new HttpErr(400, "Today's report is already submitted.");
    const left = o.qty - soldOf(o.id); if (n > left) throw new HttpErr(400, 'Only ' + left + ' available.');
    const id = rid();
    put('sal', id, { orderId: o.id, no: o.no, name: o.name, units: n, price: o.price, user: u.id, date: today(), ts: Date.now(), status: 'active' });
    audit(u.id, `Sold ${n} × ${o.name} @ ${o.price}`); return send(res, 200, { id });
  }
  if (p[0] === 'sales' && p[2] === 'request' && m === 'POST') {
    const s = get('sal', p[1]);
    if (!s || s.user !== u.id || s.status !== 'active' || s.date !== today()) throw new HttpErr(400, 'This sale cannot be edited.');
    put('sal', s.id, { ...s, status: 'requested' }); audit(u.id, `Requested edit of sale ${s.name} (${s.units})`); return send(res, 200, {});
  }
  if (p[0] === 'sales' && p[2] === 'resubmit' && m === 'POST') {
    const s = get('sal', p[1]), n = whole(b.units);
    if (!s || s.user !== u.id || s.status !== 'rollback') throw new HttpErr(400, 'Nothing to resubmit.');
    const o = get('ord', s.orderId); if (!o || o.status !== 'For Sale' || !o.price) throw new HttpErr(400, 'Item is no longer for sale.');
    const left = o.qty - soldOf(o.id); if (n > left) throw new HttpErr(400, 'Only ' + left + ' available.');
    put('sal', s.id, { ...s, units: n, price: o.price, status: 'active' }); audit(u.id, `Resubmitted sale of ${s.name}: ${n} units`); return send(res, 200, {});
  }
  if (p[0] === 'report' && m === 'POST') {
    const d = today(), mine = list('sal').filter(s => s.user === u.id);
    if (mine.some(s => s.status === 'rollback')) throw new HttpErr(400, 'Resubmit your rolled-back sales first.');
    if (get('rep', u.id + '_' + d)) throw new HttpErr(400, 'Report already submitted.');
    const t = mine.filter(s => s.date === d && counted(s));
    put('rep', u.id + '_' + d, { user: u.id, date: d, sales: t.length, units: t.reduce((a, s) => a + s.units, 0), revenue: t.reduce((a, s) => a + s.units * s.price, 0), ts: Date.now() });
    audit(u.id, 'Submitted daily report'); return send(res, 200, {});
  }

  // ---- manager-only below
  if (!mgr) throw new HttpErr(403, 'Manager access required.');
  if (p[0] === 'audit' && m === 'POST') { audit(u.id, String(b.action || '').slice(0, 300)); return send(res, 200, {}); }

  if (p[0] === 'c' && COLS.includes(p[1])) {         // generic CRUD on business data
    const c = p[1], id = p[2];
    const check = d => { if (c === 'ord' && d.price != null && d.price !== '' && Number(d.price) < Number(d.unitCost)) throw new HttpErr(400, 'Selling price cannot be below production price.'); };
    if (m === 'POST' && !id) { check(b); const n = rid(); put(c, n, b); return send(res, 200, { id: n }); }
    if (m === 'PUT' && id) { check(b); put(c, id, b); return send(res, 200, { id }); }
    if (m === 'PATCH' && id) { const o = get(c, id); if (!o) throw new HttpErr(404, 'Not found'); const d = { ...o, ...b }; check(d); put(c, id, d); return send(res, 200, { id }); }
    if (m === 'DELETE' && id) { del(c, id); return send(res, 200, {}); }
  }

  if (p[0] === 'users') {                            // manage salespeople
    if (m === 'POST' && !p[1]) {
      const id = String(b.u || '').trim().toLowerCase().replace(/\s/g, '');
      if (!id || String(b.p || '').length < 6) throw new HttpErr(400, 'Username required; password min 6 characters.');
      if (db.prepare('SELECT 1 FROM users WHERE id=?').get(id)) throw new HttpErr(400, 'Username taken.');
      db.prepare('INSERT INTO users VALUES(?,?,?,1,?)').run(id, 'sales', hashPw(b.p), Date.now());
      audit(u.id, 'Registered salesperson ' + id); return send(res, 200, {});
    }
    const t = db.prepare('SELECT * FROM users WHERE id=?').get(p[1]);
    if (!t || t.role !== 'sales') throw new HttpErr(404, 'Salesperson not found.');
    const drop = () => db.prepare('DELETE FROM sessions WHERE user=?').run(t.id);
    if (p[2] === 'password' && m === 'POST') {
      if (String(b.p || '').length < 6) throw new HttpErr(400, 'Password too short.');
      db.prepare('UPDATE users SET hash=? WHERE id=?').run(hashPw(b.p), t.id); drop(); audit(u.id, 'Reset password for ' + t.id); return send(res, 200, {});
    }
    if (p[2] === 'active' && m === 'POST') {
      db.prepare('UPDATE users SET active=? WHERE id=?').run(b.active ? 1 : 0, t.id); if (!b.active) drop();
      audit(u.id, (b.active ? 'Enabled ' : 'Disabled ') + t.id); return send(res, 200, {});
    }
    if (m === 'DELETE') { db.prepare('DELETE FROM users WHERE id=?').run(t.id); drop(); audit(u.id, 'Deleted salesperson ' + t.id); return send(res, 200, {}); }
  }
  throw new HttpErr(404, 'Not found');
}

// ---------- static files + server ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.ico': 'image/x-icon' };
const PUB = path.join(__dirname, 'public');
http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    let f = path.normalize(path.join(PUB, url.pathname === '/' ? 'index.html' : url.pathname));
    if (!f.startsWith(PUB) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(PUB, 'index.html');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    fs.createReadStream(f).pipe(res);
  } catch (e) {
    if (e instanceof HttpErr) return send(res, e.code, { error: e.message });
    console.error(e); send(res, 500, { error: 'Server error' });
  }
}).listen(PORT, () => console.log(`XYZ Collection running on http://localhost:${PORT}`));
setInterval(() => db.prepare('DELETE FROM sessions WHERE exp<?').run(Date.now()), 3600e3).unref();