// ============================================================
// worker.js — API BACKEND POS MULTI-TENANT (Cloudflare Worker + D1)
// VERSI TER-HARDENING — ditulis ulang dengan referensi pola keamanan
// dari `piawai-api` (lihat SECURITY.md untuk daftar temuan & perbaikan).
// ============================================================
// Ringkas perubahan keamanan dibanding versi sebelumnya:
//
//  1. Password TIDAK PERNAH keluar dari server. Tabel `users` diblokir
//     total dari CRUD generik /api. Satu-satunya jalan autentikasi
//     adalah POST /public?view=login|register.
//  2. Password disimpan sebagai hash PBKDF2-SHA256 (salt per-user,
//     100.000 iterasi — batas maksimum WebCrypto Workers) — kolom
//     `users.passwordHash`, bukan `password` plaintext.
//  3. Otorisasi TIDAK lagi memercayai `tenantId`/`role` dari klien.
//     Keduanya diturunkan dari token sesi HMAC-SHA256 yang diverifikasi
//     di server (header `Authorization: Bearer <token>`). Parameter
//     `tenantId` di query string diabaikan sepenuhnya untuk tabel scoped.
//  4. Captcha matematika kustom diverifikasi di server sebelum
//     login/registrasi diproses — soal + jawaban ditandatangani HMAC.
//  5. Rate limiting nyata di D1 (tabel `rate_limit`): per-IP dan
//     per-akun untuk login/registrasi, per-IP untuk percobaan captcha.
//  6. Nama kolom di INSERT/UPDATE di-allowlist per tabel
//     (WRITABLE_COLUMNS). Versi lama merakit
//     `INSERT INTO t (${Object.keys(body)})` dari body klien apa
//     adanya — itu injeksi SQL lewat nama kolom, bukan cuma nilai.
//  7. CORS tidak lagi `*`: hanya origin yang terdaftar (ALLOWED_ORIGINS).
//  8. Otorisasi PERAN per tabel untuk operasi tulis (POST/PATCH/DELETE) —
//     mis. hanya 'owner' yang boleh menulis ke `akun`/`jurnal`/
//     `jurnal_detail` (data keuangan), walau sebelumnya ini cuma
//     ditegakkan di frontend (requireLogin([...]) di pages/*.js) dan
//     bisa dilewati siapa pun yang memanggil API langsung.
//
// Secret/variable yang WAJIB di-set (lihat README.md):
//   wrangler secret put SESSION_SECRET
//   (opsional) vars ALLOWED_ORIGINS = "https://pos.piawai.id"
// ============================================================

// ------------------------------------------------------------
// Konfigurasi
// ------------------------------------------------------------
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;      // 12 jam
// Runtime Cloudflare Workers (WebCrypto) MEMBATASI PBKDF2 maksimal
// 100.000 iterasi (di atas itu subtle.deriveBits melempar
// NotSupportedError) — batas maksimal yang didukung dipakai di sini.
const PBKDF2_ITERATIONS = 100_000;
const KODE_TOKO_RE = /^[A-Z0-9][A-Z0-9_-]{1,29}$/;
const USERNAME_RE = /^[A-Za-z0-9._-]{3,40}$/;

const DEFAULT_ORIGINS = [
  'https://pos.piawai.id',
  'https://www.pos.piawai.id',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
];

// Tabel yang TIDAK BOLEH disentuh lewat CRUD generik /api sama sekali.
// `users` memuat kredensial — satu-satunya jalan masuk/keluar adalah
// endpoint /public (login/register) atau alur khusus superadmin di
// handleTenantsTable() di bawah.
const BLOCKED_TABLES = new Set(['users']);

// Tabel yang di-scope per tenant — WAJIB kolom tenantId, dan tenantId
// SELALU diturunkan dari token sesi (session.tid), bukan dari klien.
const SCOPED_TABLES = new Set([
  'produk', 'lokasi', 'lokasi_produk', 'kontak',
  'distribusi', 'distribusi_produk',
  'transaksi', 'transaksi_produk',
  'payment',
  'akun', 'jurnal', 'jurnal_detail',
]);

// Kolom yang boleh ditulis klien, per tabel. Apa pun di luar daftar ini
// dibuang diam-diam — termasuk `id`, `tenantId`, yang selalu ditentukan
// server (lihat pickColumns()).
const WRITABLE_COLUMNS = {
  produk:            ['kode', 'nama', 'kategori', 'satuan', 'hargaBeli', 'hargaJual', 'aktif'],
  lokasi:            ['nama', 'tipe', 'alamat'],
  lokasi_produk:     ['lokasiId', 'produkId', 'stok', 'stokMinimum'],
  kontak:            ['nama', 'tipe', 'telepon', 'alamat', 'email'],
  distribusi:        ['nomor', 'tipe', 'tanggal', 'lokasiId', 'kontakId', 'status', 'catatan'],
  distribusi_produk: ['distribusiId', 'produkId', 'qty', 'hargaSatuan'],
  transaksi:         ['nomor', 'tipe', 'tanggal', 'lokasiId', 'kontakId', 'status', 'metodePembayaran', 'totalBayar', 'catatan'],
  transaksi_produk:  ['transaksiId', 'produkId', 'qty', 'hargaSatuan', 'subtotal'],
  payment:           ['transaksiId', 'metode', 'referensi', 'qrString', 'jumlah', 'status', 'paidAt'],
  akun:              ['kode', 'nama', 'tipe', 'saldoNormal', 'saldoAwal', 'aktif'],
  jurnal:            ['nomor', 'tanggal', 'sumber', 'referensiId', 'keterangan', 'status'],
  jurnal_detail:     ['jurnalId', 'akunId', 'debit', 'kredit', 'keterangan'],
};

// [SECURITY / TAMBAHAN #8] Peran yang boleh MENULIS (POST/PATCH/DELETE)
// ke tiap tabel scoped — dicocokkan dari role di TOKEN SESI, bukan dari
// klaim klien. Dulu ini hanya ditegakkan lewat requireLogin([...]) di
// frontend (pages/*.js) — bisa dilewati siapa pun yang memanggil /api
// langsung. GET (baca) sengaja TIDAK dibatasi peran di sini — semua
// peran dalam satu tenant boleh membaca tabel apa pun tenant tsb
// (dashboard perlu membaca transaksi/produk/lokasi lintas peran), yang
// dibatasi cuma TULIS ke data sensitif (keuangan, master data).
const WRITE_ROLES = {
  produk:            ['owner', 'gudang'],
  lokasi:            ['owner', 'gudang'],
  lokasi_produk:     ['owner', 'gudang'],
  kontak:            ['owner', 'kasir', 'gudang'],
  distribusi:        ['owner', 'gudang'],
  distribusi_produk: ['owner', 'gudang'],
  transaksi:         ['owner', 'kasir'],
  transaksi_produk:  ['owner', 'kasir'],
  payment:           ['owner', 'kasir'],
  akun:              ['owner'],
  jurnal:            ['owner'],
  jurnal_detail:     ['owner'],
};

function genId(table) {
  return table + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) : DEFAULT_ORIGINS);
  const allowOrigin = allowed.includes(origin) ? origin : allowed[0];
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
}

// ------------------------------------------------------------
// Encoding & waktu-konstan
// ------------------------------------------------------------
function b64urlEncode(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ------------------------------------------------------------
// Password hashing — PBKDF2-SHA256, salt 16 byte per user.
// Format tersimpan: "pbkdf2:<iterasi>:<saltB64url>:<hashB64url>"
// ------------------------------------------------------------
async function pbkdf2(password, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
  return new Uint8Array(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2:${PBKDF2_ITERATIONS}:${b64urlEncode(salt)}:${b64urlEncode(hash)}`;
}
async function verifyPassword(password, stored) {
  // [SECURITY] Selalu jalankan PBKDF2 penuh walau format `stored` rusak/
  // kosong (mis. user tidak ditemukan, lihat handlePublicLogin) — supaya
  // waktu respons tidak membocorkan "username ada tapi hash rusak" vs
  // "username tidak ada". Dummy salt tetap 100.000 iterasi juga.
  const parts = String(stored || '').split(':');
  const dummySalt = crypto.getRandomValues(new Uint8Array(16));
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') {
    await pbkdf2(password, dummySalt, PBKDF2_ITERATIONS);
    return false;
  }
  const [, iterStr, saltB64, hashB64] = parts;
  const iterations = parseInt(iterStr, 10) || PBKDF2_ITERATIONS;
  const salt = b64urlDecode(saltB64);
  const computed = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(b64urlEncode(computed), hashB64);
}

// ------------------------------------------------------------
// Token bertanda tangan HMAC-SHA256 — dipakai untuk sesi login DAN
// captcha ("typ" beda supaya satu tidak bisa dipakai sebagai yang lain).
// Fail-closed: kalau SESSION_SECRET belum di-set / terlalu pendek,
// semua operasi yang butuh token DITOLAK (bukan diam-diam memakai
// secret lemah bawaan).
// ------------------------------------------------------------
async function hmacKey(env) {
  const secret = env.SESSION_SECRET;
  if (!secret || secret.length < 16) {
    throw new HttpError(500, 'Server belum dikonfigurasi dengan benar (SESSION_SECRET kosong/terlalu pendek).');
  }
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signToken(env, typ, payload, ttlMs) {
  const key = await hmacKey(env);
  const body = { typ, iat: Date.now(), exp: Date.now() + ttlMs, ...payload };
  const bodyB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(body)));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bodyB64));
  return `${bodyB64}.${b64urlEncode(new Uint8Array(sig))}`;
}

async function verifyToken(env, typ, token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [bodyB64, sigB64] = token.split('.');
  const key = await hmacKey(env);
  const expected = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bodyB64));
  if (!timingSafeEqual(b64urlEncode(new Uint8Array(expected)), sigB64)) return null;
  let body;
  try { body = JSON.parse(new TextDecoder().decode(b64urlDecode(bodyB64))); } catch (e) { return null; }
  if (body.typ !== typ) return null;
  if (typeof body.exp === 'number' && Date.now() > body.exp) return null;
  return body;
}

async function signSession(env, payload) {
  return signToken(env, 'session', payload, SESSION_TTL_MS);
}
async function verifySession(env, token) {
  return verifyToken(env, 'session', token);
}

/** Ambil & verifikasi sesi dari header Authorization. Melempar 401 kalau
 *  tidak ada/invalid — dipakai oleh SEMUA rute /api (lihat handleApi). */
async function requireSession(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const session = token ? await verifySession(env, token) : null;
  if (!session) throw new HttpError(401, 'Sesi tidak valid atau sudah berakhir, silakan masuk kembali.');
  return session; // { typ, iat, exp, uid, tid, role, username }
}

// ------------------------------------------------------------
// [SECURITY] Captcha matematika kustom — soal & jawaban ditandatangani
// HMAC (typ:'captcha'), diverifikasi ulang di server sebelum
// login/registrasi diproses. Menggantikan widget pihak ketiga: tanpa
// dependensi eksternal, tanpa secret tambahan (reuse SESSION_SECRET).
// ------------------------------------------------------------
async function generateMathCaptcha(env) {
  const a = 1 + Math.floor(Math.random() * 9);
  const b = 1 + Math.floor(Math.random() * 9);
  const challenge = `${a} + ${b} = ?`;
  const token = await signToken(env, 'captcha', { answer: a + b }, 5 * 60 * 1000);
  return { challenge, token };
}
async function verifyMathCaptcha(env, db, token, answer, ip) {
  const key = `captcha:ip:${ip}`;
  await rateLimitCheck(db, key, { max: 10, windowMs: 15 * 60 * 1000, blockMs: 15 * 60 * 1000 });

  const body = await verifyToken(env, 'captcha', token);
  const correct = body && Number(answer) === Number(body.answer);

  if (!correct) {
    await rateLimitHit(db, key);
    throw new HttpError(400, 'Jawaban captcha salah atau soal sudah kedaluwarsa. Muat ulang soal dan coba lagi.');
  }
}

// ------------------------------------------------------------
// Rate limiting nyata di D1 (tabel `rate_limit`). Dipakai per-IP dan
// per-akun; lockout ditegakkan SEBELUM password dicocokkan, jadi bot
// yang memanggil API langsung tetap kena.
// ------------------------------------------------------------
async function rateLimitCheck(db, key, { max, windowMs, blockMs }) {
  const now = Date.now();
  const row = await db.prepare(`SELECT * FROM rate_limit WHERE key = ?`).bind(key).first();
  if (row && row.blockedUntil > now) {
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.blockedUntil - now) / 1000)} detik.`);
  }
  if (!row || (now - row.windowStart) > windowMs) {
    await db.prepare(
      `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 0, ?, 0)
       ON CONFLICT(key) DO UPDATE SET count = 0, windowStart = ?, blockedUntil = 0`
    ).bind(key, now, now).run();
    return;
  }
  if (row.count >= max) {
    const until = now + blockMs;
    await db.prepare(`UPDATE rate_limit SET blockedUntil = ?, count = 0, windowStart = ? WHERE key = ?`)
      .bind(until, now, key).run();
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil(blockMs / 1000)} detik.`);
  }
}
async function rateLimitHit(db, key) {
  const now = Date.now();
  await db.prepare(
    `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 1, ?, 0)
     ON CONFLICT(key) DO UPDATE SET count = count + 1`
  ).bind(key, now).run();
}
async function rateLimitReset(db, key) {
  await db.prepare(`DELETE FROM rate_limit WHERE key = ?`).bind(key).run().catch(() => {});
}

// ------------------------------------------------------------
// Allowlist kolom tulis — buang diam-diam apa pun di luar daftar.
// ------------------------------------------------------------
function pickColumns(body, allowed) {
  const out = {};
  for (const k of allowed) if (k in body) out[k] = body[k];
  return out;
}

function plainText(value, max) {
  return String(value ?? '').trim().slice(0, max);
}

async function insertRow(db, table, record) {
  const cols = Object.keys(record);
  await db.prepare(`INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`)
    .bind(...cols.map(c => record[c])).run();
}
async function updateRow(db, table, id, patch) {
  const cols = Object.keys(patch);
  if (!cols.length) return;
  await db.prepare(`UPDATE ${table} SET ${cols.map(c => `${c} = ?`).join(', ')} WHERE id = ?`)
    .bind(...cols.map(c => patch[c]), id).run();
}

// ============================================================
// /api — CRUD generik untuk tabel scoped-per-tenant (& `tenants`,
// ditangani terpisah di handleTenantsTable karena butuh alur khusus
// pembuatan tenant+owner).
// ============================================================
async function handleApi(request, env) {
  const session = await requireSession(request, env);
  const url = new URL(request.url);
  const table = url.searchParams.get('table');
  const id = url.searchParams.get('id');
  const db = env.DB;

  if (!table) throw new HttpError(400, "Query 'table' wajib diisi.");
  if (BLOCKED_TABLES.has(table)) {
    throw new HttpError(403, `Tabel '${table}' tidak dapat diakses lewat /api. Gunakan endpoint khusus.`);
  }
  if (table === 'tenants') return handleTenantsTable(request, env, id, session);
  if (!SCOPED_TABLES.has(table)) throw new HttpError(400, `Tabel '${table}' tidak dikenal.`);

  const tenantId = session.tid;
  const method = request.method;

  // Operasi TULIS butuh peran yang sesuai (lihat WRITE_ROLES) — dicek
  // dari token sesi, bukan dari apa pun yang dikirim klien.
  if (method !== 'GET') {
    const allowedRoles = WRITE_ROLES[table] || ['owner'];
    if (!allowedRoles.includes(session.role)) {
      throw new HttpError(403, 'Peran akun Anda tidak memiliki izin untuk mengubah data ini.');
    }
  }

  if (method === 'GET') {
    if (id) {
      const row = await db.prepare(`SELECT * FROM ${table} WHERE id = ? AND tenantId = ?`).bind(id, tenantId).first();
      return json(row || null, row ? 200 : 404);
    }
    const { results } = await db.prepare(`SELECT * FROM ${table} WHERE tenantId = ?`).bind(tenantId).all();
    return json(results);
  }

  const body = (method === 'POST' || method === 'PATCH') ? await request.json().catch(() => ({})) : {};

  if (method === 'POST' && !id) {
    const data = pickColumns(body, WRITABLE_COLUMNS[table] || []);
    const record = { id: genId(table), tenantId, ...data };
    await insertRow(db, table, record);
    return json(record, 201);
  }

  if (method === 'PATCH' && id) {
    const existing = await db.prepare(`SELECT * FROM ${table} WHERE id = ? AND tenantId = ?`).bind(id, tenantId).first();
    if (!existing) throw new HttpError(404, 'Data tidak ditemukan.');
    const data = pickColumns(body, WRITABLE_COLUMNS[table] || []);
    await updateRow(db, table, id, data);
    return json({ ...existing, ...data });
  }

  if (method === 'DELETE' && id) {
    const existing = await db.prepare(`SELECT * FROM ${table} WHERE id = ? AND tenantId = ?`).bind(id, tenantId).first();
    if (!existing) return json({ ok: true }); // idempotent
    await db.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
    return json({ ok: true });
  }

  throw new HttpError(405, 'Method not allowed.');
}

// ============================================================
// Tabel `tenants` — global (tidak di-scope), tapi butuh alur khusus:
//   GET    -> hanya superadmin (satu-satunya konsumen adalah pages/tenant.js).
//   POST   -> HANYA superadmin, membuat tenant BARU + akun owner-nya
//             sekaligus (password di-hash di sini, tidak pernah lewat
//             pickColumns biasa). Lihat juga /public?view=register
//             untuk pendaftaran mandiri (self-service, tanpa login).
//   PATCH  -> HANYA superadmin, HANYA kolom `status` (aktifkan/nonaktifkan).
//   DELETE -> tidak didukung (tenant tidak pernah dihapus keras).
// ============================================================
async function handleTenantsTable(request, env, id, session) {
  const db = env.DB;
  const method = request.method;
  const isSuper = session.role === 'superadmin';

  if (method === 'GET') {
    if (!isSuper) throw new HttpError(403, 'Hanya superadmin yang boleh melihat daftar tenant.');
    if (id) {
      const row = await db.prepare(`SELECT * FROM tenants WHERE id = ?`).bind(id).first();
      return json(row || null, row ? 200 : 404);
    }
    const { results } = await db.prepare(`SELECT * FROM tenants`).all();
    return json(results);
  }

  if (method === 'POST' && !id) {
    if (!isSuper) throw new HttpError(403, 'Hanya superadmin yang boleh membuat tenant baru.');
    const body = await request.json().catch(() => ({}));

    const kodeToko = plainText(body.kodeToko, 30).toUpperCase();
    const nama = plainText(body.nama ?? body.namaToko, 80);
    const alamat = plainText(body.alamat, 200);
    const telepon = plainText(body.telepon, 30);
    const ownerUsername = plainText(body.ownerUsername ?? body.username, 40);
    const ownerPassword = String(body.ownerPassword ?? body.password ?? '');
    const ownerName = plainText(body.ownerName, 80);

    if (!KODE_TOKO_RE.test(kodeToko)) throw new HttpError(400, 'Kode Toko harus 2-30 karakter: huruf besar, angka, atau tanda strip/underscore.');
    if (!nama) throw new HttpError(400, 'Nama toko wajib diisi.');
    if (!USERNAME_RE.test(ownerUsername)) throw new HttpError(400, 'Username pemilik harus 3-40 karakter (huruf, angka, titik, strip, underscore).');
    if (ownerPassword.length < 8) throw new HttpError(400, 'Password pemilik minimal 8 karakter.');
    if (!ownerName) throw new HttpError(400, 'Nama pemilik wajib diisi.');

    const dupe = await db.prepare(`SELECT id FROM tenants WHERE kodeToko = ?`).bind(kodeToko).first();
    if (dupe) throw new HttpError(409, 'Kode Toko sudah dipakai, gunakan kode lain.');

    const now = new Date().toISOString();
    const tenant = { id: genId('tnt'), kodeToko, nama, alamat, telepon, status: 'aktif', createdAt: now };
    await insertRow(db, 'tenants', tenant);

    const passwordHash = await hashPassword(ownerPassword);
    await insertRow(db, 'users', {
      id: genId('usr'), tenantId: tenant.id, username: ownerUsername, passwordHash,
      name: ownerName, role: 'owner', createdAt: now,
    });
    await insertRow(db, 'lokasi', {
      id: genId('lokasi'), tenantId: tenant.id, nama: 'Toko Utama', tipe: 'toko', alamat, createdAt: now,
    });

    return json(tenant, 201);
  }

  if (method === 'PATCH' && id) {
    if (!isSuper) throw new HttpError(403, 'Hanya superadmin yang boleh mengubah status tenant.');
    const existing = await db.prepare(`SELECT * FROM tenants WHERE id = ?`).bind(id).first();
    if (!existing) throw new HttpError(404, 'Tenant tidak ditemukan.');
    const body = await request.json().catch(() => ({}));
    const status = body.status === 'nonaktif' ? 'nonaktif' : (body.status === 'aktif' ? 'aktif' : null);
    if (!status) throw new HttpError(400, "Field 'status' harus 'aktif' atau 'nonaktif'.");
    await updateRow(db, 'tenants', id, { status });
    return json({ ...existing, status });
  }

  throw new HttpError(405, 'Method not allowed untuk tabel tenants.');
}

// ============================================================
// /public — login, registrasi mandiri, captcha. Tidak butuh sesi
// (ini justru yang MEMBUAT sesi), tapi dilindungi captcha + rate limit.
// ============================================================
async function handlePublic(request, env) {
  const url = new URL(request.url);
  const view = url.searchParams.get('view');
  const db = env.DB;
  const ip = clientIp(request);

  if (view === 'captcha' && request.method === 'GET') {
    return json(await generateMathCaptcha(env));
  }

  if (view === 'login' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);

    const kodeToko = plainText(body.kodeToko, 30).toUpperCase();
    const username = plainText(body.username, 40);
    const password = String(body.password || '');
    if (!kodeToko || !username || !password) throw new HttpError(400, 'Kode Toko, username, dan password wajib diisi.');

    const ipKey = `login:ip:${ip}`;
    const acctKey = `login:acct:${kodeToko}:${username.toLowerCase()}`;
    await rateLimitCheck(db, ipKey, { max: 20, windowMs: 15 * 60 * 1000, blockMs: 15 * 60 * 1000 });
    await rateLimitCheck(db, acctKey, { max: 5, windowMs: 15 * 60 * 1000, blockMs: 15 * 60 * 1000 });

    const tenant = await db.prepare(`SELECT * FROM tenants WHERE kodeToko = ?`).bind(kodeToko).first();
    const user = tenant ? await db.prepare(`SELECT * FROM users WHERE tenantId = ? AND username = ?`).bind(tenant.id, username).first() : null;

    // [SECURITY] Verifikasi password TETAP dijalankan terhadap hash dummy
    // walau tenant/user tidak ada, supaya waktu respons tidak membocorkan
    // mana yang salah (enumerasi tenant/username lewat timing).
    const ok = await verifyPassword(password, user?.passwordHash);
    if (!tenant || !user || !ok) {
      await rateLimitHit(db, ipKey); await rateLimitHit(db, acctKey);
      throw new HttpError(401, 'Kode Toko, username, atau password salah.');
    }
    if (tenant.status === 'nonaktif' && tenant.id !== 'system') {
      throw new HttpError(403, 'Akun toko ini sedang dinonaktifkan. Hubungi superadmin.');
    }

    await rateLimitReset(db, ipKey); await rateLimitReset(db, acctKey);

    const token = await signSession(env, { uid: user.id, tid: tenant.id, role: user.role, username: user.username });
    return json({ token, user: sessionUserView(user, tenant) });
  }

  if (view === 'register' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);

    const regKey = `register:ip:${ip}`;
    await rateLimitCheck(db, regKey, { max: 5, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 });

    const kodeToko = plainText(body.kodeToko, 30).toUpperCase();
    const namaToko = plainText(body.namaToko, 80);
    const alamat = plainText(body.alamat, 200);
    const telepon = plainText(body.telepon, 30);
    const ownerName = plainText(body.ownerName, 80);
    const username = plainText(body.username, 40);
    const password = String(body.password || '');

    if (!KODE_TOKO_RE.test(kodeToko)) throw new HttpError(400, 'Kode Toko harus 2-30 karakter: huruf besar, angka, atau tanda strip/underscore.');
    if (kodeToko === 'SUPERADMIN') throw new HttpError(400, 'Kode Toko tersebut tidak dapat dipakai.');
    if (!namaToko) throw new HttpError(400, 'Nama toko wajib diisi.');
    if (!ownerName) throw new HttpError(400, 'Nama pemilik wajib diisi.');
    if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Username harus 3-40 karakter (huruf, angka, titik, strip, underscore).');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');

    const dupe = await db.prepare(`SELECT id FROM tenants WHERE kodeToko = ?`).bind(kodeToko).first();
    if (dupe) { await rateLimitHit(db, regKey); throw new HttpError(409, 'Kode Toko sudah dipakai, gunakan kode lain.'); }

    const now = new Date().toISOString();
    const tenant = { id: genId('tnt'), kodeToko, nama: namaToko, alamat, telepon, status: 'aktif', createdAt: now };
    await insertRow(db, 'tenants', tenant);

    const passwordHash = await hashPassword(password);
    const user = { id: genId('usr'), tenantId: tenant.id, username, passwordHash, name: ownerName, role: 'owner', createdAt: now };
    await insertRow(db, 'users', user);

    await insertRow(db, 'lokasi', { id: genId('lokasi'), tenantId: tenant.id, nama: 'Toko Utama', tipe: 'toko', alamat, createdAt: now });

    await rateLimitReset(db, regKey);

    const token = await signSession(env, { uid: user.id, tid: tenant.id, role: user.role, username: user.username });
    return json({ token, user: sessionUserView(user, tenant) }, 201);
  }

  throw new HttpError(404, 'Rute /public tidak dikenal.');
}

/** Bentuk data pengguna yang boleh dikirim ke klien — TIDAK PERNAH
 *  menyertakan passwordHash. */
function sessionUserView(user, tenant) {
  return {
    tenantId: tenant.id, tenantNama: tenant.nama,
    userId: user.id, username: user.username, name: user.name, role: user.role,
  };
}

// ============================================================
// Entry point
// ============================================================
export default {
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    if (request.method === 'OPTIONS') return new Response(null, { headers });

    try {
      const url = new URL(request.url);
      let res;
      if (url.pathname === '/api') res = await handleApi(request, env);
      else if (url.pathname === '/public') res = await handlePublic(request, env);
      else res = json({ error: 'Not found' }, 404);
      return withHeaders(res, headers);
    } catch (err) {
      if (err instanceof HttpError) return withHeaders(json({ error: err.message }, err.status), headers);
      console.error(err);
      return withHeaders(json({ error: 'Terjadi kesalahan di server.' }, 500), headers);
    }
  },
};

function withHeaders(res, headers) {
  const merged = new Headers(res.headers);
  for (const [k, v] of Object.entries(headers)) merged.set(k, v);
  return new Response(res.body, { status: res.status, headers: merged });
}

// Ekspor internal untuk tools/hash-password.mjs (& test suite bila ada).
export const __test__ = { hashPassword, verifyPassword, signSession, verifySession, pbkdf2 };
