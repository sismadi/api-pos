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
// [ECOMMERCE] Slug link publik toko, mis. https://pos.piawai.id/?toko/jaya
// — huruf kecil/angka/strip/underscore saja, supaya aman dipakai di URL.
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{1,49}$/;

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
  transaksi:         ['nomor', 'tipe', 'tanggal', 'lokasiId', 'kontakId', 'status', 'metodePembayaran', 'totalBayar', 'catatan', 'pembeliNama', 'pembeliTelepon', 'pembeliAlamat'],
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

// [ECOMMERCE] Validasi + jamin keunikan slug etalase publik. `excludeId`
// dilewatkan saat UPDATE supaya tenant boleh menyimpan ulang slug yang
// sama persis milik sendiri.
async function normalizeSlug(db, raw, excludeId) {
  const slug = String(raw ?? '').trim().toLowerCase();
  if (!SLUG_RE.test(slug)) {
    throw new HttpError(400, 'Slug toko harus 2-50 karakter: huruf kecil, angka, strip, atau underscore, diawali huruf/angka.');
  }
  const dupe = await db.prepare(`SELECT id FROM tenants WHERE slug = ? AND id != ?`).bind(slug, excludeId || '').first();
  if (dupe) throw new HttpError(409, 'Slug toko sudah dipakai toko lain, gunakan slug lain.');
  return slug;
}

/** Turunkan slug awal dari kodeToko saat tenant baru dibuat (register/superadmin),
 *  supaya link toko langsung tersedia tanpa pemilik harus mengisi dulu.
 *  Kalau bentrok (jarang, karena kodeToko sendiri unik), tambahkan sufiks acak. */
async function autoSlugFromKodeToko(db, kodeToko) {
  const base = kodeToko.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+/, '') || 'toko';
  let candidate = base.slice(0, 50);
  let n = 0;
  while (await db.prepare(`SELECT id FROM tenants WHERE slug = ?`).bind(candidate).first()) {
    n += 1;
    candidate = `${base}-${n}`.slice(0, 50);
  }
  return candidate;
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
    if (id) {
      // [ECOMMERCE] Pemilik toko boleh membaca data TENANT MILIK SENDIRI
      // (dipakai halaman "Toko Online" untuk menampilkan slug/deskripsi/
      // status tampil saat ini) — bukan cuma superadmin.
      if (!isSuper && id !== session.tid) throw new HttpError(403, 'Anda tidak memiliki izin melihat tenant ini.');
      const row = await db.prepare(`SELECT * FROM tenants WHERE id = ?`).bind(id).first();
      return json(row || null, row ? 200 : 404);
    }
    if (!isSuper) throw new HttpError(403, 'Hanya superadmin yang boleh melihat daftar tenant.');
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
    const slug = await autoSlugFromKodeToko(db, kodeToko);
    const tenant = { id: genId('tnt'), kodeToko, nama, alamat, telepon, status: 'aktif', slug, deskripsi: null, tampilOnline: 1, createdAt: now };
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
    const existing = await db.prepare(`SELECT * FROM tenants WHERE id = ?`).bind(id).first();
    if (!existing) throw new HttpError(404, 'Tenant tidak ditemukan.');
    const body = await request.json().catch(() => ({}));

    // [ECOMMERCE] Field pengaturan etalase publik (slug/deskripsi/tampilOnline)
    // boleh diubah oleh superadmin ATAU pemilik toko itu sendiri. Field
    // `status` (aktif/nonaktif tenant) TETAP khusus superadmin.
    const isOwnerSelf = session.role === 'owner' && session.tid === id;
    if (!isSuper && !isOwnerSelf) throw new HttpError(403, 'Anda tidak memiliki izin mengubah tenant ini.');

    const patch = {};
    if (isSuper && 'status' in body) {
      const status = body.status === 'nonaktif' ? 'nonaktif' : (body.status === 'aktif' ? 'aktif' : null);
      if (!status) throw new HttpError(400, "Field 'status' harus 'aktif' atau 'nonaktif'.");
      patch.status = status;
    }
    if ('slug' in body) patch.slug = await normalizeSlug(db, body.slug, id);
    if ('deskripsi' in body) patch.deskripsi = plainText(body.deskripsi, 300);
    if ('tampilOnline' in body) patch.tampilOnline = body.tampilOnline ? 1 : 0;

    if (!Object.keys(patch).length) throw new HttpError(400, 'Tidak ada field valid untuk diubah.');
    await updateRow(db, 'tenants', id, patch);
    return json({ ...existing, ...patch });
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

  // ------------------------------------------------------------
  // [ECOMMERCE] Etalase belanja publik — TIDAK butuh sesi/login. Dipakai
  // oleh pages/toko.js (pos.piawai.id/?toko dan /?toko/<slug>). Harga &
  // validitas produk SELALU diambil ulang dari server di sini (bukan
  // dari body yang dikirim klien) supaya pembeli anonim tidak bisa
  // memanipulasi harga/produk milik toko lain lewat request palsu.
  // ------------------------------------------------------------
  if (view === 'toko-list' && request.method === 'GET') {
    const { results } = await db.prepare(
      `SELECT id, slug, nama, alamat, telepon, deskripsi FROM tenants
       WHERE status = 'aktif' AND tampilOnline = 1 AND id != 'system'
       ORDER BY nama ASC`
    ).all();
    return json(results);
  }

  if (view === 'toko-detail' && request.method === 'GET') {
    const kunci = plainText(url.searchParams.get('toko'), 60).toLowerCase();
    if (!kunci) throw new HttpError(400, "Parameter 'toko' wajib diisi.");

    // Diterima baik lewat slug (link publik) maupun id tenant mentah
    // (kompatibel ke belakang kalau link lama sempat dibagikan).
    const tenant = await db.prepare(
      `SELECT id, slug, nama, alamat, telepon, deskripsi, status FROM tenants
       WHERE (slug = ? OR id = ?) AND id != 'system'`
    ).bind(kunci, kunci).first();
    if (!tenant || tenant.status !== 'aktif') throw new HttpError(404, 'Toko tidak ditemukan.');

    const { results: produk } = await db.prepare(
      `SELECT p.id, p.kode, p.nama, p.kategori, p.satuan, p.hargaJual,
              COALESCE((SELECT SUM(lp.stok) FROM lokasi_produk lp WHERE lp.produkId = p.id), 0) AS stok
       FROM produk p
       WHERE p.tenantId = ? AND p.aktif = 1
       ORDER BY p.nama ASC`
    ).bind(tenant.id).all();

    return json({
      tenant: { id: tenant.id, slug: tenant.slug, nama: tenant.nama, alamat: tenant.alamat, telepon: tenant.telepon, deskripsi: tenant.deskripsi },
      produk,
    });
  }

  if (view === 'toko-pesan' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const kunci = plainText(body.toko, 60).toLowerCase();
    if (!kunci) throw new HttpError(400, "Field 'toko' wajib diisi.");

    // Rate limit per-IP — pembeli anonim, jadi tidak ada akun untuk dikunci.
    const ipKey = `pesan:ip:${ip}`;
    await rateLimitCheck(db, ipKey, { max: 15, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 });

    const tenant = await db.prepare(`SELECT * FROM tenants WHERE (slug = ? OR id = ?) AND id != 'system'`).bind(kunci, kunci).first();
    if (!tenant || tenant.status !== 'aktif') { await rateLimitHit(db, ipKey); throw new HttpError(404, 'Toko tidak ditemukan.'); }

    const pembeliNama = plainText(body.pembeli?.nama, 120);
    const pembeliTelepon = plainText(body.pembeli?.telepon, 40);
    const pembeliAlamat = plainText(body.pembeli?.alamat, 240);
    if (!pembeliNama || !pembeliTelepon) { await rateLimitHit(db, ipKey); throw new HttpError(400, 'Nama & telepon pembeli wajib diisi.'); }

    const items = Array.isArray(body.items) ? body.items.slice(0, 50) : [];
    if (!items.length) { await rateLimitHit(db, ipKey); throw new HttpError(400, 'Keranjang kosong.'); }

    // [SECURITY] Harga & keberadaan produk diambil ULANG dari DB milik
    // tenant ini saja — qty/produkId dari klien cuma dipakai sebagai
    // "permintaan", tidak pernah dipercaya untuk harga.
    const { results: produkRows } = await db.prepare(
      `SELECT id, hargaJual FROM produk WHERE tenantId = ? AND aktif = 1`
    ).bind(tenant.id).all();
    const produkById = Object.fromEntries(produkRows.map(p => [p.id, p]));

    const lines = [];
    let total = 0;
    for (const it of items) {
      const p = produkById[it?.produkId];
      const qty = Number(it?.qty);
      if (!p || !Number.isFinite(qty) || qty <= 0) continue;
      const hargaSatuan = p.hargaJual || 0;
      const subtotal = qty * hargaSatuan;
      lines.push({ produkId: p.id, qty, hargaSatuan, subtotal });
      total += subtotal;
    }
    if (!lines.length) { await rateLimitHit(db, ipKey); throw new HttpError(400, 'Tidak ada produk valid pada pesanan.'); }

    const lokasiTujuan =
      await db.prepare(`SELECT id FROM lokasi WHERE tenantId = ? AND tipe = 'toko' ORDER BY createdAt ASC LIMIT 1`).bind(tenant.id).first() ||
      await db.prepare(`SELECT id FROM lokasi WHERE tenantId = ? ORDER BY createdAt ASC LIMIT 1`).bind(tenant.id).first();
    if (!lokasiTujuan) { await rateLimitHit(db, ipKey); throw new HttpError(400, 'Toko ini belum siap menerima pesanan online (belum ada lokasi).'); }

    const now = new Date().toISOString();
    const trx = {
      id: genId('transaksi'), tenantId: tenant.id,
      nomor: 'ON-' + Date.now().toString(36).toUpperCase(),
      tipe: 'jual', tanggal: now.slice(0, 10), lokasiId: lokasiTujuan.id, kontakId: null,
      status: 'draft', metodePembayaran: 'tunai', totalBayar: total,
      catatan: 'Pesanan dari etalase toko online — menunggu konfirmasi.',
      sumber: 'online', pembeliNama, pembeliTelepon, pembeliAlamat,
      createdAt: now,
    };
    await insertRow(db, 'transaksi', trx);
    for (const l of lines) {
      await insertRow(db, 'transaksi_produk', { id: genId('tp'), tenantId: tenant.id, transaksiId: trx.id, ...l });
    }

    await rateLimitReset(db, ipKey);
    return json({ id: trx.id, nomor: trx.nomor, total }, 201);
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
    const slug = await autoSlugFromKodeToko(db, kodeToko);
    const tenant = { id: genId('tnt'), kodeToko, nama: namaToko, alamat, telepon, status: 'aktif', slug, deskripsi: null, tampilOnline: 1, createdAt: now };
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
