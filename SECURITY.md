# Keamanan `pos-api`

Dokumen ini merangkum temuan keamanan pada versi awal `worker.js` (arsitektur
CRUD generik path-based `/api/:table/:id`, lihat riwayat Git) dan perbaikan
yang diterapkan pada versi saat ini, ditulis dengan referensi langsung ke
pola yang sudah diterapkan di `piawai-api`.

## Temuan KRITIS pada versi sebelumnya (sudah diperbaiki)

1. **Password disimpan plaintext** (`users.password`) dan bisa dibaca lewat
   `GET /api/users?tenantId=...` oleh siapa pun yang tahu/menerka `tenantId`.
   Frontend bahkan mengambil SEMUA baris `users` sebuah tenant lalu
   mencocokkan password di JavaScript klien (`auth.js` versi lama).
   → **Diperbaiki:** password di-hash PBKDF2-SHA256 (salt per user,
   `users.passwordHash`), tabel `users` diblokir total dari `/api` generik,
   login/registrasi hanya lewat `POST /public?view=login|register` yang
   memverifikasi password di server dan tidak pernah mengembalikan hash.

2. **`tenantId` dipercaya dari klien** (query string `?tenantId=`, dan
   `body.tenantId` saat insert). Siapa pun yang mengganti nilai ini di
   DevTools/`fetch` langsung bisa membaca atau menulis data tenant lain
   (IDOR penuh) — komentar di kode lama bahkan mengakui ini secara eksplisit.
   → **Diperbaiki:** `tenantId` sekarang SELALU diturunkan dari token sesi
   HMAC-SHA256 yang diverifikasi server (`requireSession()`); parameter
   `tenantId` dari klien tidak lagi dibaca sama sekali untuk tabel scoped.

3. **Injeksi lewat NAMA KOLOM.** `INSERT/UPDATE` merakit daftar kolom
   langsung dari `Object.keys(body)`/`Object.keys(patch)` tanpa allowlist —
   klien bisa mengirim key JSON arbitrer yang lolos ke SQL mentah.
   → **Diperbaiki:** `WRITABLE_COLUMNS` per tabel + `pickColumns()`, apa pun
   di luar daftar dibuang diam-diam.

4. **Tidak ada autentikasi maupun otorisasi peran di backend.** Pembatasan
   peran (`requireLogin(['owner', ...])`) hanya ada di frontend
   (`pages/*.js`) — siapa pun yang memanggil Worker API langsung (tanpa
   lewat UI) bisa menulis ke tabel apa pun, termasuk `akun`/`jurnal`
   (data keuangan), tanpa peran apa pun.
   → **Diperbaiki:** `requireSession()` wajib untuk semua rute `/api`, dan
   `WRITE_ROLES` per tabel menolak operasi tulis dari peran yang tidak
   berwenang (mis. `kasir` tidak bisa menulis ke `akun`/`jurnal`).

5. **CORS `Access-Control-Allow-Origin: *`.** Siapa pun bisa memanggil API
   dari domain mana pun (walau isolasi tenant tetap gagal terlebih dulu di
   atas, ini memperluas permukaan serangan CSRF-like untuk sesi yang valid).
   → **Diperbaiki:** allowlist origin (`ALLOWED_ORIGINS`).

6. **Tidak ada rate limiting / captcha di alur login-registrasi**, sehingga
   brute-force kredensial atau spam pembuatan tenant tidak dicegah sama
   sekali di server.
   → **Diperbaiki:** rate limit per-IP & per-akun di tabel `rate_limit`,
   ditegakkan sebelum password dicocokkan; captcha matematika kustom
   (ditandatangani HMAC, diverifikasi server) wajib untuk login & registrasi.

## Keputusan desain yang disadari (bukan bug)

- **GET (baca) tidak dibatasi peran** di tabel scoped — semua peran dalam
  satu tenant (owner/kasir/gudang) boleh membaca tabel apa pun milik
  tenant tsb, karena Dashboard perlu membaca `transaksi`/`produk`/`lokasi`
  lintas peran. Yang dibatasi peran hanya operasi TULIS
  (lihat `WRITE_ROLES`).
- **Token sesi bersifat stateless** (HMAC, TTL 12 jam) — tidak bisa dicabut
  per-sesi sebelum kedaluwarsa, hanya lewat mengganti `SESSION_SECRET`
  (mencabut SEMUA sesi sekaligus). Untuk "paksa logout satu user", perlu
  tabel sesi tersendiri (`session`/`jti`) — belum diimplementasikan di sini.
- **`rate_limit` tidak dibersihkan otomatis.** Untuk produksi jangka
  panjang, tambahkan Cron Trigger yang menghapus baris lama (`windowStart`
  jauh di masa lalu dan `blockedUntil` sudah lewat) secara periodik.
- **Token sesi disimpan di `localStorage`** (bukan cookie `HttpOnly`),
  konsisten dengan `piawai-app`, karena frontend & backend ada di domain
  berbeda. Ini membuat sanitasi/escaping XSS di frontend jadi lapis
  pertahanan KRITIS, bukan opsional — lihat `pos-app-main/SECURITY.md`.
