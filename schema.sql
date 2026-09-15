-- ============================================================
-- schema.sql — Skema Cloudflare D1 untuk Aplikasi POS Multi-Tenant
-- ============================================================
-- Semua tabel operasional (selain `tenants`) punya kolom `tenantId`
-- yang WAJIB diisi — inilah yang membuat data 1 toko (tenant) tidak
-- pernah bercampur dengan toko lain. Penegakannya dilakukan di
-- worker.js (lapisan API), bukan di sini — lihat catatan keamanan
-- di README.md.
--
-- Entitas sesuai permintaan konversi:
--   tenants              -> daftar toko/pelanggan aplikasi (multi-tenant)
--   users                -> akun login per-tenant (+ 1 tenant khusus "system" utk superadmin)
--   produk               -> master barang
--   lokasi               -> toko/gudang milik satu tenant
--   lokasi_produk        -> stok per produk per lokasi
--   kontak               -> distributor/supplier/customer/dll
--   distribusi + distribusi_produk -> mutasi stok masuk/keluar antar lokasi/supplier
--   transaksi + transaksi_produk   -> transaksi jual/beli
--   payment              -> catatan pembayaran (tunai/QRIS) per transaksi
-- ============================================================

DROP TABLE IF EXISTS jurnal_detail;
DROP TABLE IF EXISTS jurnal;
DROP TABLE IF EXISTS akun;
DROP TABLE IF EXISTS payment;
DROP TABLE IF EXISTS transaksi_produk;
DROP TABLE IF EXISTS transaksi;
DROP TABLE IF EXISTS distribusi_produk;
DROP TABLE IF EXISTS distribusi;
DROP TABLE IF EXISTS kontak;
DROP TABLE IF EXISTS lokasi_produk;
DROP TABLE IF EXISTS lokasi;
DROP TABLE IF EXISTS produk;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

-- ---------------------------------------------------------------
-- tenants — TIDAK di-scope (memang tabel global). kodeToko adalah
-- "kunci masuk" yang diketik pengguna saat login (lihat auth.js).
-- ---------------------------------------------------------------
CREATE TABLE tenants (
  id        TEXT PRIMARY KEY,
  kodeToko  TEXT UNIQUE NOT NULL,
  nama      TEXT NOT NULL,
  alamat    TEXT,
  telepon   TEXT,
  status    TEXT NOT NULL DEFAULT 'aktif',   -- aktif | nonaktif
  createdAt TEXT NOT NULL
);

CREATE TABLE users (
  id        TEXT PRIMARY KEY,
  tenantId  TEXT NOT NULL,
  username  TEXT NOT NULL,
  password  TEXT NOT NULL,                    -- catatan: plaintext, lihat README (bukan untuk produksi)
  name      TEXT NOT NULL,
  role      TEXT NOT NULL DEFAULT 'kasir',    -- superadmin | owner | kasir | gudang
  createdAt TEXT NOT NULL
);
CREATE INDEX idx_users_tenant ON users(tenantId);

CREATE TABLE produk (
  id        TEXT PRIMARY KEY,
  tenantId  TEXT NOT NULL,
  kode      TEXT,
  nama      TEXT NOT NULL,
  kategori  TEXT,
  satuan    TEXT DEFAULT 'pcs',
  hargaBeli REAL DEFAULT 0,
  hargaJual REAL DEFAULT 0,
  aktif     INTEGER DEFAULT 1,
  createdAt TEXT NOT NULL
);
CREATE INDEX idx_produk_tenant ON produk(tenantId);

CREATE TABLE lokasi (
  id        TEXT PRIMARY KEY,
  tenantId  TEXT NOT NULL,
  nama      TEXT NOT NULL,
  tipe      TEXT NOT NULL DEFAULT 'toko',     -- toko | gudang
  alamat    TEXT,
  createdAt TEXT NOT NULL
);
CREATE INDEX idx_lokasi_tenant ON lokasi(tenantId);

CREATE TABLE lokasi_produk (
  id          TEXT PRIMARY KEY,
  tenantId    TEXT NOT NULL,
  lokasiId    TEXT NOT NULL,
  produkId    TEXT NOT NULL,
  stok        REAL NOT NULL DEFAULT 0,
  stokMinimum REAL DEFAULT 0
);
CREATE INDEX idx_lp_tenant ON lokasi_produk(tenantId);
CREATE INDEX idx_lp_lokasi ON lokasi_produk(lokasiId);
CREATE INDEX idx_lp_produk ON lokasi_produk(produkId);

CREATE TABLE kontak (
  id        TEXT PRIMARY KEY,
  tenantId  TEXT NOT NULL,
  nama      TEXT NOT NULL,
  tipe      TEXT NOT NULL DEFAULT 'customer', -- distributor | supplier | customer | lainnya
  telepon   TEXT,
  alamat    TEXT,
  email     TEXT,
  createdAt TEXT NOT NULL
);
CREATE INDEX idx_kontak_tenant ON kontak(tenantId);

CREATE TABLE distribusi (
  id        TEXT PRIMARY KEY,
  tenantId  TEXT NOT NULL,
  nomor     TEXT,
  tipe      TEXT NOT NULL,                    -- masuk | keluar
  tanggal   TEXT NOT NULL,
  lokasiId  TEXT NOT NULL,
  kontakId  TEXT,
  status    TEXT NOT NULL DEFAULT 'draft',    -- draft | selesai
  catatan   TEXT,
  createdAt TEXT NOT NULL
);
CREATE INDEX idx_distribusi_tenant ON distribusi(tenantId);

CREATE TABLE distribusi_produk (
  id           TEXT PRIMARY KEY,
  tenantId     TEXT NOT NULL,
  distribusiId TEXT NOT NULL,
  produkId     TEXT NOT NULL,
  qty          REAL NOT NULL DEFAULT 0,
  hargaSatuan  REAL DEFAULT 0
);
CREATE INDEX idx_dp_tenant ON distribusi_produk(tenantId);
CREATE INDEX idx_dp_distribusi ON distribusi_produk(distribusiId);

CREATE TABLE transaksi (
  id               TEXT PRIMARY KEY,
  tenantId         TEXT NOT NULL,
  nomor            TEXT,
  tipe             TEXT NOT NULL,             -- jual | beli
  tanggal          TEXT NOT NULL,
  lokasiId         TEXT NOT NULL,
  kontakId         TEXT,
  status           TEXT NOT NULL DEFAULT 'draft', -- draft | selesai | batal
  metodePembayaran TEXT DEFAULT 'tunai',      -- tunai | qris
  totalBayar       REAL DEFAULT 0,
  catatan          TEXT,
  createdAt        TEXT NOT NULL
);
CREATE INDEX idx_transaksi_tenant ON transaksi(tenantId);

CREATE TABLE transaksi_produk (
  id          TEXT PRIMARY KEY,
  tenantId    TEXT NOT NULL,
  transaksiId TEXT NOT NULL,
  produkId    TEXT NOT NULL,
  qty         REAL NOT NULL DEFAULT 0,
  hargaSatuan REAL DEFAULT 0,
  subtotal    REAL DEFAULT 0
);
CREATE INDEX idx_tp_tenant ON transaksi_produk(tenantId);
CREATE INDEX idx_tp_transaksi ON transaksi_produk(transaksiId);

CREATE TABLE payment (
  id          TEXT PRIMARY KEY,
  tenantId    TEXT NOT NULL,
  transaksiId TEXT NOT NULL,
  metode      TEXT NOT NULL DEFAULT 'qris',   -- qris | tunai
  referensi   TEXT,
  qrString    TEXT,
  jumlah      REAL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'pending', -- pending | lunas | gagal
  createdAt   TEXT NOT NULL,
  paidAt      TEXT
);
CREATE INDEX idx_payment_tenant ON payment(tenantId);
CREATE INDEX idx_payment_transaksi ON payment(transaksiId);

-- ---------------------------------------------------------------
-- MODUL KEUANGAN — akun (bagan akun/COA), jurnal + jurnal_detail
-- (jurnal umum, pola header+baris SAMA seperti transaksi/distribusi).
-- Tidak ada tabel neraca/laba-rugi/ekuitas tersendiri: ketiganya
-- SELALU dihitung real-time dari akun + jurnal_detail di pages/laporan.js
-- (satu sumber kebenaran, tidak ada data laporan yang disimpan ganda).
-- ---------------------------------------------------------------
CREATE TABLE akun (
  id          TEXT PRIMARY KEY,
  tenantId    TEXT NOT NULL,
  kode        TEXT NOT NULL,
  nama        TEXT NOT NULL,
  tipe        TEXT NOT NULL,             -- aset | kewajiban | ekuitas | pendapatan | beban
  saldoNormal TEXT NOT NULL,             -- debit | kredit (turunan dari tipe, disimpan eksplisit)
  saldoAwal   REAL DEFAULT 0,
  aktif       INTEGER DEFAULT 1,
  createdAt   TEXT NOT NULL
);
CREATE INDEX idx_akun_tenant ON akun(tenantId);

CREATE TABLE jurnal (
  id          TEXT PRIMARY KEY,
  tenantId    TEXT NOT NULL,
  nomor       TEXT,
  tanggal     TEXT NOT NULL,
  sumber      TEXT NOT NULL DEFAULT 'manual',  -- manual | transaksi | pembayaran
  referensiId TEXT,                             -- id transaksi/payment terkait (opsional)
  keterangan  TEXT,
  status      TEXT NOT NULL DEFAULT 'posted',   -- posted (instan, sama seperti transaksi/distribusi)
  createdAt   TEXT NOT NULL
);
CREATE INDEX idx_jurnal_tenant ON jurnal(tenantId);

CREATE TABLE jurnal_detail (
  id         TEXT PRIMARY KEY,
  tenantId   TEXT NOT NULL,
  jurnalId   TEXT NOT NULL,
  akunId     TEXT NOT NULL,
  debit      REAL DEFAULT 0,
  kredit     REAL DEFAULT 0,
  keterangan TEXT
);
CREATE INDEX idx_jd_tenant ON jurnal_detail(tenantId);
CREATE INDEX idx_jd_jurnal ON jurnal_detail(jurnalId);
CREATE INDEX idx_jd_akun ON jurnal_detail(akunId);

-- ============================================================
-- SEED DATA DEMO
-- Tenant "system" (kodeToko SUPERADMIN) khusus untuk akun superadmin
-- yang mengelola daftar tenant lain — bukan tenant bisnis sungguhan.
-- Tenant "tnt_demo" (kodeToko TOKO001) adalah contoh toko sembako.
-- ============================================================
INSERT INTO tenants (id, kodeToko, nama, alamat, telepon, status, createdAt) VALUES
 ('system',   'SUPERADMIN', 'Sistem (Superadmin)',   '-', '-', 'aktif', datetime('now')),
 ('tnt_demo', 'TOKO001',    'Toko Sembako Makmur',   'Jl. Merdeka No. 1', '081200000000', 'aktif', datetime('now'));

INSERT INTO users (id, tenantId, username, password, name, role, createdAt) VALUES
 ('usr_super', 'system',   'superadmin', 'super123', 'Super Admin',   'superadmin', datetime('now')),
 ('usr_owner', 'tnt_demo', 'owner',      'owner123', 'Budi Pemilik',  'owner',      datetime('now')),
 ('usr_kasir', 'tnt_demo', 'kasir',      'kasir123', 'Sari Kasir',    'kasir',      datetime('now'));

INSERT INTO lokasi (id, tenantId, nama, tipe, alamat, createdAt) VALUES
 ('lok_toko',   'tnt_demo', 'Toko Utama',     'toko',   'Jl. Merdeka No. 1',  datetime('now')),
 ('lok_gudang', 'tnt_demo', 'Gudang Belakang','gudang', 'Jl. Merdeka No. 1B', datetime('now'));

INSERT INTO produk (id, tenantId, kode, nama, kategori, satuan, hargaBeli, hargaJual, aktif, createdAt) VALUES
 ('prd_beras',  'tnt_demo', 'BRS001', 'Beras Premium 5kg', 'Sembako', 'karung', 60000, 72000, 1, datetime('now')),
 ('prd_minyak', 'tnt_demo', 'MYK001', 'Minyak Goreng 1L',  'Sembako', 'botol',  14000, 17000, 1, datetime('now')),
 ('prd_gula',   'tnt_demo', 'GLA001', 'Gula Pasir 1kg',    'Sembako', 'pcs',    12000, 15000, 1, datetime('now'));

INSERT INTO lokasi_produk (id, tenantId, lokasiId, produkId, stok, stokMinimum) VALUES
 ('lp1', 'tnt_demo', 'lok_toko',   'prd_beras',  20,  5),
 ('lp2', 'tnt_demo', 'lok_toko',   'prd_minyak', 40, 10),
 ('lp3', 'tnt_demo', 'lok_toko',   'prd_gula',   35, 10),
 ('lp4', 'tnt_demo', 'lok_gudang', 'prd_beras', 100, 20),
 ('lp5', 'tnt_demo', 'lok_gudang', 'prd_minyak',150, 30),
 ('lp6', 'tnt_demo', 'lok_gudang', 'prd_gula',  120, 30);

INSERT INTO kontak (id, tenantId, nama, tipe, telepon, alamat, email, createdAt) VALUES
 ('kon_sup1',  'tnt_demo', 'CV Sumber Pangan',     'supplier', '081300000001', 'Jl. Industri No. 10', 'sumberpangan@example.com', datetime('now')),
 ('kon_cust1', 'tnt_demo', 'Ibu Wati (Pelanggan)', 'customer', '081400000002', 'Jl. Kenanga No. 5',   '', datetime('now'));

-- Bagan Akun (COA) demo untuk tnt_demo. Kode 1101/1103/1104/2101/4101/5101
-- adalah kode BAKU yang dicari lewat kode (bukan id) oleh posting otomatis
-- di pages/jurnal.js (jurnalPage.postingTransaksi) — kalau tenant lain
-- membuat akunnya sendiri, kode-kode ini WAJIB dipakai ulang persis supaya
-- posting otomatis dari transaksi jual/beli berfungsi.
INSERT INTO akun (id, tenantId, kode, nama, tipe, saldoNormal, saldoAwal, aktif, createdAt) VALUES
 ('akn_kas',      'tnt_demo', '1101', 'Kas',                        'aset',       'debit',  5000000, 1, datetime('now')),
 ('akn_bank',     'tnt_demo', '1102', 'Bank',                       'aset',       'debit',  0,       1, datetime('now')),
 ('akn_piutang',  'tnt_demo', '1103', 'Piutang Usaha (QRIS)',       'aset',       'debit',  0,       1, datetime('now')),
 ('akn_persed',   'tnt_demo', '1104', 'Persediaan Barang Dagang',   'aset',       'debit',  3200000, 1, datetime('now')),
 ('akn_utang',    'tnt_demo', '2101', 'Utang Usaha',                'kewajiban',  'kredit', 0,       1, datetime('now')),
 ('akn_modal',    'tnt_demo', '3101', 'Modal Pemilik',              'ekuitas',    'kredit', 8200000, 1, datetime('now')),
 ('akn_prive',    'tnt_demo', '3102', 'Prive Pemilik',              'ekuitas',    'debit',  0,       1, datetime('now')),
 ('akn_jual',     'tnt_demo', '4101', 'Penjualan',                  'pendapatan', 'kredit', 0,       1, datetime('now')),
 ('akn_hpp',      'tnt_demo', '5101', 'Harga Pokok Penjualan (HPP)','beban',      'debit',  0,       1, datetime('now')),
 ('akn_beban_op', 'tnt_demo', '6101', 'Beban Operasional',          'beban',      'debit',  0,       1, datetime('now'));
