-- ============================================================
-- migration_ecommerce.sql — Migrasi untuk database YANG SUDAH JALAN
-- (menambah fitur etalase toko online / e-commerce), TANPA menghapus
-- data yang sudah ada (schema.sql penuh melakukan DROP TABLE — jangan
-- dijalankan ulang di database produksi yang sudah berisi data asli).
--
-- Jalankan SEKALI saja, misalnya:
--   wrangler d1 execute pos-db --remote --file=./migration_ecommerce.sql
-- ============================================================

ALTER TABLE tenants ADD COLUMN slug TEXT;
ALTER TABLE tenants ADD COLUMN deskripsi TEXT;
ALTER TABLE tenants ADD COLUMN tampilOnline INTEGER NOT NULL DEFAULT 1;

ALTER TABLE transaksi ADD COLUMN sumber TEXT NOT NULL DEFAULT 'pos';
ALTER TABLE transaksi ADD COLUMN pembeliNama TEXT;
ALTER TABLE transaksi ADD COLUMN pembeliTelepon TEXT;
ALTER TABLE transaksi ADD COLUMN pembeliAlamat TEXT;

-- SQLite/D1 tidak mendukung UNIQUE lewat ALTER TABLE ADD COLUMN, jadi
-- index unik dibuat terpisah di sini. Kalau ada tenant lama yang sudah
-- kebetulan diisi manual dengan slug sama, index ini akan gagal dibuat
-- — perbaiki duplikatnya dulu sebelum menjalankan baris ini.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- Isi slug awal untuk tenant yang sudah ada (turunan dari kodeToko,
-- huruf kecil) supaya link toko langsung tersedia tanpa perlu diisi
-- manual satu-satu dulu di halaman "Toko Online". Tenant 'system'
-- (superadmin) sengaja dilewati dan tampilOnline-nya dimatikan.
UPDATE tenants SET slug = lower(kodeToko) WHERE slug IS NULL AND id != 'system';
UPDATE tenants SET tampilOnline = 0, slug = NULL WHERE id = 'system';
