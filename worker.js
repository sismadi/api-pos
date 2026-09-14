// ============================================================
// worker.js — Worker API generik di atas D1, untuk POS Multi-Tenant
// ============================================================
// wrangler.toml perlu binding:
//   [[d1_databases]]
//   binding = "DB"
//   database_name = "<NAMA_DB>"
//   database_id = "<ID_DB>"
//
// Route generik (pola CRUD sama seperti worker MOOC asli):
//   GET    /api/:table               -> semua baris (tabel scoped WAJIB ?tenantId=)
//   GET    /api/:table/:id           -> satu baris (atau null)
//   POST   /api/:table                -> insert (body = row, id opsional)
//   PATCH  /api/:table/:id           -> update sebagian (merge)
//   DELETE /api/:table/:id           -> hapus
//
// ------------------------------------------------------------
// ISOLASI TENANT
// ------------------------------------------------------------
// Semua tabel bisnis POS ada di SCOPED_TABLES (lihat di bawah) dan WAJIB
// punya kolom `tenantId`. Tabel `tenants` sendiri TIDAK di-scope (memang
// daftar tenant global).
//
// Untuk tabel scoped:
//   - GET list   : wajib ?tenantId=..., hasil difilter WHERE tenantId=?
//   - GET by id  : wajib ?tenantId=..., 404 kalau baris ada tapi tenant beda
//                  (supaya tidak bocor informasi "baris ini ada tapi bukan milikmu")
//   - POST       : body.tenantId wajib diisi & dicocokkan dengan ?tenantId=
//   - PATCH/DELETE: wajib ?tenantId=..., baris diverifikasi dulu milik tenant
//                  tsb sebelum diubah/dihapus; body TIDAK BOLEH mengganti tenantId.
//
// CATATAN KEAMANAN (lihat juga README.md): tenantId di sini dikirim oleh
// KLIEN lewat query string, bukan diverifikasi lewat token sesi tervalidasi
// server-side. Ini cukup untuk mencegah kebocoran data antar-tenant akibat
// BUG di frontend, tapi TIDAK mencegah pengguna nakal yang sengaja mengganti
// nilai tenantId di URL/devtools. Untuk produksi sungguhan, ganti dengan
// JWT/sesi yang diverifikasi di Worker (tenantId diambil dari token, bukan
// dari input klien).
// ============================================================

const SCOPED_TABLES = new Set([
  'users', 'produk', 'lokasi', 'lokasi_produk', 'kontak',
  'distribusi', 'distribusi_produk',
  'transaksi', 'transaksi_produk',
  'payment',
]);

const TABLES = {
  tenants:            { jsonCols: [] },
  users:              { jsonCols: [] },
  produk:             { jsonCols: [] },
  lokasi:             { jsonCols: [] },
  lokasi_produk:      { jsonCols: [] },
  kontak:             { jsonCols: [] },
  distribusi:         { jsonCols: [] },
  distribusi_produk:  { jsonCols: [] },
  transaksi:          { jsonCols: [] },
  transaksi_produk:   { jsonCols: [] },
  payment:            { jsonCols: [] },
};

function genId(table) {
  return table + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function serializeRow(table, row) {
  const out = { ...row };
  for (const col of TABLES[table].jsonCols) {
    if (col in out) out[col] = JSON.stringify(out[col] ?? []);
  }
  return out;
}

function deserializeRow(table, row) {
  if (!row) return row;
  const out = { ...row };
  for (const col of TABLES[table].jsonCols) {
    if (col in out) {
      try { out[col] = JSON.parse(out[col]); } catch { out[col] = []; }
    }
  }
  return out;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/').filter(Boolean); // ['api', table, id?]

  if (parts[0] !== 'api' || !parts[1]) return json({ error: 'Not found' }, 404);
  const table = parts[1];
  const id = parts[2];
  if (!(table in TABLES)) return json({ error: `Tabel '${table}' tidak dikenal` }, 400);

  const scoped = SCOPED_TABLES.has(table);
  const tenantId = url.searchParams.get('tenantId');
  const db = env.DB;

  if (scoped && !tenantId && request.method !== 'OPTIONS') {
    return json({ error: `tenantId wajib untuk tabel '${table}'` }, 400);
  }

  if (request.method === 'GET') {
    if (id) {
      const row = await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
      if (scoped && row && row.tenantId !== tenantId) return json(null, 404);
      return json(deserializeRow(table, row) || null);
    }
    const stmt = scoped
      ? db.prepare(`SELECT * FROM ${table} WHERE tenantId = ?`).bind(tenantId)
      : db.prepare(`SELECT * FROM ${table}`);
    const { results } = await stmt.all();
    return json(results.map(r => deserializeRow(table, r)));
  }

  if (request.method === 'POST' && !id) {
    const body = await request.json();
    if (scoped) {
      if (!body.tenantId) return json({ error: 'tenantId wajib diisi pada data yang dikirim' }, 400);
      if (body.tenantId !== tenantId) return json({ error: 'tenantId pada data tidak cocok dengan query' }, 403);
    }
    const record = { id: body.id || genId(table), ...body };
    const row = serializeRow(table, record);
    const cols = Object.keys(row);
    await db
      .prepare(`INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`)
      .bind(...cols.map(c => row[c]))
      .run();
    return json(record, 201);
  }

  if (request.method === 'PATCH' && id) {
    const patch = await request.json();
    const existing = await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
    if (!existing) return json(null, 404);
    if (scoped && existing.tenantId !== tenantId) return json(null, 404);

    const merged = { ...deserializeRow(table, existing), ...patch };
    if (scoped) merged.tenantId = existing.tenantId; // tenantId tidak boleh dipindah lewat PATCH
    const row = serializeRow(table, merged);
    const cols = Object.keys(row).filter(c => c !== 'id');
    await db
      .prepare(`UPDATE ${table} SET ${cols.map(c => `${c} = ?`).join(', ')} WHERE id = ?`)
      .bind(...cols.map(c => row[c]), id)
      .run();
    return json(merged);
  }

  if (request.method === 'DELETE' && id) {
    const existing = await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
    if (!existing) return json({ ok: true }); // idempotent
    if (scoped && existing.tenantId !== tenantId) return json({ error: 'Tidak ditemukan' }, 404);
    await db.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
    return json({ ok: true });
  }

  return json({ error: 'Method not allowed' }, 405);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }
    try {
      return await handleApi(request, env);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
