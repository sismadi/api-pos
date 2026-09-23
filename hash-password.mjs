// Membuat hash password untuk seed / reset manual.
//   node hash-password.mjs "PasswordRahasia"
// Hasilnya ditempel ke kolom users.passwordHash lewat:
//   wrangler d1 execute <NAMA_DB> --remote --command \
//     "UPDATE users SET passwordHash='<hasil>' WHERE username='owner' AND tenantId='tnt_demo';"
import { __test__ } from './worker.js';
const pw = process.argv[2];
if (!pw) { console.error('Pakai: node hash-password.mjs "PasswordAnda"'); process.exit(1); }
console.log(await __test__.hashPassword(pw));
