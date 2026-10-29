# SDRScan frontend

Antarmuka web SDRScan (Sast Dast Rust Scan): Nuxt 3 + TypeScript + Vue 3, mode SPA (`ssr: false`), dibangun dengan
`nuxt generate` dan ditanam ke binary `sdrscan-backend` (satu origin, semua panggilan API ke path relatif `/api/v1/...`).
Seluruh teks antarmuka berbahasa Inggris. Sumber kebenaran: TRD v2 (bagian "Antarmuka web (Nuxt)", "API REST backend",
"Keamanan"), PRD v2 (PM-F1..F13).

## Menjalankan

Prasyarat: Node 22+ (diuji di Node 24) dan npm.

```bash
cd frontend
npm install

# A. Dengan mock API (tanpa backend)
npm run dev:mock          # mock di :8787 + Nuxt dev di http://localhost:3000, /api diteruskan ke mock

# B. Dengan backend sungguhan
SDRSCAN_API_URL=http://127.0.0.1:8080 npm run dev
```

Akun contoh mock (hanya mock; dicetak juga saat `npm run mock` berjalan):

| Username | Password | Peran |
| --- | --- | --- |
| `admin` | `admin-password-1234` | Admin |
| `member` | `member-password-1234` | Member (tanpa akses DAST) |
| `dast-member` | `dast-member-pass-1234` | Member dengan `can_run_dast` |
| `newhire` | `temporary-pass-1234` | Member, wajib ganti password |

Backend sungguhan di balik `nuxt dev`: proxy tidak mengubah header Host (`changeOrigin: false`) agar pemeriksaan
Origin/Host backend lolos. Untuk HTTP tanpa TLS, jalankan backend dengan `SDRSCAN_COOKIE_SECURE=false` dan
`SDRSCAN_ALLOWED_HOSTS` yang memuat `localhost:3000`.

Mock memakai data yang sengaja berisi string berbahaya (HTML di path, pesan, dan snippet) untuk memeriksa bahwa semuanya
dirender sebagai teks. Skenario yang tersedia: Project dengan keadaan terkini berbasis Scan penuh + Scan parsial CI, target DAST
`pending_confirmation` dan `confirmed`, Codebase yang belum dipindai, scan yang berjalan (queued, running, succeeded; nama
Codebase yang mengandung "fail" menghasilkan scan gagal), jadwal aktif dan jadwal yang ditangguhkan (cabut akses DAST
`dast-member` di halaman Users, lalu lihat Codebase `admin-portal (live)` atau halaman Schedules).

## Perintah

| Perintah | Fungsi |
| --- | --- |
| `npm run dev` / `npm run dev:mock` | Server pengembangan (real / mock) |
| `npm run mock` | Hanya mock API (`MOCK_PORT`, default 8787) |
| `npm run build` | `nuxt generate`, hasil di `.output/public` (ditanam ke backend lewat `embed.FS`) |
| `npm run gen:ui-colors` | Membangkitkan ulang `assets/css/ui-colors.css` setelah mengubah `config/uiColors.ts` |
| `node scripts/csp-preview.mjs` | Menyajikan `.output/public` dengan CSP TRD (+ proxy `/api` ke mock) untuk memeriksa pelanggaran CSP |
| `npm run lint` | ESLint (termasuk `vue/no-v-html: error`) |
| `npm run typecheck` | `nuxt typecheck` (vue-tsc) |
| `npm test` | Vitest (unit, kontrak mock, komponen, alur login) |

Hasil build memuat satu skrip inline (konfigurasi runtime Nuxt, `window.__NUXT__`). Backend menghitung hash-nya untuk CSP
(TRD, bagian Keamanan). Tanpa CDN dan tanpa font eksternal; ikon berupa SVG inline (lihat bagian Nuxt UI).

## Struktur

```
frontend/
  nuxt.config.ts        ssr:false, nuxt generate, devProxy /api, Nuxt UI, ikon lokal
  pages/                login, index (Projects), schedules, projects/[id], codebases/new, settings/vulndb,
                        codebases/[id].vue (induk: kepala, ringkasan, tab) + index|files|scans|settings,
                        findings/[id], scans/[id], account, users, settings/tokens, activity, [...slug] (404)
  components/           CveBadge, FindingTypeChip, VulnerabilityPanel, SeverityBadge, SeverityCounts, ScanStatusBadge, DastStatusBadge, SnippetView, FindingTable,
                        ModalDialog, ConfirmDeleteDialog, CodebaseForm, ScheduleSettings, RunScanButton, AppField, FormErrorSummary, ...
  composables/          useApi, useLoad, useRouteQuery, useScanEvents (SSE + polling), useNotify (toast Nuxt UI), useCodebase,
                        useFormErrors (galat per field: simpan, petakan dari server, fokus, ringkasan)
  stores/auth.ts        Pinia: pengguna, peran, csrf_token (hanya di memori)
  middleware/           auth.global.ts (GET /auth/me sekali, redirect login, must_change_password)
  utils/                apiClient (klien fetch bertipe), endpoints (wrapper tiap endpoint), errors, severity, vuln (tautan CVE/GHSA, referensi aman),
                        permissions (aturan peran), validators, formErrors (pemetaan galat server -> field), schedule, scanStream, format
  config/, modules/, scripts/  warna UI statis (CSP), pembangkit CSS, csp-preview, dev-mock
  assets/css/           main.css (Tailwind 4 + Nuxt UI), ui-colors.css (dibangkitkan)
  types/api.ts          DTO TypeScript untuk seluruh API
  mock/                 core.ts (backend in-memory), seed.ts, server.ts (HTTP + SSE), hanya untuk dev/tes
  tests/                unit/, components/, flow/
```

## Keputusan implementasi

- **Klien API tunggal.** `useApi()` membungkus `fetch` same-origin: menambahkan `X-CSRF-Token` pada semua metode selain
  GET, `Content-Type: application/json` pada setiap tulis, mem-parsing galat `{error:{code,message,details}}` menjadi
  `ApiError`, dan pada 401 (selain login dan `/auth/me`) menghapus sesi lokal lalu mengarahkan ke `/login?next=...`.
  `next` hanya menerima path internal (anti open redirect).
- **Sesi dan CSRF.** Cookie `sdrscan_session` HttpOnly tidak terlihat JS. `csrf_token` (dari `/auth/login` dan `/auth/me`)
  hanya disimpan di state Pinia. Tidak ada `localStorage`/`sessionStorage`.
- **Render aman.** Semua path, URL, pesan, snippet, evidence, dan nama dirender lewat interpolasi Vue. `v-html` dilarang
  oleh ESLint (`vue/no-v-html`), tautan CWE hanya dibentuk dari nilai yang cocok `^CWE-[0-9]+$` dengan
  `rel="noopener noreferrer"`. Diuji dengan payload XSS di path, pesan, dan snippet.
- **Aturan peran** ada di `utils/permissions.ts` dan hanya menyembunyikan atau menonaktifkan kontrol; server tetap
  otoritatif dan 403 ditampilkan sebagai "You do not have permission to do this." Hapus Project/Codebase dan kelola
  pengguna/token/activity hanya Admin; Run scan SAST untuk semua; Run DAST, pendaftaran target URL, serta ubah base
  URL dan jadwal URL hanya Admin atau `can_run_dast`; Confirm authorization hanya Admin. Hapus permanen meminta
  mengetik nama persis (server juga memeriksa `?confirm=`).
- **Status scan.** Halaman `scans/[id]` memakai SSE (`/scans/{id}/events`) dengan cadangan polling `GET /scans/{id}` tiap 2
  detik bila `EventSource` tidak ada atau stream putus. Baris log yang diputar ulang server tidak digandakan.
- **Status tampilan di URL.** Filter, halaman, tab compare, dan pilihan Scan disimpan di query string.
- **Waktu.** Ditampilkan di zona waktu peramban; atribut `title` memuat nilai UTC.
- **Penjadwalan (TRD v2, endpoint jadwal).** Panel "Schedule" di Codebase settings dan halaman `schedules.vue` ("Schedules",
  semua pengguna, filter status, Resume dan Delete). Endpoint: `GET /schedules`, `PUT /codebases/{id}/schedule` `{cron}`,
  `POST /codebases/{id}/schedule/resume`, `DELETE /codebases/{id}/schedule`; `schedule_cron` tidak lagi dikirim lewat
  `POST/PATCH /codebases`. Objek `schedule` dibaca dari `GET /codebases/{id}`: `{cron, status (active|suspended), owner,
  suspended_reason (owner_deactivated|owner_lost_permission), suspended_at, last_enqueued_at, next_run_at}` atau `null`.
  Preset Hourly / Daily 02:00 UTC / Weekly (Senin 02:00) atau cron kustom; pratinjau tiga waktu berikutnya dihitung di
  klien (`utils/cron.ts`, UTC); pemeriksaan sintaks dan interval minimum (SAST 15 menit, DAST 60 menit) di klien hanya
  umpan balik awal, server tetap menjawab 422 `invalid_cron` / `schedule_too_frequent`. Jadwal suspended menampilkan alasan
  ("Owner was deactivated." / "Owner no longer has permission.") dan tombol Resume; Resume dan Save menjadikan penggunanya
  pemilik baru. Untuk Codebase URL, Save/Resume/Delete hanya aktif bagi Admin dan pengguna dengan DAST access (yang lain
  hanya-baca); jadwal DAST dilewati selama target belum confirmed. Tidak ada saklar enabled: jadwal dihapus untuk berhenti.
- **Jaringan privat.** Formulir menolak host literal loopback, link-local, metadata cloud, RFC 1918, CGNAT (100.64/10),
  ULA/link-local IPv6, dan IPv4-mapped IPv6 dengan "Private network addresses are not allowed."; galat `address_not_allowed`
  dari server (422 saat menyimpan, atau `error_code` scan) ditampilkan dengan teks yang sama. Pemeriksaan DNS dan redirect tetap tugas backend.

## Galat per field (formulir)

Setiap formulir menampilkan galat **di bawah field yang salah atau kurang**, tidak hanya satu pesan umum. Lapisan bersama:

- `composables/useFormErrors.ts`: satu per formulir (dipanggil di komponen pemilik form). Menyimpan galat per field
  (`errors`, `errorFor(name)`, `hasErrors`, `summary`), galat tanpa field (`formError`: 403/404/500/jaringan), `check()`
  (validasi klien **semua** field sekaligus, tampilkan semua, fokus ke yang pertama), `blur(name)` (validasi saat field dilepas;
  tidak pernah menghapus galat yang sedang tampil), `autoClear(() => ({...state}))` (galat sebuah field hilang saat nilainya
  diubah), `fromServer(error, opts)` (petakan galat server ke field), `focusField`, `focusFirst`, `reset`.
- `components/AppField.vue`: `UFormField` + store galat. Menerima `name`, `label`, `required` (penanda wajib), `help`/`hint`.
  Nuxt UI memasang `aria-invalid` dan `aria-describedby` ke pesan galat; `data-field` dipakai untuk fokus dan urutan halaman.
- `components/FormErrorSummary.vue`: ringkasan di atas form (`UAlert`, `role="alert"`): daftar "Label: pesan" dengan tombol yang
  memfokuskan field-nya, ditambah galat yang tidak terkait field.
- `utils/formErrors.ts`: logika murni pemetaan (diuji tanpa DOM).

Kontrak galat server (lihat `backend/README.md`, "Validation errors"): `details.field` (field pertama) dan `details.fields`
(`[{field, message, code?}]` bila beberapa field salah). Nama bersarang memakai titik (`login.password`, `headers.Authorization`)
dan elemen daftar indeks (`dast_crawl_exclude[2]`). Pemetaan ke nama field di form:

1. alias persis atau berawalan path (`aliases: { dast_crawl_exclude: 'exclude' }` juga memetakan `dast_crawl_exclude[2]` ke `exclude[2]`);
2. bila form tidak punya field itu: `x[2]` ke `x`, `a.b.c` ke `a.b` (mis. `headers.X` ke grup `headers`);
3. tanpa `details` (server lama): awalan pesan (`repo_url is required.`, `New password must ...` ke `new_password`);
4. yang tetap tidak dikenal, dan semua galat bukan-input (401/403/404/5xx/jaringan), tampil di alert form (bukan hilang).
Field baru di formulir (mis. `login.token.path`, `login.success.json_path_equals.value`) cukup diberi `AppField name="<jalur API>"`; tanpa field sendiri galatnya jatuh ke induk terdekat (`login.token`, `login.success`) lalu ke alert form.
`fromServer(e, { byCode: { name_taken: 'name' } })` mengisi field untuk server yang belum mengirim `details`.

Aturan UI: tombol kirim tidak dimatikan diam-diam (klik tetap memunculkan galat per field; hanya mati saat mengirim atau karena
izin yang dijelaskan di layar). Validasi klien memeriksa semua field sekaligus: "X is required" untuk yang kosong, galat format
untuk yang salah. Daftar pasangan (`PairListEditor`: header, cookie, field login tambahan) dan baris pengecualian crawl punya galat
per baris. Formulir yang tercakup: login, ganti password, project, codebase (repo dan URL), Authentication, Crawling, jadwal,
buat pengguna, reset password, token ingest, pembaruan basis data kerentanan, pindah codebase, hapus (nama konfirmasi),
konfirmasi otorisasi. Mock (`mock/core.ts`) mengembalikan bentuk galat yang sama dengan backend.

## DAST terautentikasi dan crawl

Dua panel baru di **Codebase settings** untuk Codebase URL (hanya terlihat oleh Admin dan Member dengan `can_run_dast`; Member tanpa
izin tidak melihat Codebase ini sama sekali, jadi tidak ada panel yang bisa dirender).

- **Authentication** (`components/DastAuthSettings.vue`, `utils/dastAuth.ts`): pilihan *None / Login form / Fixed header(s) / Login form + headers*.
  Formulir login: login URL (default base URL + `/login`, harus satu origin dengan base URL), method, body format (Form / JSON), nama field
  username dan password, username, password (`type=password`), field tambahan (nama/nilai), CSRF (source, name, send as, header name),
  bagian **Token in login response** (saklar; Source: JSON body / Response header, Path atau nama header, Send as: Authorization header / Custom header / Cookie,
  header name, prefix, cookie name; teks bantuan untuk aplikasi JavaScript: pakai endpoint API yang dipanggil browser, bukan halaman /login) dan
  success indicator (statuses, cookie set, body contains / does not contain, redirect not to, JSON path exists / equals). Header tetap dan cookie: daftar nama/nilai.
  **Semua nilai rahasia write-only**: setelah tersimpan panel menampilkan lencana *Credential saved*, ringkasan nama saja
  (`POST https://… as tester · headers: Authorization`) serta tombol **Replace**, **Remove** (dialog konfirmasi) dan **Test login**.
  Replace membuka formulir dengan input rahasia kosong ("Saved (leave blank to keep)"); nilai kosong dikirim sebagai `""` dan server
  mempertahankan nilai tersimpan dengan nama yang sama. Setelah PUT berhasil semua nilai yang diketik dihapus dari state. Tidak ada
  `v-html`, tidak ada `localStorage`. *Test login* memanggil `POST /codebases/{id}/dast-auth/test` (hanya target confirmed dan jenis dengan
  login form) dan menampilkan hasil sukses/gagal beserta pesan; menguji kredensial yang tersimpan, bukan isi formulir.
  Teks bantuan: gunakan akun uji berhak minimal; kredensial disimpan terenkripsi dan hanya dikirim ke host target; didukung hanya login formulir
  (POST, form/JSON, token CSRF opsional) dan header/cookie tetap, **tidak** OAuth/SSO, MFA, atau CAPTCHA.
- **Crawling** (`components/DastCrawlSettings.vue`): saklar enable, max depth (1..10), max pages (1..500), daftar pola pengecualian path
  (regex, maks 20 pola x 200 karakter) dengan catatan pengecualian bawaan engine (logout, delete, remove, ...) dan batasan bahwa aplikasi
  satu halaman berbasis JavaScript tidak dijelajahi. Disimpan lewat `PATCH /codebases/{id}` (`dast_crawl_enabled`, `dast_crawl_max_depth`,
  `dast_crawl_max_pages`, `dast_crawl_exclude`).
- Validasi klien ringan (origin login, nama dan nilai header tanpa CR/LF, header terlarang Host/Cookie/Content-Length/Transfer-Encoding/Connection,
  jumlah, 4 KiB per nilai, 16 KiB total, regex yang dapat dikompilasi tanpa look-around/back-reference); server tetap otoritatif dan galatnya
  ditampilkan ramah (mis. 503 `secret_key_required` -> "SDRSCAN_SECRET_KEY belum diatur").
- Mengubah base URL ke origin lain menghapus kredensial di server (pengaturan crawl tetap); halaman menampilkan pemberitahuan.
- **Scan run** (`pages/scans/[id].vue`): untuk scan DAST, lencana **Authenticated scan**, baris Login dan **Pages scanned** ditampilkan bila
  log job memuat `authenticated scan (<jenis>)` dan `scan summary: N pages scanned` (tidak pernah ada nilai kredensial di log).
- Tipe di `types/api.ts` (`DastAuth`, `DastAuthBody`, `DastCrawl`, `LoginCheckResult`), endpoint di `utils/endpoints.ts` (`dastAuth.get/put/remove/test`),
  mock di `mock/core.ts` (aturan sama: write-only, 404 identik, validasi, `secretKey: false` untuk 503).

## Active scanning (pemindaian aktif, BERISIKO)

**Fitur berisiko.** Active scanning mengirim payload uji SQL injection, XSS reflected, open redirect dan header injection ke
parameter yang ditemukan di target — parameter GET, **formulir POST HTML hasil crawl**, dan, bila spesifikasi OpenAPI/Swagger
tersedia, operasi API (GET/POST/PUT/PATCH; **DELETE tidak pernah diuji**) dengan payload juga dikirim di **body JSON**, bukan
hanya di URL/form HTML. Ini **dapat membuat, mengubah, atau menghapus data nyata**, terutama pada aplikasi yang mengubah
state lewat GET, atau yang mengekspos POST/PUT/PATCH/operasi API tanpa langkah konfirmasi. Karena itu ada **lapisan otorisasi
terpisah yang lebih tegas** daripada konfirmasi target DAST biasa — tanpanya scan DAST selalu berjalan pasif saja, berapa pun
permintaannya.

- **Panel "Active scanning"** (`components/ActiveScanningSettings.vue`) di Codebase settings, di bawah panel Authentication
  dan Crawling, dengan border amber dan ikon peringatan (hanya terlihat oleh Admin/Member `can_run_dast` pada Codebase URL).
  Menjelaskan risiko di atas secara eksplisit. Status belum diotorisasi: tombol **"Authorize active scanning"** membuka
  `AuthorizeActiveScanningDialog.vue` (mirip `ConfirmDeleteDialog`): pengguna harus mencentang pernyataan risiko DAN mengetik
  ulang nama codebase persis, baru submit memanggil `POST /codebases/{id}/authorize-active-scanning`
  (`{statement_accepted, codebase_name}`; galat per-field `statement_accepted` / `codebase_name`, 409 `target_not_confirmed`
  bila target dasar belum dikonfirmasi, 409 `not_a_url_target` untuk repo). Status sudah diotorisasi: "Authorized by `<user>`
  on `<tanggal>`" dan tombol **Revoke** (`DELETE` yang sama, 204, idempoten).
- **OpenAPI/Swagger spec URL** (opsional, field teks di panel yang sama, independen dari otorisasi): divalidasi satu origin
  dengan base URL (aturan sama seperti login URL), kosong = hanya auto-discovery saat crawl. Disimpan lewat
  `PATCH /codebases/{id}` (`dast_openapi_spec_url`), tampil di `GET /codebases/{id}` sebagai `dast_active.openapi_spec_url`.
  Ikut terhapus saat origin base URL berubah, sama seperti kredensial DAST.
- **Dialog "Run scan"** untuk target DAST kini selalu lewat `RunDastScanDialog.vue` (dipicu dari `RunScanButton.vue`): toggle
  **"Active scanning"** hanya muncul bila `dast_active.authorized` true; selain itu disembunyikan dengan teks "Authorize
  active scanning first." dan tautan ke pengaturan (`#active-scanning`). Saat aktif, muncul sub-toggle **"Time-based SQL
  injection tests (adds server load)"** (default mati, opt-in ganda). Mengaktifkan toggle menampilkan ringkasan peringatan
  ("This will send SQL injection, XSS, and other test payloads to this target.") sebelum submit. Submit memanggil
  `POST /scans` dengan `{active, active_timing}` hanya bila `active` dinyalakan; scan SAST tetap langsung jalan tanpa dialog.
- **Riwayat dan detail scan**: lencana **"Active scan"** (+ "+ timing" bila dipakai) terpisah dari Full/Partial, di
  `pages/codebases/[id]/scans.vue` dan `pages/scans/[id].vue` (dari field `scan.active` / `scan.active_timing`). Baris
  "Active requests sent" tampil bila log job memuat ringkasan tersebut. `utils/dastAuth.ts` menambah `scanActiveInfo(lines)`
  (membaca `active scanning authorized by <user> on <tanggal>, type: ...` dan jumlah permintaan aktif, termasuk format
  mentah mesin "N permintaan aktif dikirim, M temuan aktif" — hanya jumlah permintaan yang diambil, bukan jumlah temuan).
- **Temuan aktif**: rule dengan awalan `dast-active-` ditandai lencana "Active" di `FindingTable.vue` (terdeteksi dari
  `rule_id` di sisi frontend; backend tidak mengekspos facet khusus untuk ini di versi ini).
- Tipe baru di `types/api.ts` (`DastActiveInfo`, `AuthorizeActiveScanningBody`, `Scan.active/active_timing`,
  `PatchCodebaseBody.dast_openapi_spec_url`), endpoint di `utils/endpoints.ts`
  (`codebases.authorizeActiveScanning/revokeActiveScanning`, `scans.create(id, {active, active_timing})`), mock di
  `mock/core.ts` (aturan sama: urutan validasi identik dengan backend — `active_timing` tanpa `active` ditolak lebih dulu,
  lalu `target_not_confirmed`, lalu `active_scanning_not_authorized`; jadwal menolak `active`/`active_timing`; otorisasi
  ikut terhapus saat origin base URL berubah).

## CVE dan kerentanan dependensi

Backend mengirim temuan kerentanan (SCA: paket di lockfile; DAST: produk/versi di URL) sebagai temuan biasa dengan `kind: "vulnerability"` dan objek
`vulnerability` (`ids`, `package`, `fixed_versions`, `source`, `references`, `cvss`, `confidence`, `scope`; semua kunci selalu ada). Temuan kode memiliki
`kind: "code"` dan `vulnerability: null`. DTO ada di `types/api.ts`, pembungkus endpoint di `utils/endpoints.ts`.

- **Daftar finding** (`codebases/[id]/index.vue`, `FindingTable.vue`): kolom Type (`FindingTypeChip`: Code | Vulnerability), kolom "Rule / CVE" berisi lencana ID
  (`CveBadge`, maksimal 3 lalu "+N more") dan `paket@versi` (SCA) atau `produk versi` (DAST). Filter "Type" (`kind=`), kotak "CVE" (ID lengkap CVE/GHSA/OSV
  -> `cve=` persis; teks sebagian -> `q`, dipakai hanya bila kotak Search kosong), keduanya tersimpan di query string. Ringkasan "N vulnerable dependencies"
  memakai `facets.vulnerable_packages` (disembunyikan bila 0) dengan tombol "Show vulnerabilities only".
- **Detail finding** (`pages/findings/[id].vue`, `VulnerabilityPanel.vue`): ID (CVE -> NVD hanya bila cocok `^CVE-[0-9]{4}-[0-9]{4,19}$`; GHSA -> GitHub hanya bila
  cocok `^GHSA-[2-9a-z]{4}-[2-9a-z]{4}-[2-9a-z]{4}$` tanpa memedulikan huruf besar/kecil; ID lain teks biasa), paket/ekosistem/versi terpasang, "Upgrade to ...",
  skor dan vektor CVSS, sumber (OSV/NVD), confidence (DAST: "Version-based detection, may be patched by the vendor."), scope Dev/Runtime, referensi (hanya
  http/https tanpa kredensial, `target="_blank"` `rel="noopener noreferrer"`; selain itu teks biasa), serta lokasi lockfile atau URL. Semua nilai dirender sebagai teks.
- **Halaman Admin "Vulnerability database"** (`/settings/vulndb`, menu hanya untuk Admin lewat `canManageVulnDb`): kartu status (terpasang, jumlah advisory, umur data
  tertua), tabel sumber per ekosistem, peringatan ("CVE checks are off until the database is installed." bila belum dikonfigurasi/terpasang, data tua lewat
  `stale`, alat `sdrscan-vuln` tidak ada, SCA dimatikan, galat status), tombol "Update now" (dialog: pilih ekosistem Packagist/npm/Go/crates.io dan opsi NVD),
  status job (running/succeeded/failed/cancelled, kode galat, kode keluar, log), tombol "Cancel update", dan polling `GET /system/vulndb` tiap 2 detik selama job berjalan.
  Endpoint: `GET /system/vulndb`, `POST /system/vulndb/update {ecosystems?, nvd?}` (202), `POST /system/vulndb/update/cancel` (202); semua Admin saja (Member: 403 `forbidden_role`).
- **Confidence dan scope (keputusan produk):** finding bertipe kerentanan selalu `confidence: "normal"` di tingkat finding (backend memaksa ini saat ingest), jadi selalu
  muncul di daftar default, total, ringkasan, dan compare; aturan sembunyi low-confidence hanya berlaku untuk temuan kode. Tingkat keyakinan CVE ada di
  `vulnerability.confidence`: lencana "Confidence: low" di samping severity (daftar dan detail) dan catatan "Version-based detection, may be patched by the vendor." (DAST).
  Filter `confidence=high|low` dan `scope=runtime|dev` (400 untuk nilai lain; temuan kode tidak pernah cocok) ada di daftar finding sebagai select "Confidence" dan
  "Scope" (hanya tampil bila ada temuan kerentanan), tersimpan di query string, dengan hitungan dari `facets.confidence` / `facets.scope` (hanya temuan CVE, masing-masing
  mengabaikan filternya sendiri). Dependensi dev tetap dilaporkan dan dihitung; lencana "Dev" tampil di daftar dan lencana Dev/Runtime di detail.
- **Produk DAST (CPE):** `vulnerability.package.product` dari mesin DAST adalah prefiks CPE (mis. `cpe:2.3:a:apache:http_server`). Daftar dan detail menampilkan
  "vendor product versi" (mis. "apache http_server 2.4.41"; vendor sama dengan product ditampilkan sekali: "nginx 1.18.0"); string CPE mentah tetap tampil sebagai teks
  (baris kecil di panel detail, atribut `title` di daftar), tidak pernah menjadi tautan. Nilai yang bukan CPE ditampilkan apa adanya. ID seperti `GHSA-2099-fram-0001`
  atau `PKSA-2099-FRAM-0001` tidak cocok pola ketat sehingga tampil sebagai teks biasa (bukan tautan); mock memuat ID seperti itu.
- **Go (go.sum):** SCA untuk Go bekerja dari `go.sum` sehingga dapat melaporkan berlebih (modul mungkin tidak dipakai). Panel detail untuk paket ekosistem Go memuat satu baris
  petunjuk: "Go: detected from go.sum, may over-report (the module may not be used)." Tidak ada penanganan khusus lain.
- **Bentuk `status` (dari `sdrscan-vuln status --json`):** `GET /system/vulndb` memuat `status {installed, advisory_count, updated_at, age_days, max_age_days,
  format_version, sources[{name, ecosystem, advisories, updated_at, age_days, products[]}]}`. `status` tidak pernah null selama alat bekerja (belum terpasang =
  `installed:false`, `sources:[]`); `status` null hanya bila alat tidak ada/gagal, dan `status_error` terisi. `format` dan `raw` sudah dihapus (tidak ada teks
  cadangan). `stale` dan `stale_after_days` (= `max_age_days`, 7) berasal dari CLI. Halaman admin menampilkan umur sebagai "N days ago" dari `age_days`
  (kembali ke selisih waktu bila kosong), sumber OSV per ekosistem, dan sumber NVD dengan daftar produk CPE sebagai teks kecil. Di dialog update, NVD tetap
  opt-in dengan petunjuk: hanya diperlukan untuk CVE produk dari DAST; OSV (ekosistem yang dipilih) mencakup SCA.
- **Mock** (`mock/`): codebase `shop-deps` (id 7, project Internal Tools; SCA `composer.lock` dan `package-lock.json`) dengan CVE+GHSA, versi perbaikan, referensi
  `javascript:`/`ftp:`/URL berkredensial, serta nama paket, versi, ID, dan referensi berisi HTML; codebase `status-page (live)` (id 8, DAST) dengan CVE nginx
  (`confidence: low`) dan satu temuan kode. Temuan DAST ikut aturan visibilitas URL (404 untuk Member tanpa DAST). Basis data kerentanan mock: data 2 hari, update
  3 detik lalu sukses; skenario `installed:false` (belum terpasang), `dataAgeDays: 12` (stale), `toolAvailable:false` (status null + `status_error`) tersedia; update dengan ekosistem `npm` saja selalu gagal (untuk melihat status gagal). Skenario lain lewat `createMockBackend({ vulndb: { configured, installed,
  toolAvailable, scaEnabled, dataAgeDays, cron } })`.

## Nuxt UI, ikon, font, dan CSP

Pustaka komponen: **Nuxt UI 3** (`@nuxt/ui`, Tailwind CSS 4): UModal, UButton, UInput/USelect/UTextarea/UCheckbox/URadioGroup,
UForm/UFormField, UTable, UBadge, UAlert, UTabs, UBreadcrumb, UPagination, UDropdownMenu, UNavigationMenu, UCard, dan toast
(`UApp`). Komponen kita yang tersisa hanya pembungkus yang menyandikan aturan produk (`SeverityBadge`, `ModalDialog`, `FindingTable`,
`RunScanButton`, ...), `SnippetView` (teks saja), dan `LoadingState`/`EmptyState`.

- **Ikon tanpa CDN.** Koleksi `@iconify-json/lucide` dibundel ke klien (`icon.clientBundle`, 52 ikon, sekitar 13 KB),
  `icon.provider: 'none'`, `fallbackToApi: false`, dan `icon.mode: 'svg'` (inline `<svg>`). Tidak ada permintaan ke `api.iconify.design`
  (diperiksa: semua sumber daya halaman berasal dari satu origin).
- **Font lokal.** `@fontsource-variable/public-sans` dibundel (satu berkas woff2 di `_nuxt/`); modul `@nuxt/fonts` dimatikan (`ui.fonts: false`).
- **Mode gelap** mengikuti sistem lewat `plugins/color-scheme.client.ts` (menambah/menghapus class `dark`); modul color-mode dimatikan karena ia menyuntik skrip inline.

### Temuan CSP (diuji dengan `scripts/csp-preview.mjs`, kebijakan TRD)

Kebijakan yang diuji (persis TRD): `default-src 'none'; script-src 'self' 'sha256-<hash skrip inline Nuxt>'; style-src 'self';
style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.

Nuxt UI 3 **mentah** melanggar kebijakan itu pada tiga hal, semuanya pada waktu berjalan (SPA):
1. plugin `colors` menyuntik `<style id="nuxt-ui-colors">` (variabel warna) dan skrip inline kecil
   (`document.head.removeChild(...)`) yang menghapus salinan sementaranya;
2. `@nuxt/icon` mode `css` menyuntik `<style>` berisi kelas mask per ikon (ikon tidak tampil);
3. (tidak ada pelanggaran dari atribut `style=`: Reka UI/floating-ui memakai CSSOM dan atribut, yang diizinkan `style-src-attr 'unsafe-inline'`.)

Penyelesaian tanpa melonggarkan CSP: CSS warna dibuat statis (`assets/css/ui-colors.css`, dibangkitkan dari `config/uiColors.ts` oleh
`npm run gen:ui-colors`, dijaga sinkron oleh uji `uiColors.test.ts`), plugin `colors` dihapus oleh `modules/static-ui-colors.ts`, dan ikon memakai
mode `svg`. Hasil: halaman build tidak memuat elemen `<style>` maupun skrip inline selain satu skrip konfigurasi runtime Nuxt
(`window.__NUXT__`, di-hash backend), dan tidak ada satu pun pelanggaran `securitypolicyviolation` saat login, tabel, dialog,
dropdown, select, tab, form, dan halaman jadwal dijalankan.

**Rekomendasi kebijakan minimal untuk backend: kebijakan TRD apa adanya, tanpa `'unsafe-inline'` pada `style-src` dan `script-src`.**
Yang dibutuhkan frontend: `script-src 'self'` + hash skrip inline `window.__NUXT__` (dihitung dari `index.html` saat start; hash berubah
tiap build karena memuat `buildId`), `style-src 'self'` (semua CSS adalah berkas `_nuxt/*.css`), `style-src-attr 'unsafe-inline'`
(untuk atribut `style="..."` yang diatur komponen overlay/popper), `font-src 'self'`, `img-src 'self' data:`, `connect-src 'self'` (API dan SSE).
Bila suatu saat plugin warna dikembalikan, kebutuhannya menjadi `style-src 'self' 'unsafe-inline'` dan hash skrip tambahan; sebaiknya dihindari.

## Visibilitas Codebase URL

Codebase `url` hanya ada bagi Admin dan Member dengan `can_run_dast`. Backend menyaring (daftar, dashboard, total, jadwal, pencarian) dan
membalas 404 `not_found` (bukan 403) untuk setiap endpoint yang menyentuhnya; frontend tidak merender apa pun yang tidak dikirim server.
Halaman Codebase menampilkan "Codebase not found." untuk 404 (juga bila izin dicabut saat halaman terbuka); halaman Scan run yang
mendapat 404 mengakhiri stream dan mengarahkan pengguna ke daftar Project. Opsi jenis "URL", lencana status DAST, tombol Run scan URL, dan
panel jadwal URL hanya muncul bagi yang berhak. Mock menegakkan aturan yang sama (`mock/core.ts`, predikat `visible`) dan diuji untuk semua endpoint.

## Asumsi dan penyimpangan dari TRD

- **Kontrak DTO** mengikuti bagian "Bentuk respons (DTO)" TRD (semua daftar beramplop `{items,total,page,page_size}`; kunci tidak berlaku = `null`,
  tidak dihilangkan; `types/api.ts` adalah salinannya). Tidak ada pembacaan toleran yang tersisa. Ringkasnya: `/projects` (`codebase_count`, `totals`,
  `highest_severity`), `/codebases/{id}` (`project`, `dast {status,registered_by,confirmed_by,confirmed_at}`, `confirmation_statement` hanya untuk url
  pending, `active_scan`, `schedule`), `facets.rule` sebagai larik `{id,count}` yang dihitung dengan semua filter kecuali dimensinya sendiri, `compare`
  (`base` bisa null, `warning {code,message}` dengan kode `empty_scope`, `items [{status, finding}]`), `/ingest-tokens` berhalaman (POST membalas `{token, secret}`),
  `/schedules` (objek `codebase` dan `project` bersarang). `confirmation_statement` ditampilkan apa adanya dari server (tanpa teks cadangan).
- **Yang tetap asumsi karena TRD belum merincinya:** baris `GET /codebases/{id}/files` (`{location,total,critical..info,kind?}`), `GET /audit-log`
  (`{id,at,actor_name,action,target}`), `GET /system/info`, dan `dast_max_rps` lewat `PATCH /codebases/{id}`, dengan batas UI 1 sampai 100 (TRD tidak
  menyebut batas atas; ubah di `CodebaseForm.vue` bila perlu).
- **Jadwal** (TRD): `GET /schedules`, `PUT /codebases/{id}/schedule {cron}`, `POST .../resume`, `DELETE .../schedule`; mengosongkan jadwal = DELETE
  (PUT dengan cron kosong tidak dikirim). `PUT` dan `resume` menjadikan pemanggil pemilik baru dan menghapus status suspended. Pratinjau tiga waktu
  berikutnya dan pemeriksaan interval minimum (SAST 15, DAST 60 menit) dihitung di klien (`utils/cron.ts`) hanya sebagai umpan balik awal; server tetap
  menjawab 422 `invalid_cron` / `schedule_too_frequent`. Preset Weekly dipilih Senin 02:00 UTC (TRD tidak menyebut hari).
- **Daftar target URL** (keputusan pemilik produk): Member tanpa DAST access tidak melihat Codebase URL sama sekali (lihat bagian di atas).
- **`activity.vue`** (log audit) diimplementasikan; hanya Admin.
- **Scan parsial** tidak pernah dipicu dari web; UI hanya menampilkannya (label Partial, "Based on full scan #N plus M partial scans", spanduk lingkup).
- **Dev proxy:** `nitro.devProxy` di `nuxt.config.ts` diberi `as never` karena tipe konfigurasi Nitro tidak dikenali setelah Nuxt UI memasang tipe `@nuxt/schema` 4.
  Tidak ada uji e2e Playwright (opsional di TRD); diganti uji alur dengan mock in-process.

## Pengujian

`npm test` menjalankan 288 uji Vitest (termasuk galat per field: pemetaan server ke field, komponen AppField/ringkasan, tiap formulir utama, kontrak galat mock) (termasuk DAST terautentikasi: validator, panel Authentication/Crawling, kontrak mock, alur halaman) (termasuk helper CVE/referensi, komponen CVE, kontrak mock temuan kerentanan dan basis data kerentanan, dan alur halaman Admin): klien API (CSRF, 401, format galat, Retry-After, 204, jaringan putus), pemetaan dan
urutan severity, aturan peran, validator dan penolakan tiap kelas alamat privat, helper jadwal dan stream scan, kontrak mock
(login/throttle, CSRF, 403 peran, konfirmasi hapus, aturan DAST, siklus hidup scan, keadaan terkini, filter, compare parsial,
admin terakhir, jadwal: pemilik, suspend otomatis, resume, interval minimum), evaluator cron, komponen kunci (XSS sebagai teks, Run scan per peran, dialog hapus), satu alur
login -> dashboard -> detail Finding dengan mock, dan **active scanning** (`tests/unit/activeScanningContract.test.ts`,
`tests/components/activeScanning.test.ts`, kasus `scanActiveInfo`/`openapiSpecUrlIssue` di `tests/unit/dastAuth.test.ts`):
urutan validasi `POST /scans` (`active_timing` tanpa `active` -> `target_not_confirmed` -> `active_scanning_not_authorized`),
dialog otorisasi (nama salah ditolak per-field, nama benar sukses), revoke, penghapusan otomatis saat origin berubah, jadwal
menolak `active`/`active_timing`, toggle "Active scanning" muncul/tersembunyi sesuai status otorisasi di dialog Run scan, dan
peran (Member tanpa `can_run_dast` tidak melihat apa pun untuk Codebase URL ini).
