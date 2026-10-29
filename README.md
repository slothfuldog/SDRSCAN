# SDRScan (Sast Dast Rust Scan) (v1: Core + SAST PHP)

Struktur repo: `engine/` (workspace Rust), `backend/` (Go), `frontend/` (Nuxt), `deploy/` (Dockerfile dan compose).
Semua perintah Rust di bawah dijalankan dari folder `engine/`.

Workspace Rust dengan crate `core` (model temuan, template, profil, SARIF, laporan), crate `sast` (binary `sdrscan-sast`),
crate `dast` (binary `sdrscan-dast`: pemeriksaan pasif, login terautentikasi, dan crawl pasif terbatas), crate `vulndb` (basis data kerentanan lokal),
dan crate `vuln` (binary `sdrscan-vuln`: pembaruan basis data CVE). Backend (Go) dan frontend (Nuxt) menyusul.

## Pakai

```bash
cargo build --release
target/release/sdrscan-sast scan <PATH> --templates templates/php --format sarif --output sdrscan.sarif --fail-on high
```

Tanpa `--templates`, template dicari di `templates/` di samping binary; paket rilis harus menyertakan
`templates/` dan `profiles/`. Kode keluar: 0 bersih, 1 ada temuan >= `--fail-on`, 2 galat penggunaan/konfigurasi.

Opsi: `--format text|sarif`, `--output <file>`, `--fail-on <severity>` (default `high`, atau nilai dari profil),
`--profile <nama|path>` (`profiles/<nama>.yaml`), `--templates <dir>`, `-v`/`-q`.

## Menambah deteksi

Satu file YAML di `templates/php/` + fixture `tests/fixtures/php/<id>/{vulnerable.php,safe.php,expected.json}`.
Lokasi temuan = capture `@finding` (bila ada), lalu capture taint, lalu capture pertama. Tes menolak template tanpa fixture.

## Uji

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Catatan: pada macOS dengan Command Line Tools terbaru, linker bisa gagal membaca SDK default; jalankan dengan
`SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk`.

## DAST

```bash
target/release/sdrscan-dast scan https://target.example --format sarif --output dast.sarif --fail-on medium
```

Tanpa opsi tambahan: satu permintaan GET dan pemeriksaan pasif (header keamanan, flag cookie, pembukaan versi server,
CVE dari banner, input kata sandi); tanpa payload. Redirect hanya diikuti pada origin yang sama. Lokasi temuan berupa URL.
Kode keluar sama dengan SAST (0 bersih, 1 ada temuan di atas `--fail-on`, 2 galat).
HTTPS: sertifikat diverifikasi dengan penyimpanan sertifikat sistem. Untuk CA internal pakai `--ca-cert <berkas.pem>`;
`--insecure` melewati verifikasi (tidak aman, hanya untuk target yang Anda percaya; hasil diberi peringatan).
Jaringan privat (loopback, RFC 1918, CGNAT, ULA, link-local) diizinkan secara default; `--block-private-networks` menolaknya.
Endpoint metadata cloud (169.254.169.0/24, 169.254.170.0/24, 100.100.100.200, fd00:ec2::/32) selalu ditolak.
Pagar jaringan berlaku pada setiap permintaan (login, crawl, redirect).
**Hanya pindai target yang Anda miliki atau berizin tertulis.**

### Pemindaian terautentikasi dan crawl pasif

```bash
sdrscan-dast scan https://app.example/dashboard --auth-file auth.json --login-check          # uji login saja
sdrscan-dast scan https://app.example/dashboard --auth-file auth.json --crawl \
  --max-depth 3 --max-pages 50 --max-rps 5 --exclude-path '^/admin/billing' --format sarif --output dast.sarif
```

| Opsi | Default | Keterangan |
|---|---|---|
| `--auth-file PATH` | - | berkas JSON autentikasi (di bawah); kredensial tidak pernah lewat argumen atau env |
| `--crawl` | mati | crawl pasif dari URL target (tanpa opsi ini hanya satu halaman, walau ada `--auth-file`) |
| `--max-depth N` | 3 | kedalaman tautan (0 = hanya URL target); batas keras 10 |
| `--max-pages N` | 50 | jumlah halaman maksimum yang diambil; batas keras 500 |
| `--max-rps N` | 5 | permintaan per detik, termasuk login dan redirect (1 sampai 100) |
| `--exclude-path REGEX` | - | regex (tidak peka huruf besar-kecil) atas jalur+query yang tidak diambil; dapat diulang |
| `--login-check` | mati | hanya login lalu keluar: kode 0 bila berhasil (mencetak `login berhasil: N cookie diterima, halaman awal X`, atau `login berhasil: token diterima (header Authorization), halaman awal X` bila `login.token` dipakai; nilai token tidak pernah dicetak), 2 bila gagal; tanpa crawl dan tanpa temuan |

Nilai di luar batas keras ditolak (kode 2), tidak dipotong diam-diam.

**Berkas auth** (JSON, maksimum 64 KiB, harus berkas biasa; buat dengan izin `0600`, izin yang lebih longgar hanya diberi peringatan).
`login` dan/atau `headers`/`cookies` boleh ada:

```json
{
  "version": 1,
  "login": {
    "type": "form",
    "url": "https://app.example/login",
    "method": "POST",
    "body_format": "json",
    "username_field": "user",
    "password_field": "password",
    "username": "akun-uji",
    "password": "...",
    "extra_fields": {"remember": "true"},
    "csrf": {"source": "html_input", "name": "csrf_token", "send_as": "field"},
    "token": {"from": "json", "path": "data.access_token", "send_as": "header", "header_name": "Authorization", "prefix": "Bearer "},
    "success": {"statuses": [200, 302], "cookie_set": "session", "body_contains": "...", "body_not_contains": "invalid", "redirect_not_to": "/login",
                "json_path_exists": "data.access_token", "json_path_equals": {"path": "status", "value": "ok"}}
  },
  "headers": {"Authorization": "Bearer ...", "X-Api-Key": "..."},
  "cookies": {"name": "value"}
}
```

- `login.url` WAJIB satu origin (skema, host, port) dengan target; bila tidak, galat (kode 2) sebelum ada permintaan terkirim.
  Hanya `type: form` dan `method: POST`; `body_format`: `json` atau `form` (default, `application/x-www-form-urlencoded`).
- Alur: GET halaman login (cookie awal dan token CSRF), POST kredensial, cookie ditampung di cookie jar internal
  (Path/Domain/Secure sederhana; `Secure` tidak dikirim lewat http), lalu redirect satu origin diikuti dengan GET.
- `csrf.source`: `html_input` (`<input name=... value=...>` di halaman login), `cookie`, atau `header` (header respons halaman login).
  `csrf.send_as`: `field` (default untuk `html_input`) atau `header` (default untuk `cookie` dan `header`; nama header di `csrf.header_name`, default `X-CSRF-Token`).
- `success`: semua bidang yang diisi harus terpenuhi. `statuses` dinilai pada respons POST (default 2xx/3xx); `cookie_set` = nama cookie
  yang diterima; `body_contains`/`body_not_contains` dinilai pada respons akhir; `redirect_not_to` = teks yang tidak boleh ada pada
  `Location` hop mana pun. Bila `cookie_set` kosong, minimal satu `Set-Cookie` harus diterima; bila `redirect_not_to` kosong,
  redirect kembali ke URL login dianggap gagal.
- `token` (opsional, `version` tetap 1): untuk aplikasi yang form loginnya ditangani JavaScript dan API login-nya mengembalikan token di
  isi JSON atau header respons, bukan `Set-Cookie`. `login.url` harus berupa endpoint API yang dipanggil browser (DevTools, tab Network),
  bukan halaman `/login`; `body_format` mengikuti isi permintaan API itu. Setelah POST login: `from` = `json` (default; `path` = jalur titik
  ke nilai, mendukung indeks array seperti `items[0].token` atau `[0].token`) atau `header` (`path` = nama header respons). Nilai harus string
  atau angka, tidak kosong, maksimum 8 KiB, tanpa karakter kontrol atau non-ASCII; bila tidak, login gagal dengan pesan yang menyebut jalur
  tetapi tidak nilai atau isi respons. Token dikirim di SETIAP permintaan berikutnya (crawl, halaman, redirect satu origin; tidak pernah
  ke origin lain): `send_as` = `header` (default; `header_name` default `Authorization`; `prefix` default `Bearer ` untuk `Authorization`
  dan kosong untuk header lain, `""` eksplisit berarti tanpa prefiks; maksimum 32 karakter ASCII) atau `cookie` (`cookie_name` wajib).
  Bila `token` dikonfigurasi, token yang valid SUDAH cukup sebagai tanda login berhasil (cookie baru tidak diwajibkan; `success.cookie_set`
  tetap dipenuhi bila diisi). Login ulang (sesi 401/redirect login) mengambil token baru. Token disamarkan dari stdout/stderr/SARIF/log
  (tidak pernah dicetak).
- `success.json_path_exists` (jalur harus ada di isi JSON respons login) dan `success.json_path_equals` (`{"path","value"}`; nilai skalar
  dibandingkan sebagai string, jadi `"true"` cocok dengan `true`) adalah pemeriksaan eksplisit tambahan pada respons POST pertama. Status HTTP
  di luar 2xx/3xx (mis. 401/403) = gagal. Bila POST login mengembalikan HTML padahal `body_format` `json`, galat ditambah petunjuk
  `respons login berupa HTML; kemungkinan URL login adalah halaman, bukan endpoint API`; bila tidak ada cookie dan tidak ada `token`,
  galat menyarankan `login.token` dan memakai endpoint API.
- Contoh target SPA: `POST /api/auth/login` dengan `{"username","password"}` membalas `{"data":{"access_token":"..."}}` ->
  `"login": {"type":"form","url":"https://app.example/api/auth/login","body_format":"json","username_field":"username","password_field":"password","username":"...","password":"...","token":{"path":"data.access_token"}}`.
  Keterbatasan: crawl hanya membaca HTML sisi server; token membuat permintaan terautentikasi, tetapi halaman SPA yang dirender JavaScript tidak dijelajahi.
- `headers` dan `cookies` hanya dikirim ke origin target, tidak pernah ke host lain (redirect lintas origin tidak diikuti).
  Header `Host`, `Cookie`, `Content-Length`, `Transfer-Encoding`, `Connection` tidak diizinkan di `headers`.
- Login gagal = kode keluar 2 dengan alasan (status, tidak ada cookie, token CSRF tidak ditemukan, redirect ke login)
  tanpa mengutip kredensial atau isi cookie. Sesi berakhir saat crawl (redirect ke halaman login atau 401): login ulang satu kali per
  pemindaian, lalu pemindaian dihentikan dengan peringatan.
- Halaman login juga diperiksa (HTTP, autocomplete) dan flag cookie sesi yang diterima setelah login diperiksa
  (Secure, HttpOnly, SameSite; nilai cookie tidak pernah dicetak).

**Crawl pasif.** Dimulai dari URL target (setelah login): tautan `<a href>` dan `<form method=get action>` (formulir berisi input kata sandi
dilewati), satu origin, fragmen dibuang, BFS menurut `--max-depth` dan `--max-pages`. Hanya GET, tidak pernah POST/PUT/DELETE
selain login. Dilewati tanpa diambil: ekstensi statis (gambar, css, js, font, arsip, pdf, media), tautan lintas origin, dan jalur
yang cocok pola pengecualian bawaan berikut (ditambah `--exclude-path`), juga bila tujuan redirect:

```
logout|log-out|signout|sign-out|keluar|delete|remove|destroy|hapus|unsubscribe|reset|revoke|terminate|disable|deactivate|purge|drop|wipe|/api/.*/delete
```

Lainnya: URL dinormalisasi (parameter query diurutkan) dan duplikat/loop dibuang; maksimum 3 variasi query per jalur; badan
respons dibaca hanya untuk `text/html`, maksimum 2 MiB per respons (lebih besar: peringatan dan tidak dianalisis). Respons bukan HTML
tetap diperiksa headernya tetapi tidak diikuti. Respons 404/410 pada halaman hasil crawl tidak dilaporkan.

**Keluaran.** SARIF dan teks sama kontraknya (lokasi URL, bukti di `properties.evidence`). Temuan header/cookie yang sama di banyak
halaman digabung: satu temuan per (aturan, bukti), lokasi = URL pertama, bukti diakhiri `(berlaku juga di N halaman lain: ...)` (maksimum 5 URL;
bagian ini tidak ikut sidik jari). Ringkasan stderr: `N halaman dipindai, X temuan, Y peringatan`. Peringatan (stderr, bukan SARIF):
batas halaman/kedalaman tercapai, halaman dilewati karena pengecualian, sesi kedaluwarsa, respons terlalu besar, izin berkas auth longgar.

Pemeriksaan pasif tambahan: `dast-form-password-over-http` (input kata sandi di halaman HTTP atau dikirim ke URL HTTP, medium),
`dast-autocomplete-password` (input kata sandi tanpa `autocomplete=off`/`new-password`, info), `dast-sensitive-info-in-url`
(parameter `token`/`key`/`password`/`secret`/`session` pada tautan, low; hanya nama parameter yang dicatat).

**Keamanan rahasia.** Password, token, header, dan cookie tidak muncul di stdout/stderr, SARIF, pesan galat, atau log (`-v`/`-vv`):
nilai parameter sensitif pada URL disamarkan (`***`), log pustaka HTTP/TLS tidak diteruskan, dan galat berkas auth hanya menyebut nama bidang.
**Peringatan penggunaan:** gunakan akun uji dengan hak minimal (bukan admin) pada lingkungan uji/staging. Crawl hanya mengirim GET, tetapi
aplikasi tertentu dapat mengubah data lewat GET (mis. tautan aksi tanpa kata kunci pada daftar pengecualian); tinjau `--exclude-path`
sebelum memindai sistem yang berisi data penting. Aplikasi satu halaman berbasis JavaScript tidak dijelajahi (hanya HTML statis dari server).

### Active scanning (higher risk)

**PERINGATAN.** Fitur ini mengirim payload uji (bukan hanya membaca respons) ke parameter yang ditemukan, dan DAPAT memicu efek
samping nyata pada aplikasi yang salah desain (mis. yang mengubah data lewat GET, atau formulir POST yang benar-benar membuat/mengubah
data setiap kali diuji). **Hanya jalankan pada target yang Anda miliki atau berwenang tertulis, sebaiknya di lingkungan staging/uji,
bukan produksi.** Active scanning sekarang juga mengirim formulir GET **dan POST** dengan payload uji SQL injection; formulir POST jauh
lebih mungkin membuat, mengubah, atau menghapus data sungguhan dibanding GET — field lain pada formulir POST yang tidak sedang diuji
tetap dikirim dengan nilai dasarnya di SETIAP permintaan uji, sehingga formulir itu benar-benar disubmit berkali-kali (sesuai anggaran
`--active-max-requests`). Ini adalah keterbatasan bawaan semua alat active scanning (mis. Burp Suite, OWASP ZAP), bukan hanya SDRScan.
Mati secara default; **selalu wajib** opt-in eksplisit `--active`.

```bash
sdrscan-dast scan https://staging.example/app --active --crawl --max-rps 5 \
  --active-max-params 30 --active-max-requests 300 --active-timeout 600 \
  --format sarif --output active.sarif --fail-on high

# dengan spesifikasi OpenAPI/Swagger eksplisit (bila tidak ditemukan otomatis) dan time-based opt-in ganda
sdrscan-dast scan https://staging.example/api --active --active-timing \
  --openapi-spec https://staging.example/v3/api-docs --fail-on critical
```

| Opsi | Default | Batas keras | Keterangan |
|---|---|---|---|
| `--active` | mati | - | mengaktifkan seluruh pemeriksaan aktif di bawah; tanpa ini tidak ada payload yang pernah dikirim |
| `--active-timing` | mati | - | opt-in GANDA (butuh `--active` juga; tanpa `--active` = galat kode 2): time-based blind SQLi (payload `SLEEP`/`pg_sleep`), dibatasi maksimum 3 parameter diuji time-based per pemindaian (2 varian per parameter) karena membebani server |
| `--active-max-params N` | 30 | 100 | jumlah parameter/field unik maksimum yang diuji (gabungan GET, formulir GET/POST, dan endpoint API); dipotong menurut urutan ditemukan, sisanya diberi peringatan |
| `--active-max-requests N` | 300 | 2000 | jumlah permintaan aktif total maksimum (semua parameter/metode digabung); dihentikan dengan peringatan saat tercapai, hasil sebagian tetap dilaporkan |
| `--active-timeout DETIK` | 600 | 3600 | batas waktu total pemeriksaan aktif; dihentikan dengan peringatan saat tercapai |
| `--openapi-spec PATH-atau-URL` | - | - | lokasi eksplisit spesifikasi OpenAPI/Swagger (berkas lokal JSON, atau URL satu origin dengan target); tanpa ini, jalur umum dicoba otomatis (lihat di bawah) |

Nilai di luar batas keras ditolak (kode 2), tidak dipotong diam-diam. `scan --help` mencantumkan semua opsi ini.

**Sumber kandidat uji** (dedup; `--active-max-params` membatasi totalnya):
1. Parameter query pada URL target awal (selalu, walau tanpa `--crawl`).
2. Bila `--crawl` dipakai: parameter query pada setiap halaman hasil crawl, field formulir `method="get"`, DAN field formulir
   `method="post"` (text/password\*/email/number/hidden/textarea; checkbox/radio dikirim apa adanya dari atribut
   `checked`/`value`, tidak pernah diinjeksi; field bernama mirip `csrf`/`token`/`_token`/`authenticity`/`nonce` tidak pernah
   diinjeksi tetapi tetap dihitung ke anggaran). Formulir berisi input password (kemungkinan form login) dan formulir lintas-origin
   selalu dilewati sepenuhnya.
3. Endpoint API dari spesifikasi OpenAPI 3.x/Swagger 2.0: method **GET, POST, PUT, PATCH** (**DELETE tidak pernah dipanggil sama
   sekali, bahkan untuk baseline**); ditemukan lewat `--openapi-spec` eksplisit, atau dicoba otomatis pada origin target:
   `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/api-docs.json`, `/swagger/v1/swagger.json`,
   `/.well-known/openapi.json` (dikenali dari isi JSON berkunci `openapi` atau `swagger`). Parameter path/query diuji seperti
   parameter GET biasa; untuk PUT/PATCH/POST dengan `requestBody` JSON objek datar, properti **string** diuji satu per satu
   (properti non-string dikirim dengan nilai `example`/`default` dari skema atau nilai generik aman: `test`, `1`, `false`, `[]`).
   Skema yang tidak dapat diurai (bersarang kompleks, `oneOf`/`allOf`/`anyOf`) membuat operasi itu kehilangan pengujian badan
   (dilewati dengan aman, bukan gagal total); operasi tanpa path/query param dan tanpa badan yang bisa diurai tidak pernah diminta.
   **Keterbatasan:** hanya JSON (YAML tidak didukung), parser minimal (tanpa `$ref`, `allOf` komposisi, dsb.) — ini bukan pengganti
   Burp/ZAP untuk API kompleks, hanya jaring pengaman dasar.
4. Jalur `/api/...` tambahan ditemukan secara tekstual (regex, bukan eksekusi) pada berkas `.js` satu origin yang ditautkan dari
   halaman hasil crawl: literal yang diawali `/api/`, atau argumen pertama `fetch(...)`/`axios.<method>(...)`/`.get|post|put|patch(...)`.
   Method HTTP tidak dapat dipastikan dari teks, sehingga hasil ini hanya ditambahkan sebagai halaman untuk dijelajahi (GET); parameter
   query yang sudah tersemat dalam literalnya lalu diuji seperti sumber (2) di atas.

**Pemeriksaan dan payload** (himpunan kecil tetap, bukan daftar besar):
- SQLi error-based (`'` ditambahkan ke nilai dasar; dicocokkan dengan tanda galat MySQL/PostgreSQL/SQLite/SQL Server/Oracle).
- SQLi boolean-based blind (`' OR '1'='1` vs `' AND '1'='2`; heuristik panjang body dibanding dasar).
- SQLi time-based blind (`' OR SLEEP(3)-- -`, lalu `' OR pg_sleep(3)-- -` bila yang pertama tidak memicu jeda) — hanya `--active-timing`.
- XSS reflected: marker unik acak per pemindaian (`sdrscanxss<token>`), polos dan breakout (`"><sdrscanxss<token>>`); hanya temuan
  bila tanda `<` muncul verbatim tidak ter-escape pada respons HTML.
- Open redirect: hanya parameter yang nilainya tampak URL/path atau namanya cocok `redirect|return|next|continue|url|target|dest|callback`;
  payload `https://sdrscan-redirect-check.invalid/x` (TLD `.invalid`, dicadangkan IANA, tidak pernah resolve); temuan hanya bila
  `Location` mengarah PERSIS ke domain itu (redirect ini tidak pernah diikuti).
- CRLF/header injection: payload `x%0d%0aX-Sdrscan-Test: 1`; temuan bila respons memuat header `X-Sdrscan-Test`.

SQLi berlaku untuk semua sumber kandidat (termasuk formulir POST dan endpoint API); XSS, open redirect, dan header injection hanya
untuk parameter GET (URL dan endpoint API bermetode apa pun, bukan field formulir POST/badan JSON).

**Aturan dan severity:** `dast-active-sqli-error-based` (critical, CWE-89), `dast-active-sqli-boolean-blind` (high, CWE-89),
`dast-active-sqli-time-based` (high, CWE-89, keyakinan rendah), `dast-active-xss-reflected` (high, CWE-79),
`dast-active-open-redirect-confirmed` (medium, CWE-601), `dast-active-header-injection` (medium, CWE-113). Temuan ini BUKAN CVE:
`properties.vulnerability` tidak dipakai, jalur SARIF sama seperti temuan DAST pasif lain. Satu temuan per (aturan, URL/endpoint
tanpa query, nama parameter/field) walau beberapa payload dicoba. Pagar jaringan (metadata ditolak, dsb.), pengecualian jalur
(`--exclude-path` dan bawaan), dan `--max-rps` berlaku untuk SEMUA permintaan aktif juga. Ringkasan stderr menambah baris
`N permintaan aktif dikirim, M temuan aktif` bila `--active` dipakai.

## CVE / basis data kerentanan

SDRScan mencocokkan dependensi (SCA, di `sdrscan-sast`) dan versi perangkat lunak di banner HTTP (di `sdrscan-dast`)
dengan **basis data lokal**. Mesin pemindai **tidak pernah memakai jaringan untuk data CVE**; hanya
`sdrscan-vuln update` yang mengunduh. Tanpa basis data, SCA/CVE dilewati dengan peringatan (bukan galat).

### Pakai

```bash
export SDRSCAN_VULN_DB=/var/lib/sdrscan/vulndb          # atau --vuln-db <dir> di setiap perintah
sdrscan-vuln update                                      # OSV: Packagist, npm, Go, crates.io
sdrscan-vuln update --ecosystems Packagist,npm --nvd     # subset OSV + NVD (produk web terkurasi); NVD_API_KEY dipakai bila ada
sdrscan-vuln status [--json] [--max-age-days 7]          # umur data, jumlah advisory, peringatan bila usang (kode keluar 0)
sdrscan-vuln lookup --ecosystem npm --package lodash --version 4.17.15   # debug

sdrscan-sast scan <PATH> --vuln-db <dir>                 # SCA ikut berjalan; --no-sca mematikan
sdrscan-dast scan https://target.example --vuln-db <dir> # CVE dari header Server/X-Powered-By/X-AspNet-Version
```

Opsi `update`: `--ecosystems A,B`, `--db <dir>`, `--nvd` (`--no-osv` bila hanya NVD), `--from-dir <dir>`, `--timeout <detik>`,
`--ca-cert <pem>` (proksi/CA internal), `--insecure`, `--osv-base-url`/`--nvd-base-url` (cermin), `--max-download-mb`, `--force`.
Kode keluar `sdrscan-vuln`: 0 sukses, 2 galat. Pembaruan atomik: indeks dibangun di direktori sementara lalu dipasang;
bila gagal (unduhan terpotong, zip rusak, jumlah advisory menyusut di bawah separuh tanpa `--force`) basis data lama tidak berubah.
Batas anti zip-bomb: jumlah entri, ukuran terurai per entri dan total, ukuran unduhan; isi unduhan hanya dibaca, tidak pernah dijalankan.
Advisory malware OSV (`MAL-`) tidak diindeks.

### Instalasi tertutup (tanpa internet di mesin pemindai)

Di mesin yang berinternet unduh `https://osv-vulnerabilities.storage.googleapis.com/<Ekosistem>/all.zip` (Packagist, npm, Go,
crates.io), letakkan sebagai `<dir>/<Ekosistem>/all.zip` (atau `<dir>/<Ekosistem>.zip`, atau direktori berisi berkas `.json`),
dan untuk NVD simpan halaman respons API 2.0 per produk sebagai `<dir>/nvd/*.json`. Bawa `<dir>` ke mesin tertutup lalu:

```bash
sdrscan-vuln update --from-dir <dir> --db /var/lib/sdrscan/vulndb [--nvd]
```

Atau salin langsung direktori basis data hasil `update` (formatnya portabel). Mesin dengan proksi/CA internal memakai `--ca-cert`.

### Format direktori (versi 1)

```text
<db>/meta.json              {format_version, updated_at, advisory_count, sources:{osv:{updated_at, ecosystems:{<Eko>:{updated_at,advisories}}}, nvd:{updated_at,last_modified,entries,products}}}
<db>/osv/Packagist.jsonl    JSON Lines, satu advisory per paket, terurut (package, id): lihat tests/fixtures/vulndb
<db>/osv/npm.jsonl  osv/Go.jsonl  osv/crates.io.jsonl
<db>/nvd/products.jsonl     satu entri per (produk CPE, CVE): rentang versionStart/End*, atau versi persis
```

Baris OSV: `{"package","ecosystem","id","aliases","summary","cvss":{score,vector},"severity","ranges":[{"type","events":[{"introduced"|"fixed"|"last_affected"|"limit"}]}],"versions","fixed","references"(maks 5),"cwe","modified","withdrawn"}`.
`package` selalu field pertama sehingga pembaca memfilter baris dari awalan tanpa mengurai JSON penuh dan memuat per ekosistem
(lazy). Rentang GIT diabaikan. Skor CVSS dihitung dari vektor v3.x; tanpa skor dipakai severity kualitatif sumber, lalu `medium`.

### SCA (`sdrscan-sast`)

Lockfile yang dibaca: `composer.lock` (packages dan packages-dev -> `scope: dev`), `package-lock.json`/`npm-shrinkwrap.json`
(v1/v2/v3), `yarn.lock` (v1 saja), `go.mod` + `go.sum`, `Cargo.lock`. `.gitignore` dihormati; direktori `vendor` dan
`node_modules` tidak pernah ditelusuri. Satu temuan per (paket@versi, advisory) di lockfile (baris entri paket); `rule_id` = id CVE
(jika ada alias CVE; GHSA/PKSA/RUSTSEC yang beralias digabung), severity dari CVSS (critical >= 9,0; high >= 7,0; medium >= 4,0;
low > 0). Go: versi dari `go.mod` bila ada (versi terpilih, `replace` diikuti), selain itu versi tertinggi per modul dari
baris `go.sum` berhash zip (baris `/go.mod` hanya graf modul). Untuk menekan advisory, tulis id (CVE atau GHSA) per baris di
`.sdrscan-vuln-ignore` pada akar target (`#` komentar). Profil: `exclude_tags`/`include_tags` dengan tag `sca` (atau `cve`,
`dependency`) mengatur SCA; `min_severity` dan `fail_on` berlaku seperti temuan lain.

### DAST: CVE dari versi di banner

Produk terkurasi: Apache httpd, nginx, Microsoft IIS, PHP, OpenSSL, Tomcat, Jetty, Node.js, Express, lighttpd, ASP.NET (hanya bila
versinya jelas). Setiap CVE yang rentangnya (CPE NVD) memuat versi menjadi temuan `confidence: low` (nomor versi dapat ditambal
distribusi tanpa berubah; verifikasi diperlukan), maksimum 25 per respons (severity tertinggi dulu, lalu id) dengan peringatan
bila dipotong. Syarat platform (konfigurasi AND dengan OS) pada data NVD tidak dievaluasi.

### Kontrak SARIF

`result.properties.vulnerability` = `{ids, package, fixed_versions, source, references, cvss?, confidence, scope?}` dengan
`package` = `{ecosystem,name,version}` (SCA) atau `{product,version}` (DAST; `product` = awalan CPE). Rule dibuat dinamis dari
temuan (id CVE, `shortDescription` = ringkasan, tag `security`, `external/cve/<id>`, `external/cwe/<cwe>`, `security-severity` dari
CVSS). Sidik jari `sdrscanFingerprint/v1` dihitung dari (rule_id, path, paket@versi), bukan snippet.

### Sumber data dan lisensi

- OSV (https://osv.dev): data OSV dilisensikan CC-BY 4.0; entri GitHub Advisory Database CC-BY 4.0; pustaka/skema Apache-2.0.
  Basis data yang dibangun berisi turunan data tersebut: pertahankan atribusi "Open Source Vulnerabilities (OSV), osv.dev".
- NVD (https://nvd.nist.gov): data NVD adalah domain publik (karya pemerintah AS); gunakan `NVD_API_KEY` untuk batas laju lebih longgar
  dan patuhi ketentuan layanan NVD. Produk ini memakai data NVD tetapi tidak didukung atau disertifikasi oleh NVD.
# SDRSCAN
