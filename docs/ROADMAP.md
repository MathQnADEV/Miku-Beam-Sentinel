# Roadmap Pengembangan — Miku Beam Sentinel

> Catatan analisis internal. Semua rujukan `file:baris` merujuk ke kondisi kode
> saat dokumen ini dibuat. Gunakan `engine/scanners/cmdi.py` sebagai standar emas
> pola deteksi saat me-refactor scanner lain.

## 1. Penilaian Umum

Miku Beam Sentinel adalah **prototipe fungsional yang ambisius namun belum matang**
— rebrand dari Cerberus API Sentinel dengan arsitektur yang bersih di permukaan
(modul recon terpisah rapi, kontrak `BaseScanner`/`Vulnerability` konsisten, higiene
konkurensi `ThreadPoolExecutor` yang benar, layout Django/DRF konvensional) tetapi
rapuh di bagian terpenting.

Kekuatan konseptual terbesar: paradigma **reconnaissance-first + smart scanner
selection** — recon (port scan, deteksi tech, crawl, dir discovery) seharusnya
mengarahkan scanner mana yang jalan dan endpoint mana yang diuji. Sayangnya ini
**baru sebatas janji**: di jalur CLI, hasil recon sama sekali tidak menggerakkan
pemilihan scanner (`cli/main.py:144-257` murni dari flag argparse); di jalur web,
`_select_scanners` (`scan_executor.py:76-144`) hanya menjangkau 13 dari 23 scanner
— 10 scanner (LDAP, XPath, XMLInjection, OAuth, HPP, RateLimit, MassAssignment,
BusinessLogic, Logging, Auth) tak pernah terpilih, dan SQLi/NoSQL di-gate pada
string database tebakan yang sering "Unknown" sehingga scanner unggulan di-skip
diam-diam.

Kelemahan terbesar: **kesehatan deteksi (detection soundness)**. Mayoritas scanner
injeksi menyimpulkan "vulnerable" dari bukti lemah — refleksi payload (XSS, SSRF),
token yang payload-nya sendiri mengandungnya (deteksi sirkular pada SSRF/NoSQL/XXE),
substring ultra-generik (`'near "'`/`'SQL error'` untuk SQLi; `'self'`/`'request'`
untuk SSTI; `'localhost'`/`'root:'` untuk XXE), atau timing sekali-jalan tanpa
baseline. Banyak yang **nyaris dijamin false positive** pada halaman biasa. Jadi
klaim "23 scanners / Nikto-level / 200+ payloads" jauh melampaui apa yang benar-benar
dijalankan dan menghasilkan sinyal terpercaya (jumlah nyata: SQLi 146, XSS 117,
SSRF 51). Titik terang: `cmdi.py` memakai regex output ketat + baseline + timing
double-confirm, dan **harus menjadi template refactor semua scanner lainnya**.

---

## 2. Temuan Kritikal (perbaiki sebelum publish)

### Blocker publikasi GitHub (repo tidak bisa di-clone & dijalankan)
- **Frontend tidak bisa di-build** — `web/frontend/package.json`, `package-lock.json`,
  `index.html` **belum ter-track** (untracked). → `git add` ketiga file, verifikasi
  `npm ci && npm run dev` di clone bersih.
- **`LICENSE` belum ter-track** meski dirujuk di mana-mana. → `git add LICENSE`
  (dual-copyright sudah benar).
- **`engine/integrations/` (nuclei_runner) belum ter-track** → integrasi Nuclei
  hilang di clone. → `git add engine/integrations/`.
- **`web/backend/.env` belum di-gitignore** dan berisi `SECRET_KEY` (placeholder) +
  konfigurasi DB. `git add .` akan ikut meng-commit-nya. → Tambah `.env` dan
  `**/.env` ke `.gitignore` **sekarang**, buat `web/backend/.env.example` berisi
  placeholder, rotasi `SECRET_KEY`.
- **Launcher lama `cerberus` masih ter-track** (berisi path home penulis asli &
  branding "Cerberus"; sudah dihapus di working tree). → commit penghapusan
  (`git rm cerberus`) dan **track `miku-beam`** (launcher pengganti).
- **Badge/clone/issue/wiki README menunjuk repo upstream** — sudah diperbaiki ke
  `MathQnADEV/Miku-Beam-Sentinel` di README baru; pastikan tak ada sisa
  `CerberusMrX/Cerberus-API-Sentinel`.
- **`requirements.txt` mematahkan install bersih** — `mysqlclient` butuh header C;
  beberapa dependency (scapy, sqlalchemy, celery, redis, whitenoise, gunicorn,
  pyyaml, tqdm) tak pernah di-import. → Default `settings.py` ke SQLite untuk build
  OSS, jadikan MySQL opsional (atau PyMySQL); hapus dep tak terpakai; pin versi;
  pisahkan test dep ke `requirements-dev.txt`.

### Bug korektnes yang menghentikan fungsi
- **`BOLAScanner` crash** — `for payload in self.PAYLOADS:` (`bola.py:17`) merujuk
  atribut yang tak pernah didefinisikan. Di CLI (`cli/main.py:159-162` tanpa
  try/except) `--scan-all` / `--scan-bola` **abort total** dengan `AttributeError`.
  → Hapus loop mati baris 17-36, pertahankan logika manipulasi ID numerik di
  bawahnya.
- **Frontend "New Scan" hang** — `ProjectDetail.jsx` merender `<ScanProgress>` tanpa
  `scanId`, memicu guard error dan `onComplete` tak pernah jalan. → Ambil
  `res.data.id` saat start scan dan teruskan sebagai prop `scanId`.
- **`--auth-type api_key` diterima tapi tak melakukan apa pun** (`cli/main.py:124-129`),
  begitu juga `--headers` (`cli/main.py:67`, tak pernah di-parse). → Tambah cabang
  `elif api_key`; parse `args.headers` dengan `json.loads`.

### Keamanan (alat itu sendiri)
- **SSRF tak terautentikasi ke URL arbitrer** — `AllowAny` + `DEBUG=True`
  (`settings.py:32,101`) + `URLField` polos: siapa pun bisa mem-POST project dengan
  `target_url=http://169.254.169.254/...` lalu server fetch & port-scan jaringan
  internal. → Wajibkan auth untuk membuat scan; tolak host yang resolve ke
  loopback/link-local/RFC1918.
- **Stored XSS di laporan HTML** — semua field vuln diinterpolasi tanpa escape;
  `evidence` memuat payload `<script>` mentah + 500 char respons target
  (`reporter.py:64-72`). → `html.escape()` semua field, atau pindah ke Jinja2
  `autoescape=True`.
- **Autentikasi palsu** — halaman Login tak pernah di-route, interceptor token
  di-comment (`api.js:14-21`), backend `AllowAny`. → Putuskan tegas: hapus UI auth
  ATAU wire flow nyata + aktifkan `IsAuthenticated`.

### Dead code / arsitektur salah
- **`self.scanners` (23 objek) dibangun di `__init__` tapi tak pernah dipakai**
  (`scan_executor.py:48-74`); `_select_scanners` re-instansiasi. → Hapus atau gunakan.
- **Phase 3 `scan_executor.py:388-488` re-crawl + buat subdomain/port/tech "simulasi"
  yang tak pernah disimpan** ke `results`. → Hapus seluruh blok; recon nyata sudah
  di Phase 1.
- **Scan jalan di daemon thread tak terbatas; endpoint cancel kosmetik.** Celery/Redis
  ada di requirements tapi tak pernah di-wire; `InMemoryChannelLayer` rusak
  lintas-proses.
- **Backend membuang `recommendation`/`url`/`proof_of_concept`** saat menyimpan vuln
  (`scan_executor.py:375-382`) walau objek `Vulnerability` punya field itu → saran
  remediasi hilang di UI web.

---

## 3. Peningkatan Kualitas Deteksi

Tujuan: setiap temuan harus **dapat dipercaya**. Jadikan `cmdi.py` standar emas.

1. **Baseline + control request untuk setiap sinyal.** Ambil respons benign (tanpa
   payload) dan bandingkan sebelum menyimpulkan.
   - SQLi error-based (`injection.py:340`): signature error hanya dihitung jika
     **absen di baseline** dan muncul hanya setelah payload pemecah-sintaks; buang
     signature generik (`near "`, `SQL error`, `Database error`, `Syntax error`).
   - SQLi/NoSQL time-based (`injection.py:356`): ganti `elapsed >= 5` dengan
     `elapsed >= baseline + margin` + re-issue untuk konfirmasi.
   - HPP (`hpp.py:39`): jangan flag pada beda body mentah; bandingkan nilai
     parameter yang direfleksikan.
2. **Verifikasi out-of-band (OAST)** untuk kelas blind. SSRF (`ssrf.py:147`) & XXE
   (`xxe.py:151`) harus memakai server interaksi unik-per-request; lapor hanya saat
   callback tiba — bukan substring yang payload-nya sendiri mengandungnya.
3. **XSS context-aware** (`xss.py:223`): suntik canary acak, parse respons, konfirmasi
   payload mendarat **tanpa encoding di konteks eksekutif**. Hapus klausa payload
   ter-URL-encode (refleksi ter-encode justru pertahanan yang benar).
4. **SSTI dengan aritmetika operand acak** (`ssti.py:102`): dua angka acak 4-digit,
   wajibkan hasil kali absen di baseline; buang heuristik `'self'`/`'request'`.
5. **NoSQL operator injection yang benar-benar terkirim** (`nosql.py:118`): bracket
   notation `id[$ne]=` atau JSON body (bukan `str(payload)` teks datar); boolean
   differential (true vs false control).
6. **Perbaiki indicator case-dead** (`ssrf.py:108`, `xxe.py:127-128`):
   `computeMetadata`/`<!ENTITY`/`<!DOCTYPE` dibandingkan ke `.lower()` sehingga tak
   pernah cocok. `casefold()` kedua sisi + unit test per-indicator.
7. **Hentikan asumsi "200 + kata umum = vuln."** BrokenAccessControl
   (`access_control.py:43`), MassAssignment (`mass_assignment.py:47`), DataExposure
   file check (`data_exposure.py:70`), RateLimit (`rate_limit.py:36`), AuthScanner
   missing-auth (`auth.py:41`) fire pada catch-all SPA/halaman publik. Wajibkan
   differential (auth vs unauth, userA vs userB) + soft-404 baseline. Buang finding
   invalid: JWT HS256-as-vuln (`jwt.py:61`), X-XSS-Protection-missing
   (`misconfig.py:33`).
8. **Soft-404 baseline untuk recon** (`dir_discovery.py:61`, `subdomain_enum.py:33`):
   minta path/label acak dulu; lapor hanya yang divergen bermakna; deteksi
   wildcard-DNS sebelum brute subdomain.
9. **PoC capture di laporan** (`reporter.py`): render `recommendation`,
   `proof_of_concept`, `url` (kini dibuang) — ter-escape.

---

## 4. Roadmap Bertahap

### Phase 1 — Quick wins & cleanup (~1–2 hari, target: siap publish)
- Selesaikan semua blocker publikasi di bagian 2.
- Hapus artefak dev di root: `fix_imports.py`, `check_scanner_names.py`,
  `verify_backend.py`, `test_ws.py`, `scan_hang_analysis.md`, `RESTART_SERVER.md`.
- Perbaiki crash BOLA (`bola.py:17`) & hang "New Scan" frontend.
- Perbaiki launcher `--gui` agar pakai `daphne`, bukan `runserver`.
- Escape XSS laporan HTML + `encoding='utf-8'` di semua `open()` (cegah
  `UnicodeEncodeError` di Windows).
- Hapus dead code (`self.scanners`, blok simulasi Phase 3, indicator case-dead).
- Perbaiki `--auth-type api_key`, `--headers`, parsing host tanpa scheme
  (`port_scanner.py:43`).

### Phase 2 — Korektnes & arsitektur (~2–4 minggu, target: alat terpercaya)
- **Refactor semua scanner ke pola `cmdi.py`** (bagian 3). Pekerjaan inti penentu nilai.
- **Satukan recon → scanning.** Ekstrak peta `tech/port → scanner` ke helper engine
  yang dipakai bersama CLI & web; scanner menerima `discovered_urls`/form dari
  crawler dan mem-fuzz parameter nyata (bukan hanya base URL + param tebakan);
  jadikan 10 scanner tak terjangkau bisa dipilih; treat "Unknown" sebagai "jalankan".
- **Async task queue nyata.** Pindah `execute_scan` ke Celery + Redis (sudah di
  requirements) atau thread pool terbatas dengan queue persisten; rekonsiliasi scan
  stuck RUNNING → FAILED saat startup; cancellation flag kooperatif.
- **`InMemoryChannelLayer` → `RedisChannelLayer`**; consumer kirim state saat connect;
  reconnect-with-backoff di frontend; batasi pertumbuhan array `logs`.
- **Auth & otorisasi konsisten:** aktifkan `IsAuthenticated`, queryset per-owner,
  `DEBUG` dari env (default False), gate subscription WS per-scan, blokir SSRF ke
  range internal.
- **Session per-thread / HTTPAdapter pool** untuk `dir_discovery.py` (Session dibagi
  30 thread — bukan thread-safe).
- **Injeksikan Authenticator ke modul recon** agar auth berlaku ke
  tech-detect/dir-discovery/crawl.

### Phase 3 — Fitur ambisius (kelas profesional)
- **OAST/collaborator server built-in** — subdomain unik per-request untuk verifikasi
  blind SSRF/XXE/RCE/SQLi. Lompatan kualitas terbesar.
- **Auth/session handling untuk scanning di belakang login** — login recorder,
  cookie/token injection, session refresh.
- **Plugin API scanner** — registry deklaratif + predikat applicability + kontrak
  callback seragam; auto-generate flag argparse; hapus 23 blok copy-paste di
  `cli/main.py`.
- **CI + Docker** — GitHub Actions (install, migrate, pytest, build frontend); smoke
  test instansiasi tiap scanner (tangkap crash tipe BOLA); Dockerfile ASGI (Daphne)
  + docker-compose dengan Redis. Selaraskan `DEPLOYMENT.md` (kini salah:
  PostgreSQL+gunicorn/WSGI vs. MySQL+Daphne/ASGI aktual).
- **Reporting lebih kaya** — sort by severity, ringkasan count, styling, ekspor
  Markdown dari CLI, streaming Nuclei nyata.
- **Fingerprinting berbasis bukti** (Wappalyzer-style: word-boundary, header, script
  filename, meta generator, cookie) menggantikan substring naif (`'java' in
  'javascript'`).

---

## 5. Ide Fitur Baru (high-value)

1. **OAST interaction server terintegrasi** — mengubah scanner dari "penuh false
   positive" jadi "terpercaya". Mulai sederhana: subdomain wildcard + listener
   HTTP/DNS lokal.
2. **Authenticated scanning + login recorder** — buka seluruh permukaan aplikasi
   nyata yang kini tak tersentuh.
3. **Scan profile & policy (YAML)** — profil quick / deep / API-only / passive;
   sekalian menghidupkan checkbox modul di `ScanConfig.jsx` (kini dekoratif).
4. **Passive discovery** — crt.sh (Certificate Transparency) untuk subdomain +
   parsing `robots.txt`/`sitemap.xml`/JS bundle untuk endpoint. Jauh lebih akurat
   dari brute wordlist.
5. **OpenAPI/Swagger & Postman import** — parse spec untuk endpoint + parameter +
   tipe body nyata, lalu fuzz in-place. Solusi elegan untuk "scanner hanya uji base
   URL".
6. **Scan diffing & continuous monitoring** — bandingkan scan berturut, tandai vuln
   baru/hilang, notifikasi. Cocok untuk positioning "sentinel".
7. **Severity scoring + noise suppression jujur** — CVSS, confidence level
   (Confirmed/Firm/Tentative ala Burp), mode "hanya Confirmed". Lindungi kredibilitas
   selama Phase 2 berjalan.
8. **Rate limiting & scope guardrails** — throttle global, allow-list host/CIDR,
   penolakan target internal. Menambal SSRF sekaligus membuat alat aman dipakai.
