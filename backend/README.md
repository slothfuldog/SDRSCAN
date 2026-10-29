# sdrscan-backend

Backend of SDRScan (Sast Dast Rust Scan), written in Go: REST API under `/api/v1`,
scan runner (clone + `sdrscan-sast` / `sdrscan-dast`), SARIF ingest for CI, scheduler and the embedded web UI.
It follows the TRD "Project Management (v2: Grouping Codebase dan Kerentanan)". PostgreSQL 15 or newer is required.

## Run it

```bash
export PATH=/usr/local/go/bin:$PATH
cd backend
go build -o bin/sdrscan-backend ./cmd/sdrscan-backend      # or: make build

export DATABASE_URL='postgres://sdrscan:sdrscan_dev@127.0.0.1:5433/sdrscan?sslmode=disable'
export SDRSCAN_SAST_BIN=../dist/sdrscan-sast  SDRSCAN_DAST_BIN=../dist/sdrscan-dast
export SDRSCAN_TEMPLATES=../dist/templates/php  SDRSCAN_WORKDIR=/tmp/sdrscan
export SDRSCAN_SECRET_KEY="$(openssl rand -base64 32)"      # needed to store git credentials
export SDRSCAN_COOKIE_SECURE=false                           # only for plain HTTP on localhost
export SDRSCAN_BOOTSTRAP_ADMIN_USER=admin SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password'
./bin/sdrscan-backend serve        # listens on 127.0.0.1:8080, migrates the database at start
```

Subcommands: `serve` (default), `migrate`, `user create|list|reset-password|set-role|enable|disable`
(direct database access, recovery path; `--password-stdin` or a prompt), `token create --name <label> [--project-id N]`,
`maintenance rebuild-state [--codebase-id N]` (recomputes `is_current` and the summaries from the canonical query), `version`.

The first Admin is created either by `user create --username <n> --role admin` or, when the `users` table is empty, from
`SDRSCAN_BOOTSTRAP_ADMIN_USER` / `SDRSCAN_BOOTSTRAP_ADMIN_PASSWORD(_FILE)`. Both create the account with
`must_change_password = true`: until the password is changed every endpoint except `/auth/me`, `/auth/password` and
`/auth/logout` answers 403 `password_change_required`.

### Web UI

`internal/webui/dist` is embedded into the binary (`//go:embed all:dist`). It ships empty (a `.gitkeep`), in which
case a placeholder page is served, so the backend always builds. To embed the frontend:
`cd frontend && npx nuxt generate && cd ../backend && make web` (copies `frontend/.output/public` to
`internal/webui/dist` and rebuilds). For development, `SDRSCAN_WEB_DIR=../frontend/.output/public` serves the files
from disk instead. SPA routes fall back to `index.html`; the CSP hashes the inline scripts of `index.html` at start.

### Docker

`deploy/Dockerfile` (multi-stage: Rust engines, Nuxt site, Go binary, `debian:stable-slim` with `git` and `ssh`) and
`deploy/docker-compose.yml` (PostgreSQL + backend, `tmpfs` work directory, read-only root, port bound to 127.0.0.1).
Build context is the repository root. Not built in this session (no Docker image build was run).

## Configuration (environment)

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL URL (TLS required for non-local hosts) |
| `SDRSCAN_LISTEN` | `127.0.0.1:8080` | listen address |
| `SDRSCAN_SAST_BIN`, `SDRSCAN_DAST_BIN` | `sdrscan-sast`, `sdrscan-dast` | engine binaries, checked with `--version` at start (exit 2 otherwise) |
| `SDRSCAN_TEMPLATES` | `/opt/sdrscan/templates` | passed as `--templates` to SAST |
| `SDRSCAN_WORKDIR` | `/tmp/sdrscan` | per-job work directories (`scan-<id>-<random>`, mode 0700) |
| `SDRSCAN_WORKERS` | `2` | concurrent scan workers |
| `SDRSCAN_SCAN_TIMEOUT` | `30m` SAST / `60m` DAST | total job timeout (one value sets both) |
| `SDRSCAN_SECRET_KEY` | unset | AES-256 key (32 bytes, base64) for git credentials and DAST credentials; without it they are refused (503) |
| `SDRSCAN_GIT_KNOWN_HOSTS` | unset | `known_hosts` for SSH clones (no trust on first use) |
| `SDRSCAN_GIT_ALLOWED_HOSTS` | all public hosts | comma-separated allow list of git hosts |
| `SDRSCAN_DAST_CA_CERT` | unset | PEM file with the CA(s) trusted for HTTPS DAST targets (for internal CAs); passed as `--ca-cert`. Unset = system trust store |
| `SDRSCAN_DAST_INSECURE_TLS` | `false` | passes `--insecure` to `sdrscan-dast`: target certificates are NOT verified. Unsafe; the scan records a warning. Use only for targets you trust, e.g. a dev environment |
| `SDRSCAN_ALLOWED_HOSTS` | listen address + localhost | accepted `Host` header values |
| `SDRSCAN_COOKIE_SECURE` / `SDRSCAN_TRUST_PROXY` | `true` / `false` | cookie `Secure`; trust `X-Forwarded-For` for the client IP |
| `SDRSCAN_MAX_BODY_MB` / `SDRSCAN_MAX_RESULTS` | `50` / `100000` | ingest limits (after decompression) |
| `SDRSCAN_SECRET_RULES` | `php-hardcoded-secret` | extra rule ids treated as secret rules (layer 1 redaction) |
| `SDRSCAN_VULN_DB` | unset | vulnerability database directory; unset = CVE checks off. Passed as `--vuln-db` to both engines when it exists and the engine lists the flag (probed with `scan --help`, so older engines still work) |
| `SDRSCAN_VULN_BIN` | `sdrscan-vuln` | executable of the Admin update job and of `status` |
| `SDRSCAN_VULN_UPDATE_TIMEOUT` | `60m` | time limit of one update |
| `SDRSCAN_SCA_ENABLED` | `true` | `false` stops passing the database to the engines |
| `SDRSCAN_VULN_CA_CERT` | unset | PEM file with the CAs the updater trusts (`--ca-cert`), for internal proxies / CAs |
| `SDRSCAN_VULN_UPDATE_CRON` | unset | scheduled update (5-field cron, UTC, runs at least 1 h apart); runs on the scheduler leader |
| `SDRSCAN_SCHEDULER_ENABLED` | `true` | switch the scheduler off on an instance |
| `SDRSCAN_SCHEDULE_MIN_INTERVAL_SAST` / `_DAST` | `15m` / `60m` | minimum time between two scheduled runs |
| `SDRSCAN_AUTO_MIGRATE` | `true` | migrate at start |
| `SDRSCAN_LOG_LEVEL` / `SDRSCAN_LOG_FORMAT` | `info` / `text` | `json` for JSON logs |
| `SDRSCAN_WEB_DIR` | unset | serve the frontend from disk |
| `SDRSCAN_ALLOW_PRIVATE_NETWORKS` | `true` | git clones and DAST targets may be on private networks (loopback, RFC 1918, CGNAT, ULA, link-local); `false` refuses them and passes `--block-private-networks` to `sdrscan-dast`. Cloud metadata endpoints (`169.254.169.0/24`, `169.254.170.0/24`, `100.100.100.200`, `fd00:ec2::/32`, `metadata.google.internal`) are always refused. Anyone allowed to register a target can probe your internal network from this server: set `false` on a shared or cloud host |
| `SDRSCAN_TEST_ALLOW_LOCAL_REPOS` | `false` | **test/demo only**: accept local paths and `file://` as `repo_url` |
| `SDRSCAN_TEST_ALLOW_PRIVATE_NETWORKS` | `false` | **test/demo only**: lift the private-network policy and pass `--allow-private-networks-for-tests` to `sdrscan-dast` |

The two `SDRSCAN_TEST_*` switches are off by default, are not in the compose file, and log a warning at every start.

## Implementation decisions (where the TRD left room)

* **Private networks are refused** (loopback, link-local, metadata incl. `metadata.google.internal`, RFC1918, ULA,
  CGNAT, `0.0.0.0/8`, multicast, IPv4-mapped IPv6 normalised) for `repo_url` and `base_url`: literal IPs at save time,
  and the DNS answer (every A/AAAA record must pass) at save time, at job start and, for DAST, at `POST /scans`.
  Error: 422 `address_not_allowed` ("Private network addresses are not allowed."); in a job `error_code = address_not_allowed`.
  Git is pinned to the checked address (`-c http.curloptResolve=host:port:ip` for https; ssh connects to the IP with
  `-o HostKeyAlias=<host>`) and runs with `http.followRedirects=false`. After redirects for DAST the engine is responsible.
* **Visibility of URL codebases** is enforced in the server: `codebaseVisibleTo(user, codebase)` (Go) and the matching SQL filter
  `target_type = 'repo' OR <user is admin or can_run_dast>` in list/total queries. The user row is re-read from the database on
  every request; SSE streams re-check every second and close when access is revoked. See the TRD for the endpoint list; the
  answer is a 404 `not_found` identical to a missing id (tested byte-for-byte). `dast_forbidden` (403) only appears when a
  member without DAST access registers a URL target.
* **Schedules** (`PUT/DELETE /codebases/{id}/schedule`, `POST .../schedule/resume`, `GET /schedules`): one schedule per
  codebase, owner = last user who set or resumed it, status `active|suspended` stored in the database. The scheduler
  (advisory-locked, one tick per minute) queues the latest due cron slot exactly once (`schedule_last_enqueued_at`, slots
  missed during an outage are not back-filled, 90 s tolerance), re-reads the owner's rights and suspends the schedule
  (audit `schedule_suspended`) when the owner is inactive or, for URL targets, is neither Admin nor can_run_dast. A deactivated
  owner, a revoked `can_run_dast` or a demotion also suspends in the same transaction as the user change. A URL target that is
  not `confirmed` is skipped without suspending. Scheduled jobs carry `trigger = 'schedule'` and `requested_by = owner`
  and the runner re-checks the owner just before a scheduled DAST run (`error_code = schedule_suspended`).
  `PATCH /codebases/{id}` refuses `schedule_cron` (use the schedule endpoints); `POST .../codebases` still accepts it once.
* Migrations: `0001_init.sql` (the 10 tables of the TRD), `0002_schedule.sql` (schedule ownership columns; idempotent,
  upgrades a database that already ran 0001) and `0003_vulnerability.sql` (CVE columns on `findings`, see "Vulnerabilities").
* Scans from the web are always full (`coverage = 'full'`); the runner never passes `--files-from`; the engine's exit codes
  0 and 1 are both success and `--fail-on` is not used as a gate. Partial scans (`run.properties.scanKind = partial` +
  `scannedFiles`) are only accepted from CI and need a full scan first (409 `baseline_required`). The current engine does not
  write that property yet, so partial scans are exercised with synthetic SARIF in the tests.
* The runner passes only flags the engine supports: it probes `scan --help` once, so `--max-rps` / `--templates` are sent to
  `sdrscan-dast` only if the binary lists them (today it does not).
* Duplicates: same SHA-256 + codebase + `ref` (a missing `ref` matches on the hash alone). A runner job whose SARIF is identical
  to an older scan ends `succeeded` with `duplicate_of_scan_id` and is left out of the history, compare and "latest".
* DAST findings keep the evidence from `properties.evidence` as `snippet` (engine SARIF has no region for URLs); the location
  URL must be on the host of `base_url` (`location_outside_target`).
* Ingest token prefix: `token_prefix` stores the first 12 characters of the token (`sdrscan_` + 4 random characters), since the
  first 8 characters would always be `sdrscan_`. `POST /ingest-tokens` answers `{token, secret}`.
* Passwords: Argon2id (m=19 MiB, t=2, p=1), 12-128 characters, 4 concurrent verifications; per-account lock (5 failures, 15 min,
  in the database) and per-IP limit (20/min, in memory). Sessions are cookie `sdrscan_session` (HttpOnly, SameSite=Strict,
  Secure by default), 8 h idle / 7 d absolute, only the SHA-256 is stored. Writes need `X-CSRF-Token`, an `Origin` equal to
  `Host`, and `Content-Type: application/json`.
* `GET /codebases` (all projects, `project_id` and `target_type` filters) exists in addition to the TRD table because the UI lists
  codebases across projects. The finding list omits `snippet` (use `GET /findings/{id}`).
* A private repo/host is a plain failure on purpose for CI-only targets: use ingest for them.

## Vulnerabilities (CVE)

Besides code findings, a SARIF result may carry `properties.vulnerability` (written by the engines when they were given
a vulnerability database): a dependency in a lockfile (SCA: `composer.lock`, `package-lock.json`, `yarn.lock`, `go.sum`,
`Cargo.lock`) or a product version found on a DAST target. The finding keeps its identity (`partialFingerprints`, occurrence,
compare, duplicates by SARIF hash are unchanged); `ruleId` is the CVE or advisory id.

* **Storage** (migration `0003_vulnerability.sql`): `findings.vulnerability JSONB` (NULL for code findings) and
  `findings.vuln_ids TEXT[]` (CVE first, then GHSA/OSV aliases) with a GIN index and a shape constraint. Old rows are untouched:
  they read as `kind: "code"`, `vulnerability: null`.
* **Validation at ingest** (never fails the ingest): the object is read field by field. Ids must be CVE / GHSA / OSV-shaped (CVE
  upper case, GHSA lower-case suffix, max 20; falls back to a canonical `ruleId`), `package` is `{ecosystem,name,version}` or
  `{product,version}`, `fixed_versions` max 20, `source` osv|nvd, `references` http/https only with a host and no userinfo, max 5,
  `cvss` `{score 0-10, vector?}`, `confidence` high|low, `scope` runtime|dev. Anything invalid is dropped; if no valid id remains
  (or the object is not an object / over 64 KiB) the result is stored as a plain finding and counted in the response as
  `vulnerability_ignored` (`vulnerability_findings` counts the CVE findings). Redaction applies to message and snippet only.
  Severity: `security-severity` of the result or rule, else the CVSS score, else the SARIF level.
* **Confidence (product decision).** A CVE finding is never "low confidence" in the sense of the existing rule (which hides ambiguous
  SAST taint warnings): the backend stores it with finding `confidence = normal` even when the SARIF result says `low`, so it is
  listed by default and counted in severities, Codebase/Project summaries and compare. `vulnerability.confidence` (e.g. a
  version-based DAST match) is kept and returned; the UI shows it. `confidence=high|low` and `scope=runtime|dev` filter on the
  CVE object; dev dependencies are reported and counted.
* **API.** Finding list items, compare items and `GET /findings/{id}` carry `kind` (`code`|`vulnerability`) and `vulnerability`
  (the object above with every key present, or `null`). Filters: `kind`, `cve` (exact, any id of the finding, case-insensitive, 400
  when malformed), `confidence`, `scope`; `q` also matches advisory ids and package/product names. `facets` gains `kind {code,
  vulnerability}`, `cve [{id,count}]` (CVE ids, top 100), `vulnerable_packages` (distinct package@version), `confidence`, `scope`.
  Visibility is unchanged: DAST CVE findings belong to a URL codebase and are 404 for members without DAST access like every
  other finding of that codebase; there is no cross-codebase CVE search endpoint.
* **Runner.** With `SDRSCAN_VULN_DB` set, existing, and `SDRSCAN_SCA_ENABLED` not false, SAST and DAST scans get
  `--vuln-db <dir>` if the engine supports it; otherwise the job log says why CVE checks were skipped (the path is not logged).
* **Database management (Admin).** `GET /system/vulndb` runs `sdrscan-vuln status --json --db <dir> --max-age-days 7` and maps its
  output (format_version 1: `advisory_count`, `age_days`, `max_age_days`, `stale`, `updated_at`, `osv.<Ecosystem>{advisories,
  age_days,updated_at}`, `nvd{entries,age_days,updated_at,last_modified,products[]}`) to `status {installed, advisory_count,
  updated_at, age_days, max_age_days, format_version, sources[{name osv|nvd, ecosystem, advisories, updated_at, age_days,
  products}]}`; `stale` and `stale_after_days` come from the CLI. A directory without `meta.json` is reported as not installed
  (`status.installed = false`) without running the tool, because the real CLI exits 2 with a message in that case; any other
  failure (e.g. a broken `meta.json`) becomes `status_error` with a 200 answer.
  `POST /system/vulndb/update` runs `sdrscan-vuln update --db <dir> [--ecosystems A,B] [--nvd] [--ca-cert <pem>]` as one background job: argument
  array, no shell, clean environment (only `SDRSCAN_VULN_DB`, `HOME`/`TMPDIR` of a temporary directory, proxy / CA variables and the
  optional `NVD_API_KEY`), process group killed on cancel or `SDRSCAN_VULN_UPDATE_TIMEOUT`, bounded log (16 KiB tail, URL userinfo and
  control sequences removed), one update at a time in the process and, through a PostgreSQL advisory lock, across instances. OSV covers
  SCA; `nvd: true` additionally fetches NVD data, which only DAST (CVEs of web server banners) needs. The latest job
  (state, log, exit code, `error_code` `update_failed|timeout|cancelled|tool_not_found`) is kept in memory and returned by `GET`, so it
  is gone after a restart (the data age comes from `status`). Audit actions: `vulndb_update_started`, `vulndb_update_finished`,
  `vulndb_update_cancelled`. The backend never contacts the feeds itself. `SDRSCAN_VULN_CA_CERT` (PEM of the CAs the updater trusts,
  `--ca-cert`) is for internal proxies.
* **Engine warnings.** The engines print `peringatan: ...` lines on stderr (database older than 30 days, SCA skipped because the database
  is missing or unusable). They never fail a scan (exit codes 0/1 stay success); up to five are copied into the job log as
  `engine warning: ...` with the database path replaced by a placeholder.
* **Limits.** SCA for Go works from `go.sum` and may over-report (a listed module can be unused). Updating while a scan reads the
  database is the tool's job to make safe (atomic replacement).

## Authenticated DAST and crawling

A URL target can log in before the scan and crawl the site passively. Both are settings of the **Codebase URL**
(Admin or Member with `can_run_dast`; everyone else gets the same 404 as for a missing id). Credentials always reuse
the git-credential machinery: AES-256-GCM with `SDRSCAN_SECRET_KEY` (no variable is new; without the key `PUT .../dast-auth`
answers 503 `secret_key_required`), write-only API.

* **Types**: `form` (login form or JSON login), `header` (fixed headers and/or cookies), `form+header`. `none` is the absence of
  settings (`DELETE`). Use a **test account with minimal rights**: the scan only sends GET requests, but whatever the account
  may open is requested, and the crawl follows links.
* **`PUT /codebases/{id}/dast-auth`** replaces the configuration. Body:

  ```json
  {"type": "form+header",
   "login": {"url": "https://shop.example.com/login", "method": "POST", "body_format": "json",
             "username_field": "user", "password_field": "password", "username": "tester", "password": "***",
             "extra_fields": {"remember": "1"},
             "csrf": {"source": "html_input", "name": "_csrf", "send_as": "field"},
             "token": {"from": "json", "path": "data.access_token", "send_as": "header", "header_name": "Authorization", "prefix": "Bearer "},
             "success": {"statuses": [200, 302], "cookie_set": "sid", "body_contains": "Welcome",
                         "body_not_contains": "Invalid", "redirect_not_to": "/login",
                         "json_path_exists": "data.access_token", "json_path_equals": {"path": "status", "value": "ok"}}},
   "headers": {"Authorization": "Bearer ***"}, "cookies": {"sid": "***"}}
  ```

  `csrf.source` is `html_input|cookie|header`, `csrf.send_as` is `field|header` (`header_name` then required); `method` is
  `POST|PUT|PATCH` (default POST), `body_format` `form|json` (default form). `token` (optional) tells the engine to read a token from
  the login response (`from` `json|header`, default json; `path` is a dotted JSON path such as `data.access_token` or `items[0].token`,
  at most 200 characters, or a response header name) and send it on every later request to the target origin (`send_as`
  `header|cookie`; `header_name` default `Authorization` and not a forbidden header; `prefix` at most 32 ASCII characters without CR/LF,
  default `Bearer ` for Authorization, `""` means none; `cookie_name` required for cookie). It is for JavaScript apps whose login API
  returns the token in the body: `login.url` must then be that API endpoint. Only these settings are stored (the token is dynamic and
  never stored or returned). `success.json_path_exists` / `success.json_path_equals` (`{path, value}`) check the login response body.
  Field errors name `login.token.path`, `login.token.header_name`, `login.token.prefix`, `login.token.cookie_name`,
  `login.token.from`, `login.token.send_as`, `login.success.json_path_exists`, `login.success.json_path_equals.path|value`.
  Tokens the engine obtained at login are not in the stored secrets, so the job log and login-check message also mask
  `Bearer <token>` values and JWTs by pattern. A blank `password`, header/cookie value or
  extra-field value **keeps the stored one with the same name**, so non-secret settings can be edited without retyping
  secrets. The response (and `GET`, and `dast_auth` inside `GET /codebases/{id}`) is the non-secret description:

  ```json
  {"type": "form+header", "has_secret": true, "login_url": "https://shop.example.com/login", "method": "POST",
   "body_format": "json", "username_field": "user", "password_field": "password", "username": "tester",
   "extra_field_names": ["remember"], "csrf": {"source": "html_input", "name": "_csrf", "send_as": "field", "header_name": null},
   "token": {"from": "json", "path": "data.access_token", "send_as": "header", "header_name": "Authorization", "prefix": "Bearer ", "cookie_name": null},
   "success": {"statuses": [200, 302], "cookie_set": "sid", "body_contains": "Welcome", "body_not_contains": "Invalid", "redirect_not_to": "/login",
               "json_path_exists": null, "json_path_equals": null},
   "header_names": ["Authorization"], "cookie_names": ["sid"], "updated_at": "2026-10-28T08:00:00Z",
   "updated_by": {"id": 3, "username": "dewi"}}
  ```

  No password, token, header value, cookie value or extra-field value is ever returned, logged or written to the audit log.
  Validation: the login URL must have the **same origin** (scheme, host, port) as `base_url` and pass the network policy;
  no CR/LF or control characters; header names are HTTP tokens (not `Host`, `Cookie`, `Content-Length`, `Transfer-Encoding`,
  `Connection`, `Proxy-*`, `Sec-*` ...); at most 10 headers, 10 cookies and 20 extra fields; values at most 4 KiB (secrets at least
  4 characters, so they can be redacted); the whole configuration at most 16 KiB.
* **`POST .../dast-auth/test`** runs `sdrscan-dast scan <base_url> --auth-file ... --login-check` synchronously (30 s) and returns
  `{ok, message}`; the message is the engine's summary with every credential value replaced by `[REDACTED]`. Only for
  `confirmed` targets with a login form (header-only configurations have nothing to test: 409 `no_login_configured`); one test at a time per target. Audit `dast_auth_tested` records the outcome only.
* **Crawl** settings are part of `PATCH /codebases/{id}`: `dast_crawl_enabled` (default false), `dast_crawl_max_depth` (1..10,
  default 3), `dast_crawl_max_pages` (1..500, default 50), `dast_crawl_exclude` (at most 20 regular expressions of at most 200
  characters, Go/RE2 syntax which is linear-time: look-around and back-references are rejected with 422). They are returned as
  `dast_crawl: {enabled, max_depth, max_pages, exclude}`. The engine always skips its built-in paths (logout, delete, ...) in
  addition. Repository targets have `dast_auth: null, dast_crawl: null`.
* **Origin changes**: `PATCH base_url` to another scheme/host/port **deletes the stored credentials** and (as before) resets the
  confirmation; the runner also refuses to send credentials whose login URL no longer matches the target origin
  (`error_code = auth_unreadable`). A path-only change keeps them.
* **Runner**: for a DAST job with credentials the runner decrypts them, writes `auth-*.json` (mode 0600, version 1 document, see
  below) inside the job's 0700 work directory, passes `--auth-file <path>` and removes the file the moment the engine exits
  (also on timeout, cancel and panic; leftovers of a crash are swept at start-up). Credentials are **never** in argv or in the
  environment. Crawling adds `--crawl --max-depth N --max-pages N` and one `--exclude-path <regex>` per pattern. Scheduled
  scans use the same stored settings. The runner probes `scan --help`: an engine without `--auth-file` fails an authenticated
  target with `error_code = engine_unsupported` (it never scans without the login silently); an engine without `--crawl` runs
  without crawling and says so in the job log; one that cannot honour `--max-depth/--max-pages/--exclude-path` fails with
  `engine_unsupported` (exclusions are never dropped).
* **Redaction**: every known secret (and its JSON, URL and Base64 encodings, and the token part of `Scheme token` headers) is
  replaced by `[REDACTED]` in `log_tail`, error messages and in the SARIF before it is ingested.
* **Job log**: `authenticated scan (form+header)`, `crawl enabled (max depth 3, max pages 50, 2 excluded patterns)` and, when the
  engine's stderr summary has a line like `Ringkasan: 12 halaman dipindai, 3 temuan, 0 peringatan`, `scan summary: 12 pages scanned`.
* **Audit**: `dast_auth_set`, `dast_auth_deleted` (also when an origin change removed them), `dast_auth_tested`,
  `dast_crawl_updated`.
* Engine file (`--auth-file`, JSON, `{"version":1,"login":{"type":"form","url","method","body_format","username_field",
  "password_field","username","password","extra_fields","csrf","success"},"headers":{},"cookies":{}}`) follows the engine contract;
  `login`, `headers` and `cookies` are each optional.
* Migration `0004_dast_auth.sql` adds `dast_auth_type`, `dast_auth_enc`, `dast_auth_meta` and `dast_crawl_*` with CHECK constraints
  (type values, auth shape, depth, pages, 20 patterns of at most 200 characters, crawl only on URL targets); down drops them.

## Active scanning (payload-sending DAST)

**This is a risky feature. Only enable it for applications you own or are explicitly authorized to test against,
and prefer a staging or test environment over production.** Active scanning sends SQL injection, reflected XSS, open
redirect and header-injection test payloads to parameters found on the target (GET query parameters, and **HTML POST
forms found by the crawler** — SQL injection testing now also submits those, not only GET). It can also exercise the
target's **API endpoints** (GET/POST/PUT/PATCH — never DELETE) when an OpenAPI/Swagger spec is auto-discovered during
the crawl or explicitly configured, sending the same kind of test payloads in **JSON request bodies**, not only in URLs
and HTML form fields. Any of this **may create, modify or delete real data** on an application that mutates state via
GET, that exposes state-changing POST/PUT/PATCH forms or API operations without a confirmation step, or that has no
separation between a database used for testing and one used for anything that matters. Time-based SQL injection checks
(`--active-timing`, a second, separate opt-in) additionally add load to the target server. **Treat active scanning as
an intrusive penetration-testing action, not a routine scan**, and never point it at a system you do not fully control
or whose owner has not explicitly authorized active testing.

Because of this, active scanning requires a **separate, stricter authorization layer** on top of the basic DAST target
confirmation (`dast_status = 'confirmed'`, see above): without it, a DAST scan always stays passive (read-only checks),
whatever is requested — the scan request itself is rejected rather than silently downgraded.

* **`POST /codebases/{id}/authorize-active-scanning`** (Admin or Member with `can_run_dast`; Codebase URL only, same
  visibility as `dast-auth`: everyone else gets the same 404 as a missing id; a repository codebase is 409
  `not_a_url_target`; the target must already be `confirmed`, otherwise 409 `target_not_confirmed`). Body
  `{"statement_accepted": true, "codebase_name": "<the codebase's exact name>"}`: the caller must also retype the
  codebase name, as deliberate friction for a riskier action than the basic confirmation (wrong name: 422
  `validation_failed`, `details.field = "codebase_name"`; statement not accepted: 422, `details.field =
  "statement_accepted"`). On success (200, the updated `GET /codebases/{id}` shape) the server stores who authorized it
  and when, and the accepted statement text (for audit; it is not a secret). Audit `dast_active_authorized`.
* **`DELETE /codebases/{id}/authorize-active-scanning`** revokes it (204, idempotent, no audit row when it was already
  unauthorized). Audit `dast_active_revoked`.
* **`GET /codebases/{id}`** carries `dast_active: {authorized, authorized_at, authorized_by, openapi_spec_url}` for URL
  targets (`null` for repositories). `openapi_spec_url` is the optional OpenAPI/Swagger spec location (see below), or
  `null` when relying on auto-discovery only.
* **Optional OpenAPI/Swagger spec**: `PATCH /codebases/{id}` also takes `dast_openapi_spec_url` for URL targets (Admin
  or `can_run_dast`): a URL on the **same origin** as `base_url` (same validation as the login URL), or `null`/empty to
  clear it and rely on auto-discovery during the crawl alone. Stored in `dast_openapi_spec_url`; like the DAST
  credentials, it is tied to the target's origin and is cleared whenever `base_url` changes to another origin.
* **`POST /scans`** takes two optional booleans for `codebase_id` of a URL target: `active` (default false) and
  `active_timing` (default false, meaningful only together with `active`). Validation, in order: `active_timing` true
  without `active` true is 422 `validation_failed` (`details.field = "active_timing"`); the target must be `confirmed`
  (409 `target_not_confirmed`, same check as any DAST scan); `active` true additionally requires the authorization
  above, otherwise 409 `active_scanning_not_authorized`. A scheduled scan never supports `active`/`active_timing`:
  `PUT /codebases/{id}/schedule` rejects the body with 422 (`details.field = "active"` or `"active_timing"`) rather
  than silently ignoring it — scheduled DAST scans always stay passive. The flags are recorded on the `scans` row
  (`active`, `active_timing`) so the history and a re-run never inherit them silently, and are included in the scan DTO.
* **Runner**: for an `active` job the runner probes `scan --help` (same mechanism as `--auth-file`/`--crawl`) and
  passes `--active` (and `--active-timing`); an engine without the flag fails the job with `error_code =
  engine_unsupported` rather than running passively without telling anyone. When a spec URL is configured and the job
  is active, `--openapi-spec <url>` is added too, but only if the engine advertises support for it (otherwise the scan
  still runs, without the spec, and the job log says so — like `--templates` or `--vuln-db`). The job log records
  `active scanning authorized by <username> on <date>, type: boolean/error-based/XSS/open-redirect/header-injection`
  (with `/time-based` appended when `--active-timing` was used) and, when the engine's stderr summary has a line such
  as `N active requests sent` (or `N permintaan aktif dikirim`), the same line is copied into the job log.
* **New SARIF rules**: `dast-active-sqli-error-based`, `dast-active-sqli-boolean-blind`, `dast-active-sqli-time-based`,
  `dast-active-xss-reflected`, `dast-active-open-redirect-confirmed`, `dast-active-header-injection` (produced by the
  engine, not the backend).
* Migration `0005_dast_active.sql` adds `dast_active_authorized_at/by/statement` to `codebases` (CHECK: only meaningful
  for `target_type = 'url'`, and all three set together or all null) and `active`, `active_timing` to `scans` (default
  false); down drops them. Migration `0006_dast_openapi.sql` adds the nullable `dast_openapi_spec_url` to `codebases`
  (CHECK: only on `target_type = 'url'`); down drops it.

## Endpoints

Auth column: `-` open, `session` login, `+csrf` CSRF header on writes, `admin` Admin only, `token` ingest token.
All lists answer `{items, total, page, page_size}` (`?page=1&page_size=50`, max 200). Errors are
`{"error": {"code", "message", "details", "request_id"}}`.

### Validation errors

Every error about the input of a request names the field that is wrong, so a form can show the message under that field.
The name is the JSON name of the field. Objects use a dotted path (`login.password`, `login.csrf.name`, `headers.Authorization`,
`cookies.sid`, `login.extra_fields.tenant`) and list elements an index (`dast_crawl_exclude[2]`, `login.success.statuses[1]`,
`ecosystems[0]`). A header, cookie or field whose *name* is itself invalid is reported on the group (`headers`, `cookies`,
`login.extra_fields`), with the name quoted in the message.

One wrong field: `details.field`.

```json
{"error": {"code": "validation_failed", "message": "repo_url is required.", "details": {"field": "repo_url"}, "request_id": "..."}}
```

Several wrong fields (all of them are checked before answering): `details.fields` lists every failure in page order;
`message` and `details.field` stay those of the first one, so a client that knows nothing of the list still shows a useful error.

```json
{"error": {"code": "validation_failed", "message": "name is required.", "details": {
  "field": "name",
  "fields": [{"field": "name", "message": "name is required."}, {"field": "repo_url", "message": "repo_url is required."}]}}}
```

* `details.fields` is present only when two or more fields failed. An entry carries `code` when the failure has a specific code
  (`address_not_allowed`, `invalid_cron`, `schedule_too_frequent`); a single failure keeps that code as `error.code`
  (the status is 422 and the field is in `details.field`), several failures answer `validation_failed`.
* Conflicts that belong to a field name it too: `409 name_taken` (`details.field = "name"`), `409 username_taken` (`"username"`).
  `project_id does not exist` is `details.field = "project_id"`. Query parameters of `GET` lists are reported the same way with
  a `400 bad_request` (`page_size`, `kind`, `severity`, ...).
* Fields checked together: create/update Codebase (`name`, `language`, `target_type`, `repo_url`, `base_url`, `branch`, `subdirectory`,
  `git_auth_kind`, `git_username`, `git_secret`, `dast_max_rps`, `schedule_cron`, `project_id`, `dast_crawl_*`, `dast_openapi_spec_url`),
  `PUT /codebases/{id}/dast-auth` (every field of the login form, each header and cookie, success indicators, CSRF), crawl settings
  (numbers and every exclusion row), `POST .../authorize-active-scanning` (`statement_accepted`, `codebase_name`), `POST /scans`
  (`active`, `active_timing`), create user (`username`, `role`, `password`), change password (`current_password`, `new_password`),
  ingest token (`name`, `project_id`), Project (`name`, `description`), login (`username`, `password`: `422` when one is empty;
  wrong credentials stay `401 invalid_credentials`), vulnerability database update (`ecosystems[i]`).
* The schedule endpoint (`PUT /codebases/{id}/schedule`) names the field `cron` (`schedule_cron` when it is part of a Codebase body).
* Messages say what is wrong ("repo_url is required.", "Password must be at least 12 characters.", "Pattern 3 is not a valid regular
  expression: ..."); they never contain a secret value.
* Errors that are not about one input (401/403/404/409 state conflicts such as `target_not_confirmed`, 5xx) carry no `details.field`.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `/healthz` | - | `{"status":"ok"}` / 503 |
| POST | `/auth/login` | - | 200 `{user, csrf_token, must_change_password}`; 401 `invalid_credentials`; 429 `login_throttled` |
| POST | `/auth/logout` | session+csrf | 204 |
| GET | `/auth/me` | session | `{user, csrf_token, must_change_password}` |
| POST | `/auth/password` | session+csrf | 204; revokes other sessions |
| GET, POST | `/users` | admin | create sets `must_change_password` |
| PATCH | `/users/{id}` | admin | `{role, is_active, can_run_dast}`; 409 `last_admin`; suspends owned schedules |
| POST | `/users/{id}/reset-password` | admin | 204; revokes sessions |
| GET | `/audit-log` | admin | |
| GET, POST | `/projects` | session | `codebase_count`, `totals`, `highest_severity` from visible codebases |
| GET, PATCH | `/projects/{id}` | session | GET = dashboard `{project, totals, codebases}` |
| DELETE | `/projects/{id}?confirm=<name>` | admin | 200 `{deleted}`; 422 `confirmation_required` / `confirmation_mismatch` |
| GET | `/codebases` | session | |
| POST | `/projects/{id}/codebases` | session+csrf | URL targets: Admin or `can_run_dast`; `pending_confirmation` |
| GET, PATCH | `/codebases/{id}` | session | PATCH `base_url` resets the confirmation and active-scanning authorization (and, when the origin changes, deletes the DAST credentials and OpenAPI spec URL); PATCH also takes `dast_crawl_*` and `dast_openapi_spec_url` for URL targets |
| DELETE | `/codebases/{id}?confirm=<name>` | admin | |
| POST | `/codebases/{id}/confirm-authorization` | admin | `{statement_accepted: true}`; 409 `not_a_url_target` |
| PUT, DELETE | `/codebases/{id}/schedule` | session+csrf | PUT `{cron}`; 422 `invalid_cron`, `schedule_too_frequent`, or `active`/`active_timing` (scheduled scans are always passive); DELETE 204 |
| POST | `/codebases/{id}/schedule/resume` | session+csrf | 409 `schedule_not_suspended` |
| GET | `/schedules` | session | `?status=active\|suspended` |
| GET, PUT, DELETE | `/codebases/{id}/dast-auth` | session+csrf | URL targets, Admin or `can_run_dast` (404 for others); see "Authenticated DAST". PUT 200 (meta), DELETE 204; 422 `validation_failed`, `address_not_allowed`; 503 `secret_key_required`; 409 `not_a_url_target` |
| POST | `/codebases/{id}/dast-auth/test` | session+csrf | login check, 30 s, confirmed targets only: 200 `{ok, message}`; 409 `target_not_confirmed`, `no_auth_configured`, `no_login_configured`, `test_in_progress`; 501 `engine_unsupported` |
| POST, DELETE | `/codebases/{id}/authorize-active-scanning` | session+csrf | URL targets, Admin or `can_run_dast` (404 for others); see "Active scanning". POST `{statement_accepted, codebase_name}` -> 200 (the codebase); 422 `validation_failed` (`statement_accepted`, `codebase_name`); 409 `target_not_confirmed`, `not_a_url_target`. DELETE 204 (idempotent) |
| POST | `/scans` | session+csrf | `{codebase_id, active?, active_timing?}` -> 202 queued; 409 `scan_in_progress`, `target_not_confirmed`, `active_scanning_not_authorized`; 422 `active_timing` without `active`; 404 for invisible URL codebases |
| GET | `/scans/{id}` | session | status, summary, `log_tail`, `error_code` |
| GET | `/scans/{id}/events` | session | SSE: `event: status` / `event: log` |
| POST | `/scans/{id}/cancel` | session+csrf | 202 / 409 |
| GET | `/codebases/{id}/scans` | session | history (`?status=`) |
| GET | `/codebases/{id}/compare` | session | `?base=&head=&status=new\|unchanged\|fixed` |
| GET | `/codebases/{id}/findings`, `/scans/{id}/findings` | session | `severity`, `rule`, `path`, `q`, `include_low_confidence`, `sort=severity`, `kind=code\|vulnerability`, `cve=<advisory id>`, `confidence=high\|low`, `scope=runtime\|dev`; `facets` |
| GET | `/codebases/{id}/files`, `/scans/{id}/files` | session | per file (per URL for DAST) |
| GET | `/findings/{id}` | session | full finding with snippet |
| POST | `/ingest?project=&codebase=&ref=&started_at=` | token | 201 / 200 `duplicate` / 404 with suggestions / 409 `baseline_required` / 413 / 415 / 422 |
| POST | `/codebases/{id}/ingest` | token | same, by id |
| GET, POST | `/ingest-tokens` | admin | POST `{name, project_id?}` -> `{token, secret}` (secret shown once) |
| DELETE | `/ingest-tokens/{id}` | admin | revoke, 204 |
| GET | `/system/info` | session | versions, queue (DAST jobs hidden from members without access) |
| GET | `/system/vulndb` | admin | vulnerability database: configuration, `sdrscan-vuln status` (age and advisory count per source), latest update job |
| POST | `/system/vulndb/update` | admin+csrf | `{ecosystems?: ["Packagist","npm","Go","crates.io"], nvd?: bool}` -> 202 `{update}`; 409 `vulndb_not_configured`, `vuln_tool_unavailable`, `update_in_progress`; 422 unknown ecosystem |
| POST | `/system/vulndb/update/cancel` | admin+csrf | 202 `{update}`; 409 `no_update_running` |

### Ingest from CI

```bash
sdrscan-sast scan . --format sarif --output sdrscan.sarif --fail-on high; rc=$?
curl --fail-with-body --silent --show-error --retry 3 \
  -X POST "$SDRSCAN_URL/api/v1/ingest?project=Online%20Shop&codebase=storefront&ref=$GIT_COMMIT" \
  -H "Authorization: Bearer $SDRSCAN_TOKEN" -H "Content-Type: application/json" \
  --data-binary @sdrscan.sarif
exit $rc
# large files: gzip -c sdrscan.sarif | curl ... -H "Content-Encoding: gzip" --data-binary @-
```

## Tests

`go test ./...` talks to a real PostgreSQL: it creates `sdrscan_test_<random>` databases (and drops them) through
`SDRSCAN_TEST_DATABASE_URL` (default: the local dev URL above). The end-to-end tests use the real engines from `../dist`
and skip with a message when they are missing. The suite covers the schema constraints, SARIF reading, ingest (valid/invalid/
duplicate/partial/redaction/rollback/concurrency/current-state invariants), the authorization matrix generated from the router,
the URL-codebase visibility matrix, DTO shapes against the TRD examples, auth/CSRF/sessions, schedules and the scheduler,
the runner (queue, cancel, timeout, lost workers, shutdown, clone safety, credential handling, real SAST on the fixtures,
real DAST on an `httptest` server, authenticated DAST with a fake engine that records argv, environment and the 0600 auth file,
plus an end-to-end test against a loopback login site that is skipped until `dist/sdrscan-dast` supports `--auth-file`), CVE findings (SARIF validation, ingest, filters, facets, visibility, migration from the old schema), active scanning
(authorization endpoint, revoke, the `confirmed` -> `active_scanning_not_authorized` validation order of `POST /scans`, the
schedule rejecting `active`/`active_timing`, the `--active`/`--active-timing`/`--openapi-spec` flags only ever reaching the
engine when explicitly requested and only when it advertises support, plus an end-to-end test against the real
`dist/sdrscan-dast` that is skipped until it supports `--active`) and the
vulnerability database job (a fake `sdrscan-vuln` script from `internal/testutil`; no CVE data is ever downloaded). `go vet ./...` and `gofmt -l .` must be clean.
