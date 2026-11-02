# PermiScan

Access-control, authorization, and data-exposure auditing for databases, BaaS platforms
(Supabase, Firebase), and cloud infrastructure — plus a local web platform to **browse and
visualize** exactly what each misconfiguration exposes, without writing a single query by
hand.

*[Leia em português](README.pt-BR.md)*

The project's principle: **check whether the authorization mechanisms actually stop
unauthorized access**, not just whether a security feature is switched on. A table with no
policies isn't automatically vulnerable; a `USING (true)` policy doesn't matter if no
exposed role has a privilege on the table. Every PermiScan rule cross-references the
configuration against the **effective privileges** of the roles the application exposes.

> **Authorized use only.** Every command takes the target explicitly (the DSN, the project
> URL, or the rules file you point it at). Use it on systems you own or that you have
> express authorization to assess. See [SECURITY.md](SECURITY.md).

## Quickstart

Nothing installed yet? That's fine — here's the whole path from a clean machine to the
dashboard open in your browser.

**1. Install [uv](https://docs.astral.sh/uv/)** (a single binary; it also manages Python for
you, so you don't need Python installed beforehand):

```sh
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**2. Get the code and install dependencies:**

```sh
git clone https://github.com/cerva-coder/permiscan.git
cd permiscan
uv sync
```

`uv sync` downloads a matching Python 3.12+ on its own if you don't have one — there's
nothing else to install first.

**3. Run it:**

```sh
uv run permiscan serve
```

Opens `http://127.0.0.1:8080` with the dashboard shown below, ready to scan. Or run
`uv run permiscan` with no arguments for the interactive menu instead.

Docker is only needed for the optional [local lab](#local-lab) used to test the PostgreSQL
rules — not for scanning or the web platform.

## What this is for

Most scanners stop at "found a misconfigured Supabase table" and leave you to write curl
commands to see what it actually exposes. PermiScan goes one step further with a local web
platform: run a scan from the browser, and it opens a workspace where the exposed
collections, Storage buckets, and Realtime Database nodes are already **navigable as
clickable chips and breadcrumbs** — no prefix or path to type, no query to hand-craft. It's
both the scanner *and* the viewer for what the scanner found.

### Dashboard: scan and triage from the browser

![Dashboard](docs/screenshots/dashboard.jpg)

Run an individual scan or a mass triage of a URL list straight from the page — no CLI
needed. Targets are listed with severity pills, filterable by platform/status/severity, and
sortable by recency, finding count, or severity.

### Explore tab: navigate what's exposed, automatically

![Explore: Firestore collections as clickable chips](docs/screenshots/explore-firestore.jpg)

Collections the scan already confirmed are public show up first as chips — click one and its
documents load immediately. Firebase Storage buckets are the same: folders (`prefixes`) are
clickable, with a breadcrumb to go back, and every file gets a direct download link.

![Explore: Storage bucket folder navigation with breadcrumb](docs/screenshots/explore-storage.jpg)

### Evidence and a shareable report

![Evidence tab with finding detail and reproducible PoC](docs/screenshots/evidence.jpg)

Every finding keeps its raw evidence, a reproducible PoC (a `curl` you can paste), and a
remediation summary. The Report tab turns all of it into a print-ready HTML page (Ctrl+P →
PDF) or a downloadable JSON, ready to hand to whoever owns the fix.

![Technical report tab](docs/screenshots/report.jpg)

The "Authorization tests" tab goes one step further for Supabase targets: it can test
whether the anonymous role can write (gated behind an explicit checkbox) and diff read
access between the `anon` role and a synthetic `authenticated` user, to evidence an RLS gap
directly — both intrusive probes, off by default.

## Provider status

| Provider | Status | What exists today |
|---|---|---|
| Supabase (database) | Static analysis available | RLS, policies, effective privileges of `anon`/`authenticated`, views, materialized views, `SECURITY DEFINER` functions. Validated against the local lab emulating Supabase's roles; **not yet validated against a real Supabase project**. |
| Supabase (Data API) | Dynamic tests available | External scan with URL + anon key: discovers tables/RPCs via OpenAPI, observes anonymous reads, and under a flag, tests writes and RPC calls. Detects a `service_role` key on the client and extracts credentials from a page/bundle (`detect`). |
| PostgreSQL | Static analysis available | Same rules as the database analysis, with user-chosen roles and schemas, including table ownership that nullifies RLS. Validated on PostgreSQL 17. |
| Firebase | Static analysis available | Firestore, Storage, and Realtime Database Security Rules. Dynamic tests with the Emulator: planned. |
| Neon, MongoDB Atlas, Appwrite, PocketBase, AWS, GCP | Planned | Priority 2. |
| Azure, Hasura, Directus, Cloudflare, and others | Planned | Priority 3. |

The Data API scan observes real behavior (`confirmed` confidence); catalog and rules
analysis is static (confidence tops out at `likely`). Dynamic database validation with
synthetic identities doesn't exist yet.

## Usage

### Interactive menu (no arguments)

Run `permiscan` with nothing. It only asks for the **mode** and the **scan level** — the
rest is automatic:

```sh
uv run permiscan
```

```
  1  Single scan            one URL, fully automatic
  2  Mass scan               triage a list of sites
  3  Explore a saved list    digs deeper into the targets found in the triage
  4  Web platform            opens the saved-targets dashboard in the browser
  0  Exit
```

- **Single scan**: give it a URL; it identifies the stack and digs in on its own (enumerates,
  and at level 3, extracts samples).
- **Mass scan**: give it a list of sites; quickly triages which ones have Firebase/Supabase
  and saves the result to JSON.
- **Explore a saved list**: takes the triage's JSON and digs deeper only into the targets
  that had resources.
- **Web platform**: opens the browser-based dashboard described above, with every saved
  target. From there you can also launch new scans — you don't need the CLI again once this
  is running.

**Levels** (the only thing asked before running):

| Level | What it does | Alters the target? |
|---|---|---|
| 1 minimal | identifies stack, config, endpoints | no |
| 2 medium | + enumerates and reads (tables, collections, Storage, RTDB) | no |
| 3 maximum | + extracts samples, tests writes/RPC and open signup | yes (active) |

The argument-based commands below still work for scripts and CI (including
`recon --level N`).

### Web platform directly (`permiscan serve`)

Skip the menu and open the dashboard straight away:

```sh
uv run permiscan serve
```

Opens `http://127.0.0.1:8080` and launches your browser. Runs entirely on your own machine
reading your own local `permiscan.db` — nothing leaves it. `--port`, `--host`, and
`--no-browser` are available if you need them.

### Automatic recon (just the URL)

Identifies the stack, discovers exposed endpoints and credentials, and routes to the fitting
analyses — without you naming the provider:

```sh
uv run permiscan recon https://app.example.com
uv run permiscan recon https://app.example.com --probe-writes --probe-rpc   # Supabase: active tests
uv run permiscan recon https://app.example.com --format json
```

When it finds a backend, `recon` already tries to enumerate it automatically:
- **Supabase**: tables and RPCs through the Data API (like `scan-api`).
- **Firebase**: discovers the config (including at `/__/firebase/init.json`), tries reading
  common Firestore collections, lists the Storage bucket, and checks anonymous Realtime
  Database reads; with `--probe-writes`, tests whether user signup (Auth) is open.

The unified report brings: the identified stack (with confidence), discovered endpoints,
exposed configs/keys, findings, and recommendations. Anything that needs an extra credential
(the database DSN, a Firebase rules file) is flagged in the recommendations, never assumed.

> Endpoint discovery compares the response body against a nonexistent route: an SPA that
> returns `index.html` for everything (200 on any path) doesn't produce a false-positive
> "exposed file".

### Database analysis (Supabase/PostgreSQL via direct connection)

The DSN goes through an environment variable (credentials are never accepted as an
argument). Prefer a dedicated role with no extra privileges; see
[SECURITY.md](SECURITY.md#recommended-auditing-role).

```sh
export PERMISCAN_DSN='postgresql://permiscan_auditor:PASSWORD@db.abcdefghij.supabase.co:5432/postgres?sslmode=require'

uv run permiscan check --provider supabase
uv run permiscan scan  --provider supabase
uv run permiscan scan  --provider supabase --format json --output findings.json --fail-on high
uv run permiscan scan  --provider postgresql --role app_user --schema app
```

Optionally, restrict targets to an allowlist with `--scope file.toml`:

```toml
[[targets]]
host = "db.abcdefghij.supabase.co"
port = 5432
database = "postgres"

# On shared poolers, pin the user too: the host serves several projects.
[[targets]]
host = "aws-0-sa-east-1.pooler.supabase.com"
port = 5432
database = "postgres"
user = "permiscan_auditor.abcdefghij"
```

### External scan through the Supabase Data API

Just the project URL and the anon key (both public, embedded in any frontend). By default it
only observes what an anonymous request can **read**. Tests that alter the target are
explicit flags and should only be used where you're authorized.

```sh
export PERMISCAN_ANON_KEY='eyJhbGci...'   # anon/publishable key

# read (default): tables readable by anon + service_role key detection
uv run permiscan scan-api --url https://abcdefghij.supabase.co

# larger row sample as evidence
uv run permiscan scan-api --url https://abcdefghij.supabase.co --rows 20

# active tests (alter the target): writes and RPC calls
uv run permiscan scan-api --url https://abcdefghij.supabase.co --probe-writes --probe-rpc

# also calls RPCs with a destructive-sounding name (delete/drop/admin/…) — only on your own/test project
uv run permiscan scan-api --url https://abcdefghij.supabase.co --probe-rpc --include-destructive
```

| Flag | What it does | Alters the target? |
|---|---|---|
| (default) | reads 1 row per table; detects `service_role` | no |
| `--rows N` | reads up to N rows as a sample | no |
| `--probe-writes` | `POST` to test anonymous writes | may insert a row |
| `--probe-rpc` | calls RPCs to see if they respond without auth | runs the function |
| `--include-destructive` | includes destructive-sounding RPCs in `--probe-rpc` | runs the function |

### Credential detection on a page or bundle

Like the browser extension's auto-detection, but on a target you point it at (a page or a
local file), not crawling the web. Extracts project URLs and keys (anon, `service_role`,
`sb_publishable_`, `sb_secret_`). With `--scan`, scans each instance found:

```sh
uv run permiscan detect --url https://app.example.com
uv run permiscan detect --file dist/bundle.js
uv run permiscan detect --url https://app.example.com --scan --probe-writes
```

### Firebase Security Rules

Static analysis of a local rules file (the service is detected from the filename):

```sh
uv run permiscan scan-rules --rules firestore.rules
uv run permiscan scan-rules --rules storage.rules
uv run permiscan scan-rules --rules database.rules --service rtdb
```

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | Connection or configuration error |
| 2 | Target outside the authorized scope |
| 3 | There's a finding at or above the `--fail-on` severity |

The database session is a single `READ ONLY` transaction with a `statement_timeout`.
PermiScan only reads the system catalog; no row from your tables is ever queried.

## Available rules

| Rule | Detects | Severity |
|---|---|---|
| `pg-rls-disabled` | Table with no RLS and effective privileges for exposed roles (includes ignored policies) | critical (write) / high (read) |
| `pg-policy-unrestricted` | Policy with an always-true condition, applicable to a role with the matching privilege | high (write) / medium (read) |
| `pg-policy-no-ownership` | Write policy that doesn't reference the requester's identity | medium |
| `pg-rls-owner-bypass` | The audited role owns the table and RLS isn't forced | high |
| `pg-role-bypass-rls` | Audited role with `SUPERUSER` or `BYPASSRLS` | critical |
| `pg-view-definer` | View without `security_invoker` readable by exposed roles | medium |
| `pg-matview-exposed` | Materialized view (no RLS support) readable by exposed roles | medium |
| `pg-func-secdef-exposed` | `SECURITY DEFINER` function executable by exposed roles | medium |
| `pg-func-search-path` | `SECURITY DEFINER` function with no fixed `search_path` | medium |
| `supabase-api-anon-read` | Table that returns data to an anonymous Data API request | medium–critical (by column sensitivity) |
| `supabase-api-anon-write` | Table anonymous can write to (`--probe-writes`) | high–critical |
| `supabase-api-anon-rpc` | RPC function that responds without authentication (`--probe-rpc`) | by the function's name |
| `supabase-api-rpc-exposed` | Destructive-sounding RPC exposed, not called without `--include-destructive` | info |
| `supabase-service-role-key` | `service_role` key (bypasses RLS) used on the client | critical |
| `exposed-aws-access-key` | AWS Access Key ID (`AKIA…`) embedded in the frontend | critical |
| `exposed-sensitive-file` | Sensitive file (`.env`, `.git/config`) served publicly | critical |
| `firebase-rule-public` | `allow …: if true` rule (Firestore/Storage) | high (read) / critical (write) |
| `firebase-rule-any-authenticated-write` | Write requiring only `request.auth != null`, no ownership check | medium |
| `firebase-rtdb-public-read` / `-write` | Realtime Database with `".read"`/`".write": true` | high / critical |
| `firebase-firestore-public-read` | Firestore collections readable by anonymous (recon) | high |
| `firebase-storage-public-list` | Storage bucket with public listing (recon) | high |
| `firebase-auth-signup-open` | Open user signup in Firebase Auth (recon `--probe-writes`) | medium |

## Local lab

An intentionally vulnerable PostgreSQL, with vulnerable and safe scenarios side by side
([tests/fixtures/lab](tests/fixtures/lab)):

```sh
docker compose up -d --wait lab-db
export PERMISCAN_DSN=postgresql://permiscan_auditor:auditor-lab-only@127.0.0.1:55432/permiscan_lab
uv run permiscan scan --provider supabase --scope tests/fixtures/lab/scope.toml
```

## Documentation

- [SECURITY.md](SECURITY.md): authorized use, security posture, and vulnerability reporting.
- [CONTRIBUTING.md](CONTRIBUTING.md): development environment, tests, and how to add rules.
- [README.pt-BR.md](README.pt-BR.md): this README in Brazilian Portuguese.
