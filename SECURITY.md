# Security

## Authorized use

PermiScan is a defensive security tool. Only use it against systems you own or have
express, documented authorization to assess: your own applications, contracted
assessments, lab environments, and intentionally vulnerable applications.

The tool enforces this technically in two ways: every command takes the target
explicitly (the DSN, URL, or rules file you point it at — it never crawls the web for
credentials or scans whatever it stumbles on), and no operation that alters the target
runs by default (no writes, no RPC execution). An optional TOML allowlist is still
available via `--scope` for anyone who wants to pin down the targets.

## Reporting a vulnerability in PermiScan

Don't open a public issue. Use GitHub's private vulnerability reporting on this
repository (**Security → Report a vulnerability**), with reproduction steps and the
expected impact.

## The tool's security posture

### Implemented

| Control | How |
|---|---|
| Explicit target | Every command takes the target directly (DSN, URL, page, or file). `detect` extracts credentials from a page/file you point it at; there's no automatic web crawling. |
| Read-only by default | Database analysis is always read-only. The Data API only does `GET` by default. Tests that alter the target (`--probe-writes`, `--probe-rpc`) are opt-in and print a warning to stderr. |
| Destructive RPCs guarded | Under `--probe-rpc`, functions with a destructive-sounding name (delete/drop/admin/…) aren't called without `--include-destructive`; they show up in the report as "not called". |
| Pinned target (database) | Explicit `host`/`port`/`dbname` override `PG*` env vars; `hostaddr`, `service`, and multiple hosts are rejected. |
| Read-only (database) | The whole session runs inside a `READ ONLY` transaction, closed with `ROLLBACK`; only the system catalog is queried. |
| Timeouts | `connect_timeout`/`statement_timeout` of 10s/30s on the database; 15s per request on the Data API. |
| Credentials | DSN and anon key only via environment variable, never as an argument (avoids shell history and process listings). |
| Redaction | The password is stripped from error messages; a target's `repr` never includes credentials; driver exceptions aren't chained. |
| Optional allowlist | `--scope file.toml` restricts database targets to a list; a target outside it is rejected (exit code 2). |
| Identifiable on the target | Database connections use `application_name=permiscan`, visible in `pg_stat_activity` and the server logs. |

### Planned

- Dynamic database tests with synthetic identities and records, always inside a
  rolled-back transaction; minimal proof (counts instead of rows) by default.
- Firebase rules validation through the Emulator Suite.

Encryption of credentials at rest, an audit log, isolated workers, and rate limiting are
controls for a multi-user deployment; since PermiScan today is a local CLI that takes the
target on every run, they aren't implemented. They'd come in if (and when) a multi-user
API exists.

## Recommended auditing role

PermiScan doesn't need a superuser. A login role with no extra privileges can read the
catalog and compute other roles' effective privileges. The lab and the integration tests
run exactly this way.

```sql
CREATE ROLE permiscan_auditor LOGIN PASSWORD '<a strong password>';
-- no additional GRANT is needed
```

`permiscan check` warns when the connection uses a superuser or isn't in read-only mode.

## Threat model (summary)

| Asset | Threat | Mitigation |
|---|---|---|
| Target credentials | Leak in logs, history, output | DSN via environment, redaction, no exception chaining |
| Third-party targets | Use against an unauthorized system | Mandatory allowlist; DSN pinned to the validated target |
| Target integrity | Accidental write or load | Database: `READ ONLY` transaction. Data API: writes and RPC only under an explicit flag, with a warning; destructive RPCs require `--include-destructive` |
| Data exposure in evidence | Row sample in `--rows`/`scan-api` leaks target data | Default reads 1 row; values are truncated in evidence; reports stay local and gitignored |
| Finding reports | Exposure of the vulnerability map | Local output; don't version reports (`*.findings.json` is gitignored) |
| The tool itself | False positive leading to the wrong fix | Effective privileges, explicit confidence level, reviewable remediation |
