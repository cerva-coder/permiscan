# Contributing

## Environment

```sh
uv sync
docker compose up -d --wait lab-db
export PERMISCAN_LAB_DSN=postgresql://permiscan_auditor:auditor-lab-only@127.0.0.1:55432/permiscan_lab
uv run pytest
```

Without `PERMISCAN_LAB_DSN` the integration tests are skipped; CI always runs them.
Use `127.0.0.1`, not `localhost`: the lab only listens on IPv4, and `localhost` can
resolve to `::1` first, which costs a connection timeout.

To recreate the lab after changing the SQL: `docker compose down -v && docker compose up -d --wait lab-db`.

## Adding a PostgreSQL rule

1. Write a `(snapshot, provider) -> Iterator[Finding]` function in
   `permiscan/adapters/postgres/rules.py` and add it to `RULES`.
2. Always cross-reference the configuration with effective privileges
   (`Relation.privileges`, `Function.executable_by`): no role able to perform the
   operation means no finding.
3. If you need new catalog data, extend `Snapshot` in `catalog.py`.
4. Unit tests in `tests/unit/test_rules.py` with one vulnerable case **and** one safe case.
5. Add a vulnerable object to `tests/fixtures/lab/10_vulnerable.sql`, a safe one to
   `20_safe.sql`, and update the expected set in `tests/integration/test_lab.py`.
6. Document the rule in the README's table.

Confidence: `likely` when the catalog proves the condition; `possible` when it depends
on a heuristic or intent; `confirmed` only from a dynamic test.

## Adding a provider

Implement `permiscan.adapters.base.Adapter`, declare in `capabilities` only what's
actually implemented, and register it in `permiscan/adapters/__init__.py`. Update the
README's status table. Don't declare support without validating the integration; if a
credential is missing to validate it, document what was tested and how.

## Conventions

- User-facing text and comments in English; identifiers in English.
- Commits in Conventional Commits format (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Fixtures use synthetic data only. Never commit real credentials, real DSNs, or
  reports from real targets.
