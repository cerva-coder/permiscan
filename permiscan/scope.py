"""Authorized scope: no connection is opened to targets outside the explicit list."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from psycopg.conninfo import conninfo_to_dict


class ScopeError(Exception):
    pass


# Parameters that make libpq connect to an address different from the declared
# host, which would allow bypassing scope validation.
_FORBIDDEN_PARAMS = ("hostaddr", "service", "servicefile")


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    database: str
    user: str | None
    _conninfo: dict = field(repr=False)

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}/{self.database}"

    def connect_kwargs(self) -> dict:
        # Explicit host/port/dbname override PGHOST/PGPORT/PGDATABASE,
        # guaranteeing the connection goes exactly to the validated target.
        return {**self._conninfo, "host": self.host, "port": self.port, "dbname": self.database}

    def redact(self, text: str) -> str:
        password = self._conninfo.get("password")
        return text.replace(password, "***") if password else text


def parse_dsn(dsn: str) -> Target:
    try:
        info = conninfo_to_dict(dsn)
    except Exception as e:
        raise ScopeError("invalid DSN") from e
    if bad := [p for p in _FORBIDDEN_PARAMS if p in info]:
        raise ScopeError(f"parameters not allowed in the DSN: {', '.join(bad)}")
    host, database = info.get("host"), info.get("dbname")
    if not host or not database:
        raise ScopeError("the DSN must declare host and dbname explicitly")
    if "," in host:
        raise ScopeError("DSN with multiple hosts is not supported")
    try:
        port = int(info.get("port") or 5432)
    except ValueError as e:
        raise ScopeError("invalid port in the DSN") from e
    return Target(host.lower(), port, database, info.get("user"), info)


@dataclass(frozen=True)
class ScopeEntry:
    host: str
    port: int
    database: str
    user: str | None = None  # needed on shared poolers (e.g. Supabase Supavisor)

    def matches(self, t: Target) -> bool:
        return (
            (self.host, self.port, self.database) == (t.host, t.port, t.database)
            and (self.user is None or self.user == t.user)
        )


def load_scope(path: Path) -> list[ScopeEntry]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ScopeError(f"scope file not found: {path}") from e
    except tomllib.TOMLDecodeError as e:
        raise ScopeError(f"invalid scope file: {e}") from e
    entries = []
    for i, t in enumerate(data.get("targets", [])):
        try:
            entries.append(ScopeEntry(t["host"].lower(), int(t.get("port", 5432)), t["database"], t.get("user")))
        except (KeyError, TypeError, ValueError) as e:
            raise ScopeError(f"invalid scope target #{i + 1}: requires host and database") from e
    if not entries:
        raise ScopeError("the scope doesn't declare any authorized target")
    return entries


def authorize(target: Target, entries: list[ScopeEntry]) -> None:
    if not any(e.matches(target) for e in entries):
        raise ScopeError(f"target outside the authorized scope: {target.label}")
