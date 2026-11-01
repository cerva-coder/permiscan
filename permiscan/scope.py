"""Escopo autorizado: nenhuma conexão é aberta para alvos fora da lista explícita."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from psycopg.conninfo import conninfo_to_dict


class ScopeError(Exception):
    pass


# Parâmetros que fazem a libpq conectar a um endereço diferente do host
# declarado, o que permitiria contornar a validação de escopo.
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
        # host/port/dbname explícitos sobrescrevem PGHOST/PGPORT/PGDATABASE,
        # garantindo que a conexão vá exatamente para o alvo validado.
        return {**self._conninfo, "host": self.host, "port": self.port, "dbname": self.database}

    def redact(self, text: str) -> str:
        password = self._conninfo.get("password")
        return text.replace(password, "***") if password else text


def parse_dsn(dsn: str) -> Target:
    try:
        info = conninfo_to_dict(dsn)
    except Exception as e:
        raise ScopeError("DSN inválido") from e
    if bad := [p for p in _FORBIDDEN_PARAMS if p in info]:
        raise ScopeError(f"parâmetros não permitidos no DSN: {', '.join(bad)}")
    host, database = info.get("host"), info.get("dbname")
    if not host or not database:
        raise ScopeError("o DSN deve declarar host e dbname explicitamente")
    if "," in host:
        raise ScopeError("DSN com múltiplos hosts não é suportado")
    try:
        port = int(info.get("port") or 5432)
    except ValueError as e:
        raise ScopeError("porta inválida no DSN") from e
    return Target(host.lower(), port, database, info.get("user"), info)


@dataclass(frozen=True)
class ScopeEntry:
    host: str
    port: int
    database: str
    user: str | None = None  # necessário em poolers compartilhados (ex.: Supabase Supavisor)

    def matches(self, t: Target) -> bool:
        return (
            (self.host, self.port, self.database) == (t.host, t.port, t.database)
            and (self.user is None or self.user == t.user)
        )


def load_scope(path: Path) -> list[ScopeEntry]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ScopeError(f"arquivo de escopo não encontrado: {path}") from e
    except tomllib.TOMLDecodeError as e:
        raise ScopeError(f"arquivo de escopo inválido: {e}") from e
    entries = []
    for i, t in enumerate(data.get("targets", [])):
        try:
            entries.append(ScopeEntry(t["host"].lower(), int(t.get("port", 5432)), t["database"], t.get("user")))
        except (KeyError, TypeError, ValueError) as e:
            raise ScopeError(f"alvo #{i + 1} do escopo inválido: requer host e database") from e
    if not entries:
        raise ScopeError("o escopo não declara nenhum alvo autorizado")
    return entries


def authorize(target: Target, entries: list[ScopeEntry]) -> None:
    if not any(e.matches(target) for e in entries):
        raise ScopeError(f"alvo fora do escopo autorizado: {target.label}")
