"""Sensitivity classification by column/field NAME.

Used to escalate the severity of an exposure without reading any real data:
we only look at the names of the columns the schema exposes, never the values.
"""

import re

from permiscan.findings import Severity

# Fields whose exposure is serious regardless of content. Patterns cover both English and
# Portuguese column names (senha/segredo/telefone/cpf/cnpj/…), since many real-world databases
# audited by this tool — especially Brazilian ones — name columns in Portuguese.
_CRITICAL = re.compile(
    r"\b(senha|password|passwd|pwd|secret|segredo|api[_-]?key|private[_-]?key|"
    r"token|jwt|access[_-]?token|refresh[_-]?token|card[_-]?number|cartao|cvv|cvc)\b",
    re.I,
)
# Personally identifiable information.
_HIGH = re.compile(
    r"\b(email|e[_-]?mail|phone|telefone|celular|cpf|cnpj|rg|ssn|passport|passaporte|"
    r"national[_-]?id|tax[_-]?id|iban|bank[_-]?account|conta[_-]?banc|salary|salario|renda)\b",
    re.I,
)
_MEDIUM = re.compile(
    r"\b(address|endereco|street|rua|cep|zip|postal|location|localizacao|"
    r"latitude|longitude|birth|nascimento|dob|ip[_-]?address|device[_-]?id)\b",
    re.I,
)
# Names that should never pull severity up.
_BENIGN = re.compile(r"^(id|created_at|updated_at|name|nome|title|titulo|slug|url|description)$", re.I)


def field_severity(name: str) -> Severity:
    if not name or _BENIGN.match(name):
        return Severity.INFO
    if _CRITICAL.search(name):
        return Severity.CRITICAL
    if _HIGH.search(name):
        return Severity.HIGH
    if _MEDIUM.search(name):
        return Severity.MEDIUM
    return Severity.INFO


def most_sensitive(names: list[str]) -> tuple[Severity, list[str]]:
    """Highest severity among the fields, and the names that justify it."""
    worst, flagged = Severity.INFO, []
    for name in names:
        sev = field_severity(name)
        if sev.rank < Severity.INFO.rank:
            flagged.append(name)
            if sev.rank < worst.rank:
                worst = sev
    return worst, flagged
