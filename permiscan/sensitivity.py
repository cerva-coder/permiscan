"""Classificação de sensibilidade pelo NOME da coluna/campo.

Usada para escalar a severidade de uma exposição sem ler nenhum dado real:
olhamos só os nomes das colunas que o esquema expõe, nunca os valores.
"""

import re

from permiscan.findings import Severity

# Campos cuja exposição é grave independentemente do conteúdo.
_CRITICAL = re.compile(
    r"\b(senha|password|passwd|pwd|secret|segredo|api[_-]?key|private[_-]?key|"
    r"token|jwt|access[_-]?token|refresh[_-]?token|card[_-]?number|cartao|cvv|cvc)\b",
    re.I,
)
# Dados pessoais identificáveis.
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
# Nomes que nunca devem puxar a severidade para cima.
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
    """Maior severidade entre os campos e os nomes que a justificam."""
    worst, flagged = Severity.INFO, []
    for name in names:
        sev = field_severity(name)
        if sev.rank < Severity.INFO.rank:
            flagged.append(name)
            if sev.rank < worst.rank:
                worst = sev
    return worst, flagged
