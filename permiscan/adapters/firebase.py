"""Análise estática de Firebase Security Rules (Firestore, Storage, Realtime DB).

As regras são um DSL próprio; aqui fazemos análise textual das construções perigosas
conhecidas, como fazem os linters de regras. Por isso a confiança é no máximo 'likely'
(para `if true`, que é inequívoco) ou 'possible' (para heurísticas de propriedade).
A validação de comportamento real fica para o Firebase Emulator (IMPLEMENTATION_PLAN.md, M6).
"""

import re
from pathlib import Path

from permiscan.adapters.base import AdapterError
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity

_DOCS = "https://firebase.google.com/docs/rules/rules-language"
_DOCS_SECURE = "https://firebase.google.com/docs/firestore/security/get-started"

# allow <ops>: if <cond>;  (cond pode quebrar linha até o ';')
_ALLOW = re.compile(r"allow\s+([\w\s,]+?)\s*:\s*if\s+(.*?);", re.I | re.S)
# Realtime Database: ".read": true / ".write": "auth != null"
_RTDB = re.compile(r'"\.(read|write)"\s*:\s*(true|false|"[^"]*")', re.I)

# A condição se reduz a "sempre verdadeiro"?
_ALWAYS_TRUE = re.compile(r"^\(*\s*true\s*\)*$", re.I)
# A condição amarra a linha à identidade de quem faz a requisição?
_OWNERSHIP = re.compile(r"request\.auth\.uid|request\.auth\.token|resource\.data|\buid\b", re.I)
_AUTH_PRESENT = re.compile(r"request\.auth\s*(!=|==)\s*null|request\.auth\s*!=\s*null", re.I)


def _normalize(expr: str) -> str:
    return re.sub(r"\s+", " ", expr).strip()


def _ops(raw: str) -> list[str]:
    return [o.strip().lower() for o in raw.split(",") if o.strip()]


def _is_write(ops: list[str]) -> bool:
    return any(o in ("write", "create", "update", "delete") for o in ops)


def analyze_rules(text: str, service: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    # Remove comentários: blocos /* */ (multilinha) e depois linhas //  — nessa ordem,
    # porque // não pode usar DOTALL (engoliria o resto do arquivo).
    stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    stripped = re.sub(r"//[^\n]*", "", stripped)

    def add(rule_id, title, desc, sev, conf, cwe, remediation_summary):
        findings.append(Finding(
            rule_id=rule_id, title=title, description=desc,
            category=Category.AUTHORIZATION, provider="firebase", resource=source,
            severity=sev, confidence=conf, cwe=cwe, owasp="API1:2023",
            evidence={"service": service},
            remediation=Remediation(summary=remediation_summary, references=[_DOCS, _DOCS_SECURE]),
        ))

    if service == "rtdb":
        for op, value in _RTDB.findall(stripped):
            op = op.lower()
            if value.lower() == "true":
                write = op == "write"
                add(
                    f"firebase-rtdb-public-{op}",
                    f"Realtime Database com '.{op}': true",
                    f"A regra \".{op}\": true libera {'escrita' if write else 'leitura'} para qualquer um, "
                    "sem autenticação.",
                    Severity.CRITICAL if write else Severity.HIGH, Confidence.LIKELY, "CWE-284",
                    f'Troque ".{op}": true por uma condição que exija auth e propriedade '
                    "(ex.: \"auth != null && auth.uid === $uid\").",
                )
        return findings

    # Firestore / Storage: analisa cada bloco `allow`.
    matches = list(_ALLOW.finditer(stripped))
    if not matches and not _RTDB.search(stripped):
        raise AdapterError(f"nenhuma regra 'allow' reconhecida em {source}; confira o arquivo e --service")

    for m in matches:
        ops = _ops(m.group(1))
        cond = _normalize(m.group(2))
        write = _is_write(ops)
        ops_label = ", ".join(ops)

        if _ALWAYS_TRUE.match(cond):
            add(
                "firebase-rule-public",
                f"Regra pública (allow {ops_label}: if true)",
                f"A regra 'allow {ops_label}: if true' concede {'escrita' if write else 'leitura'} a "
                "qualquer requisição, autenticada ou não. Todo o caminho correspondente fica exposto.",
                Severity.CRITICAL if write else Severity.HIGH, Confidence.LIKELY, "CWE-284",
                "Exija autenticação e vincule o acesso ao dono do recurso "
                "(ex.: 'if request.auth != null && request.auth.uid == resource.data.ownerId').",
            )
        elif write and _AUTH_PRESENT.search(cond) and not _OWNERSHIP.search(cond):
            add(
                "firebase-rule-any-authenticated-write",
                f"Escrita liberada a qualquer usuário autenticado (allow {ops_label})",
                f"A regra 'allow {ops_label}' exige apenas 'request.auth != null': qualquer usuário "
                "logado pode escrever em recursos de outros, pois não há verificação de propriedade.",
                Severity.MEDIUM, Confidence.POSSIBLE, "CWE-639",
                "Adicione verificação de propriedade além de auth != null "
                "(ex.: 'request.auth.uid == resource.data.ownerId').",
            )

    return findings


_SERVICE_HINTS = {"firestore": "firestore", "storage": "storage", "database": "rtdb", "rtdb": "rtdb"}


class FirebaseAdapter:
    provider = "firebase"

    def __init__(self, rules_path: Path, service: str | None = None):
        self.path = rules_path
        self.service = self._detect_service(rules_path, service)

    @staticmethod
    def _detect_service(path: Path, service: str | None) -> str:
        if service:
            if service not in _SERVICE_HINTS:
                raise AdapterError(f"--service deve ser um de: {', '.join(sorted(set(_SERVICE_HINTS)))}")
            return _SERVICE_HINTS[service]
        name = path.name.lower()
        if "storage" in name:
            return "storage"
        if "database" in name or "rtdb" in name:
            return "rtdb"
        return "firestore"  # arquivo padrão: firestore.rules

    def check(self) -> dict:
        if not self.path.is_file():
            raise AdapterError(f"arquivo de regras não encontrado: {self.path}")
        return {"provider": self.provider, "target": str(self.path), "service": self.service}

    def scan(self) -> list[Finding]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as e:
            raise AdapterError(f"não foi possível ler {self.path}: {e}") from None
        findings = analyze_rules(text, self.service, self.path.name)
        return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.resource))
