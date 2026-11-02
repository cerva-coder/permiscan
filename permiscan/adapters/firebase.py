"""Static analysis of Firebase Security Rules (Firestore, Storage, Realtime DB).

The rules are a DSL of their own; here we do textual analysis of known dangerous
constructs, the same way rules linters do. That's why confidence tops out at
'likely' (for `if true`, which is unambiguous) or 'possible' (for ownership
heuristics). Validating real behavior is left to the Firebase Emulator.
"""

import re
from pathlib import Path

from permiscan.adapters.base import AdapterError
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity

_DOCS = "https://firebase.google.com/docs/rules/rules-language"
_DOCS_SECURE = "https://firebase.google.com/docs/firestore/security/get-started"

# allow <ops>: if <cond>;  (cond may span lines up to the ';')
_ALLOW = re.compile(r"allow\s+([\w\s,]+?)\s*:\s*if\s+(.*?);", re.I | re.S)
# Realtime Database: ".read": true / ".write": "auth != null"
_RTDB = re.compile(r'"\.(read|write)"\s*:\s*(true|false|"[^"]*")', re.I)

# Does the condition reduce to "always true"?
_ALWAYS_TRUE = re.compile(r"^\(*\s*true\s*\)*$", re.I)
# Does the condition tie the row to the identity of the requester?
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
    # Strip comments: /* */ blocks (multiline) first, then // lines — in that order,
    # because // can't use DOTALL (it would swallow the rest of the file).
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
                    f"Realtime Database with '.{op}': true",
                    f"The rule \".{op}\": true grants {'write' if write else 'read'} access to anyone, "
                    "with no authentication.",
                    Severity.CRITICAL if write else Severity.HIGH, Confidence.LIKELY, "CWE-284",
                    f'Replace ".{op}": true with a condition that requires auth and ownership '
                    "(e.g. \"auth != null && auth.uid === $uid\").",
                )
        return findings

    # Firestore / Storage: analyze each `allow` block.
    matches = list(_ALLOW.finditer(stripped))
    if not matches and not _RTDB.search(stripped):
        raise AdapterError(f"no 'allow' rule recognized in {source}; check the file and --service")

    for m in matches:
        ops = _ops(m.group(1))
        cond = _normalize(m.group(2))
        write = _is_write(ops)
        ops_label = ", ".join(ops)

        if _ALWAYS_TRUE.match(cond):
            add(
                "firebase-rule-public",
                f"Public rule (allow {ops_label}: if true)",
                f"The rule 'allow {ops_label}: if true' grants {'write' if write else 'read'} access to "
                "any request, authenticated or not. The whole matching path is exposed.",
                Severity.CRITICAL if write else Severity.HIGH, Confidence.LIKELY, "CWE-284",
                "Require authentication and tie access to the resource's owner "
                "(e.g. 'if request.auth != null && request.auth.uid == resource.data.ownerId').",
            )
        elif write and _AUTH_PRESENT.search(cond) and not _OWNERSHIP.search(cond):
            add(
                "firebase-rule-any-authenticated-write",
                f"Write granted to any authenticated user (allow {ops_label})",
                f"The rule 'allow {ops_label}' only requires 'request.auth != null': any logged-in "
                "user can write to other users' resources, since there's no ownership check.",
                Severity.MEDIUM, Confidence.POSSIBLE, "CWE-639",
                "Add an ownership check besides auth != null "
                "(e.g. 'request.auth.uid == resource.data.ownerId').",
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
                raise AdapterError(f"--service must be one of: {', '.join(sorted(set(_SERVICE_HINTS)))}")
            return _SERVICE_HINTS[service]
        name = path.name.lower()
        if "storage" in name:
            return "storage"
        if "database" in name or "rtdb" in name:
            return "rtdb"
        return "firestore"  # default file: firestore.rules

    def check(self) -> dict:
        if not self.path.is_file():
            raise AdapterError(f"rules file not found: {self.path}")
        return {"provider": self.provider, "target": str(self.path), "service": self.service}

    def scan(self) -> list[Finding]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as e:
            raise AdapterError(f"couldn't read {self.path}: {e}") from None
        findings = analyze_rules(text, self.service, self.path.name)
        return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.resource))
