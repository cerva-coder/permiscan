"""Formato comum de findings, independente do provedor de origem."""

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, computed_field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Confidence(StrEnum):
    # "confirmed" fica reservado a comportamento observado em teste dinâmico;
    # análise estática nunca passa de "likely".
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class Category(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ISOLATION = "isolation"
    DATABASE_PERMISSIONS = "database_permissions"
    API_SECURITY = "api_security"
    STORAGE = "storage"
    BUSINESS_LOGIC = "business_logic"


class Remediation(BaseModel):
    model_config = ConfigDict(frozen=True)

    summary: str
    sql: str | None = None
    references: list[str] = []


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    description: str
    category: Category
    provider: str
    resource: str
    severity: Severity
    confidence: Confidence
    cwe: str | None = None
    owasp: str | None = None
    evidence: dict[str, Any] = {}
    remediation: Remediation
    status: str = "open"

    @computed_field
    @property
    def fingerprint(self) -> str:
        """Identidade estável para deduplicação e comparação entre varreduras."""
        key = f"{self.provider}|{self.rule_id}|{self.resource}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
