"""Contrato comum dos adaptadores de provedores."""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any, ClassVar

from permiscan.findings import Finding


class Capability(StrEnum):
    METADATA = "metadata"
    RLS_ANALYSIS = "rls_analysis"
    PRIVILEGE_ANALYSIS = "privilege_analysis"
    FUNCTION_ANALYSIS = "function_analysis"
    VIEW_ANALYSIS = "view_analysis"


class AdapterError(Exception):
    pass


class Adapter(ABC):
    provider: ClassVar[str]
    # O que o adaptador realmente implementa; nada é declarado por antecipação.
    capabilities: ClassVar[frozenset[Capability]]

    @abstractmethod
    def check(self) -> dict[str, Any]:
        """Valida a conexão e informa o que foi detectado no alvo."""

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Executa a análise e devolve findings normalizados."""
