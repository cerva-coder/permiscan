"""Common contract for provider adapters."""

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
    # What the adapter actually implements; nothing is declared in advance.
    capabilities: ClassVar[frozenset[Capability]]

    @abstractmethod
    def check(self) -> dict[str, Any]:
        """Validates the connection and reports what was detected on the target."""

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Runs the analysis and returns normalized findings."""
