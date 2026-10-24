"""Log-source adapters."""

from titanlog.adapters.base import Adapter
from titanlog.adapters.generic_jsonl import GenericJsonlAdapter
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter

__all__ = ["Adapter", "GenericJsonlAdapter", "OtrfSysmonAdapter"]
