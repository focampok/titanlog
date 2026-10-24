"""Log-source adapters."""

from titanlog.adapters.base import Adapter
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter

__all__ = ["Adapter", "OtrfSysmonAdapter"]
