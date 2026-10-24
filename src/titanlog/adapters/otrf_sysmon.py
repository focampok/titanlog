"""OTRF Security-Datasets JSONL through the shared field map."""

from titanlog.adapters.generic_jsonl import GenericJsonlAdapter


class OtrfSysmonAdapter(GenericJsonlAdapter):
    """Read OTRF / Sysmon JSONL with config/field_map.yaml."""
