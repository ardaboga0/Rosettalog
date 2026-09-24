"""Canonical field taxonomy and mapping to target schemas (ASIM, CIM, ECS, Sigma, XDM)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Literal

import yaml

from rosettalog.ir.findings import Finding, Status

Taxonomy = Literal["asim", "cim", "ecs", "sigma", "xdm"]

#: Synthetic canonical field produced from event severity mappings (not a QRadar matcher field).
EVENT_SEVERITY = "EventSeverity"


@cache
def field_table() -> dict[str, dict[str, str | None]]:
    text = resources.files("rosettalog.data").joinpath("field_map.yaml").read_text("utf-8")
    data = yaml.safe_load(text)
    table: dict[str, dict[str, str | None]] = data["fields"]
    return table


def known_fields() -> frozenset[str]:
    return frozenset(field_table())


@dataclass(frozen=True)
class FieldNaming:
    """Canonical field -> target field name, plus findings produced while deciding."""

    names: dict[str, str]
    findings: list[Finding]


def resolve_names(fields: list[str], taxonomy: Taxonomy, *, target: str) -> FieldNaming:
    """Choose target names for canonical fields.

    Known fields get the taxonomy name; unmapped or unknown fields keep their original name and
    yield a PARTIAL ``FIELD_UNMAPPED`` finding. If two canonical fields would land on the same
    target name, the later one keeps its original name (``FIELD_NAME_COLLISION``).
    """
    table = field_table()
    names: dict[str, str] = {}
    findings: list[Finding] = []
    used: dict[str, str] = {}
    label = taxonomy.upper()
    for field in fields:
        mapped = table.get(field, {}).get(taxonomy)
        if mapped is None:
            reason = "is not a known field" if field not in table else f"has no {label} equivalent"
            findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="FIELD_UNMAPPED",
                    path=f"field[{field}]",
                    message=f"Field '{field}' {reason}; emitted under its original name.",
                    suggestion=f"Map '{field}' to the appropriate {label} field for your schema.",
                    target=target,
                )
            )
            mapped = field
        if mapped in used:
            findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="FIELD_NAME_COLLISION",
                    path=f"field[{field}]",
                    message=(
                        f"Field '{field}' and '{used[mapped]}' both map to {label} '{mapped}'; "
                        f"'{field}' is emitted under its original name instead."
                    ),
                    suggestion="Decide which source field should populate the normalized field.",
                    target=target,
                )
            )
            mapped = field
        used[mapped] = field
        names[field] = mapped
    return FieldNaming(names=names, findings=findings)
