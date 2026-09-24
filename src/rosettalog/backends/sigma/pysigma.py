"""The pySigma boundary: validate generated Sigma rules and convert them with pySigma backends.

pySigma and its backends are optional extras (``sigma``, ``sigma-backends``), pinned in
``pyproject.toml``. Rosettalog does not post-process their output: when a backend refuses a
construct or is known to change its meaning, that is reported as a finding naming the backend
and its version (a gap in the downstream tool), never worked around here.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from rosettalog.errors import InputError
from rosettalog.ir import Finding, Status
from rosettalog.plugins import GeneratedFile, TargetQuery

NAME = "sigma"


@dataclass(frozen=True)
class PySigmaTarget:
    module: str
    cls: str
    package: str
    extension: str
    runner_target: str
    """Rosettalog real-engine target whose engine can execute the converted query."""


TARGETS: dict[str, PySigmaTarget] = {
    "splunk": PySigmaTarget(
        "sigma.backends.splunk", "SplunkBackend", "pysigma-backend-splunk", "spl", "splunk"
    ),
    "kusto": PySigmaTarget(
        "sigma.backends.kusto", "KustoBackend", "pysigma-backend-kusto", "kql", "sentinel"
    ),
    "lucene": PySigmaTarget(
        "sigma.backends.elasticsearch",
        "LuceneBackend",
        "pysigma-backend-elasticsearch",
        "lucene",
        "elastic",
    ),
    "esql": PySigmaTarget(
        "sigma.backends.elasticsearch.elasticsearch_esql",
        "ESQLBackend",
        "pysigma-backend-elasticsearch",
        "esql",
        "elastic",
    ),
}


def package_version(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def target_label(name: str) -> str:
    t = TARGETS[name]
    return f"{t.package} {package_version(t.package) or '(not installed)'}"


def parse_targets(spec: str) -> list[str]:
    names = [n.strip() for n in spec.split(",") if n.strip()]
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        raise InputError(
            f"Unknown pySigma target(s) {', '.join(unknown)}; choose from {', '.join(TARGETS)}."
        )
    return names


@dataclass
class CheckResult:
    files: list[GeneratedFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    queries: list[TargetQuery] = field(default_factory=list)


def _finding(status: Status, code: str, message: str, **kw: Any) -> Finding:
    return Finding(status=status, code=code, path="", message=message, target=NAME, **kw)


def load_collection(text: str) -> Any:
    from sigma.collection import SigmaCollection

    return SigmaCollection.from_yaml(text)


def check_and_convert(text: str, targets: str, artifact_id: str) -> CheckResult:
    """Validate ``text`` with every pySigma validator and convert it for ``targets``."""
    out = CheckResult()
    names = parse_targets(targets)
    try:
        collection = load_collection(text)
    except ImportError:
        out.findings.append(
            _finding(
                Status.FULL,
                "SIGMA_NOT_VALIDATED",
                "pySigma is not installed, so the rule was not validated.",
                suggestion="Install the 'sigma' extra: pip install 'rosettalog[sigma]'.",
            )
        )
        if names:
            raise InputError(
                "sigma.pysigma_targets needs the 'sigma-backends' extra: "
                "pip install 'rosettalog[sigma-backends]'."
            ) from None
        return out
    errors = [e for rule in collection.rules for e in rule.errors] + list(collection.errors)
    if errors:  # we generated invalid Sigma: a Rosettalog bug, not a finding
        raise RuntimeError(f"generated Sigma rule {artifact_id} is invalid: {errors}")
    out.findings.extend(_validate(collection))
    for name in names:
        converted = _convert(collection, name, artifact_id, out.findings)
        if converted is not None:
            out.files.append(converted)
            out.queries.append(
                TargetQuery(
                    language=name,
                    path=converted.path,
                    runner_target=TARGETS[name].runner_target,
                    label=target_label(name),
                )
            )
    return out


def _validate(collection: Any) -> list[Finding]:
    from sigma.validation import SigmaValidator
    from sigma.validators.core import validators

    findings: list[Finding] = []
    for issue in SigmaValidator(validators.values()).validate_rules(collection):
        severity = str(getattr(issue.severity, "name", issue.severity)).lower()
        status = Status.FULL if severity in ("low", "informational") else Status.PARTIAL
        findings.append(
            _finding(
                status,
                "SIGMA_VALIDATION_ISSUE",
                f"pySigma {package_version('pysigma')} validator {type(issue).__name__} "
                f"({severity}): {issue.description}",
            )
        )
    return findings


def _convert(
    collection: Any, name: str, artifact_id: str, findings: list[Finding]
) -> GeneratedFile | None:
    target = TARGETS[name]
    try:
        backend = getattr(importlib.import_module(target.module), target.cls)()
    except ImportError as exc:
        raise InputError(
            f"pySigma backend '{name}' ({target.package}) is not installed; install the "
            "'sigma-backends' extra."
        ) from exc
    label = target_label(name)
    try:
        queries = backend.convert(collection)
    except Exception as exc:  # pySigma raises many exception types for unsupported features
        findings.append(
            _finding(
                Status.UNSUPPORTED,
                "PYSIGMA_BACKEND_GAP",
                f"{label} could not convert the rule: {exc}",
                suggestion="This is a limitation of the pySigma backend; translate this rule "
                "for that target by hand or report it upstream.",
            )
        )
        return None
    if not queries:
        findings.append(
            _finding(Status.UNSUPPORTED, "PYSIGMA_BACKEND_GAP", f"{label} returned no query.")
        )
        return None
    content = "\n\n".join(str(q) for q in queries) + "\n"
    findings.append(
        _finding(
            Status.FULL,
            "PYSIGMA_CONVERTED",
            f"Converted by {label} without a processing pipeline: field names are the Sigma "
            "rule's field names.",
            suggestion="Add the pySigma pipeline for your data model (e.g. sentinel_asim, "
            "splunk_cim, ecs) when converting for production.",
        )
    )
    return GeneratedFile(path=f"{artifact_id}.{name}.{target.extension}", content=content)
