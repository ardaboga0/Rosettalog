"""Plugin contracts and discovery.

Frontends (sources), backends (targets) and emulators are discovered through package entry
points, so third-party packages can add a SIEM without touching this repository:

.. code-block:: toml

    [project.entry-points."rosettalog.backends"]
    elastic = "rosettalog_elastic:ElasticBackend"

The built-in plugins register themselves the same way (see ``pyproject.toml``).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from functools import cache
from importlib.metadata import entry_points
from pathlib import Path
from typing import ClassVar, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from rosettalog.errors import PluginError
from rosettalog.ir import Artifact, Finding

FRONTENDS_GROUP = "rosettalog.frontends"
BACKENDS_GROUP = "rosettalog.backends"
EMULATORS_GROUP = "rosettalog.emulators"


class GeneratedFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    """Relative path inside the backend's output directory for this artifact."""
    content: str


Scope = Literal["index-time", "search-time", "query-time"]


class DeploymentSetting(BaseModel):
    """One generated setting and *when* it takes effect in the target SIEM.

    * ``index-time``: applied while data is ingested; affects only data indexed after deployment.
    * ``search-time``: applied when searching; affects all data, including already indexed events.
    * ``query-time``: a saved query/function; applies to all data it is run against.
    """

    model_config = ConfigDict(frozen=True)

    scope: Scope
    file: str
    setting: str
    fields: list[str] = Field(default_factory=list)
    """Generated field names that depend on this setting."""
    note: str = ""


class BackendResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    artifact_id: str
    files: list[GeneratedFile] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    field_names: dict[str, str] = Field(default_factory=dict)
    """Canonical field -> field name in the generated content (only fields actually emitted)."""
    options: dict[str, str] = Field(default_factory=dict)
    """Effective backend options, so emulators can interpret the output the same way."""
    settings: list[DeploymentSetting] = Field(default_factory=list)
    """Where and when each generated setting takes effect (see :class:`DeploymentSetting`)."""

    @property
    def produced_output(self) -> bool:
        return bool(self.files) and bool(self.field_names)


@runtime_checkable
class Frontend(Protocol):
    name: ClassVar[str]
    description: ClassVar[str]

    def accepts(self, path: Path) -> bool:
        """Cheap check whether this frontend understands ``path``."""
        ...

    def parse(self, path: Path) -> list[Artifact]:
        """Parse into IR artifacts. Must not raise for content problems: report findings."""
        ...

    # Optional: ``def assumptions(self) -> rosettalog.ir.assumptions.AssumptionSet`` returns the
    # frontend's registry of assumed source semantics. Its unconfirmed *global* assumptions are
    # listed in every report that contains artifacts of that source format.


@runtime_checkable
class Backend(Protocol):
    name: ClassVar[str]
    description: ClassVar[str]
    option_help: ClassVar[Mapping[str, str]]
    """Supported ``-O key=value`` options and their help text."""

    def supports(self, artifact: Artifact) -> bool: ...

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult: ...


@runtime_checkable
class Emulator(Protocol):
    """Executes generated target content locally to extract fields from a log line."""

    target: ClassVar[str]
    engine_note: ClassVar[str]
    """One sentence describing how faithful the emulation is."""

    def __init__(self, result: BackendResult) -> None: ...

    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]:
        """Field name (as generated) -> value, for every field in ``result.field_names``."""
        ...


def _load(group: str) -> dict[str, type]:
    found: dict[str, type] = {}
    for ep in entry_points(group=group):
        try:
            obj = ep.load()
        except Exception as exc:  # a broken third-party plugin must not break the tool
            raise PluginError(f"Failed to load plugin '{ep.name}' from {group}: {exc}") from exc
        found[ep.name] = obj
    return found


@cache
def frontends() -> dict[str, type[Frontend]]:
    return _load(FRONTENDS_GROUP)


@cache
def backends() -> dict[str, type[Backend]]:
    return _load(BACKENDS_GROUP)


@cache
def emulators() -> dict[str, type[Emulator]]:
    return _load(EMULATORS_GROUP)


def get_backend(name: str) -> Backend:
    try:
        return backends()[name]()
    except KeyError:
        known = ", ".join(sorted(backends())) or "none"
        raise PluginError(f"Unknown target '{name}'. Available: {known}.") from None


def get_emulator(name: str) -> type[Emulator] | None:
    return emulators().get(name)
