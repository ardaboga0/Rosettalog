"""Plugin contracts and discovery.

Frontends (sources), backends (targets) and emulators are discovered through package entry
points, so third-party packages can add a SIEM without touching this repository:

.. code-block:: toml

    [project.entry-points."rosettalog.backends"]
    elastic = "rosettalog_elastic:ElasticBackend"

The built-in plugins register themselves the same way (see ``pyproject.toml``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
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
RUNNERS_GROUP = "rosettalog.runners"


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


@dataclass(frozen=True)
class NotComparable:
    """A real-engine value that cannot be compared (e.g. it depends on the engine's clock)."""

    reason: str


RealValue = str | None | NotComparable


class RealEngineSession(Protocol):
    """A running real engine (container or remote service) that can process samples."""

    description: str
    """E.g. "docker.elastic.co/elasticsearch/elasticsearch:9.5.4 (local container)"."""

    def extract_batch(
        self, result: BackendResult, logs: Sequence[str], *, now: datetime
    ) -> list[dict[str, RealValue]]:
        """For each log: generated field name -> value, like :meth:`Emulator.extract`."""
        ...


@runtime_checkable
class RealEngineRunner(Protocol):
    """Opt-in verification against the real target engine (``rosettalog verify --engine real``).

    Runners must keep data local (containers bound to 127.0.0.1) unless the user explicitly
    configures a remote service, and must clean up everything they create.
    """

    name: ClassVar[str]
    target: ClassVar[str]
    image: ClassVar[str]
    """Pinned image reference, or a description of the remote service."""

    def unavailable_reason(self) -> str | None:
        """``None`` if the runner can run here; otherwise why not (platform, missing config)."""
        ...

    def session(self) -> AbstractContextManager[RealEngineSession]: ...


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


@cache
def runners() -> dict[str, type[RealEngineRunner]]:
    return _load(RUNNERS_GROUP)


def get_runner(target: str, name: str | None = None) -> RealEngineRunner:
    """The runner called ``name``, or the default runner for ``target`` (same name)."""
    available = runners()
    key = name or target
    cls = available.get(key)
    if cls is None or cls.target != target:
        known = ", ".join(f"{n} ({c.target})" for n, c in sorted(available.items())) or "none"
        raise PluginError(
            f"No real-engine runner '{key}' for target '{target}'. Available: {known}."
        )
    return cls()
