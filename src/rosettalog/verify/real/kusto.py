"""Real KQL runners: the local Kusto emulator (Kustainer) and an opt-in Azure Data Explorer runner.

Kusto emulator (https://learn.microsoft.com/en-us/azure/data-explorer/kusto-emulator-install):
a Linux container that needs "a processor that supports SSE4.2/AVX2"; "ARM processors aren't
supported". It speaks plain HTTP without authentication on port 8080.

ADX (``sentinel-adx``) runs the same queries against a cluster **you** configure through
``ROSETTALOG_ADX_CLUSTER``, ``ROSETTALOG_ADX_DATABASE`` and ``ROSETTALOG_ADX_TOKEN``. It is the only
runner that sends data off the machine, and it only runs when those variables are set.

Both use the REST API (https://learn.microsoft.com/en-us/kusto/api/rest/request): samples are
ingested into a uniquely named temporary table with ``.set-or-append`` from a ``datatable``;
the generated file runs **unmodified**, preceded by ``let <source_table> = <temp table>;`` (a
``let`` shadows the table name, so no existing table is read or written); the temp table is
always dropped.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from rosettalog.backends.sentinel.backend import kql_string
from rosettalog.plugins import BackendResult, RealValue
from rosettalog.timefmt.joda import format_timestamp
from rosettalog.verify.real.docker import (
    RealEngineError,
    container,
    docker_arch,
    docker_available,
    http_json,
    wait_until,
)

KUSTAINER = (
    "mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest"
    "@sha256:a44a0015384c9b1486f15d0fb52c6de7a9d33816d8a5cce03cf280dee10908ab"
)
EMULATOR_DB = "NetDefaultDB"
ADX_ENV = ("ROSETTALOG_ADX_CLUSTER", "ROSETTALOG_ADX_DATABASE", "ROSETTALOG_ADX_TOKEN")


def _canonical(value: Any, data_type: str) -> str | None:
    if value is None or value == "":
        return None
    if data_type.lower() == "datetime":
        text = str(value).replace("Z", "+00:00")
        if "." in text:  # Python < 3.11.x accepts at most 6 fractional digits
            head, _, tail = text.partition(".")
            # Only the leading fraction digits (not the ones in the "+00:00" offset).
            digits = tail[: len(tail) - len(tail.lstrip("0123456789"))]
            text = f"{head}.{(digits + '000000')[:6]}{tail[len(digits) :]}"
        return format_timestamp(datetime.fromisoformat(text).astimezone(UTC))
    return str(value)


@dataclass
class KustoSession:
    base_url: str
    database: str
    description: str
    headers: Mapping[str, str] = field(default_factory=dict)

    def _call(self, kind: str, csl: str) -> dict[str, Any]:
        path = "/v1/rest/mgmt" if kind == "mgmt" else "/v1/rest/query"
        response = http_json(
            "POST",
            self.base_url + path,
            {"db": self.database, "csl": csl},
            headers={"Accept": "application/json", **self.headers},
        )
        if not isinstance(response, dict):
            raise RealEngineError(f"unexpected Kusto response: {response!r}")
        return response

    def extract_batch(
        self, result: BackendResult, logs: Sequence[str], *, now: datetime
    ) -> list[dict[str, RealValue]]:
        kql = next((f.content for f in result.files if f.path.endswith(".kql")), None)
        if kql is None:
            raise RealEngineError("no .kql file in backend output")
        table = result.options.get("source_table", "Syslog")
        column = result.options.get("message_column", "SyslogMessage")
        temp = f"rl_verify_{secrets.token_hex(6)}"
        rows_literal = ", ".join(kql_string(log) for log in logs)
        self._call("mgmt", f".create table {temp} ({column}:string)")
        try:
            self._call(
                "mgmt",
                f".set-or-append {temp} <| datatable({column}:string) [{rows_literal}]",
            )
            response = self._call("query", f"let {table} = {temp};\n{kql}")
        finally:
            self._call("mgmt", f".drop table {temp} ifexists")
        first = response["Tables"][0]
        names = [c["ColumnName"] for c in first["Columns"]]
        types = {
            c["ColumnName"]: c.get("DataType") or c.get("ColumnType", "") for c in first["Columns"]
        }
        records = [dict(zip(names, row, strict=True)) for row in first["Rows"]]
        by_message = {r.get(column): r for r in records}
        out: list[dict[str, RealValue]] = []
        for log in logs:
            record = by_message.get(log)
            if record is None:
                raise RealEngineError(f"sample not returned by Kusto: {log[:80]!r}")
            out.append(
                {
                    name: _canonical(record.get(name), types.get(name, "string"))
                    for name in result.field_names.values()
                }
            )
        return out


class KustainerRunner:
    name: ClassVar[str] = "sentinel"
    target: ClassVar[str] = "sentinel"
    image: ClassVar[str] = KUSTAINER

    def unavailable_reason(self) -> str | None:
        reason = docker_available()
        if reason is not None:
            return reason
        arch = docker_arch()
        if arch not in ("x86_64", "amd64"):
            return (
                f"the Kusto emulator needs an x86-64 CPU with SSE4.2/AVX2 and does not support "
                f"ARM (Microsoft docs); this Docker host is {arch}. Use a Linux x86-64 host, the "
                "real-engines GitHub workflow, or the ADX runner (--runner sentinel-adx)."
            )
        return None

    @contextmanager
    def session(self) -> Iterator[KustoSession]:
        with container(
            KUSTAINER,
            ports=[8080],
            env={"ACCEPT_EULA": "Y"},
            platform="linux/amd64",
            memory="4g",
            prefix="rosettalog-kusto",
        ) as box:
            session = KustoSession(
                f"http://127.0.0.1:{box.host_port(8080)}",
                EMULATOR_DB,
                "Kusto emulator (kustainer-linux, local container)",
            )

            def ready() -> bool:
                session._call("mgmt", ".show cluster")
                return True

            try:
                wait_until(ready, timeout=600, what="the Kusto emulator to start", interval=5)
            except RealEngineError as exc:
                raise RealEngineError(f"{exc}\n{box.logs_tail()}") from exc
            yield session


class AdxRunner:
    """Opt-in: runs against an Azure Data Explorer cluster you configure (sends samples there)."""

    name: ClassVar[str] = "sentinel-adx"
    target: ClassVar[str] = "sentinel"
    image: ClassVar[str] = "Azure Data Explorer cluster (ROSETTALOG_ADX_CLUSTER); not a container"

    def unavailable_reason(self) -> str | None:
        missing = [v for v in ADX_ENV if not os.environ.get(v)]
        if missing:
            return f"set {', '.join(missing)} to use an Azure Data Explorer cluster"
        if not os.environ["ROSETTALOG_ADX_CLUSTER"].startswith("https://"):
            return "ROSETTALOG_ADX_CLUSTER must be an https:// URL"
        return None

    @contextmanager
    def session(self) -> Iterator[KustoSession]:
        cluster, database, token = (os.environ[v] for v in ADX_ENV)
        yield KustoSession(
            cluster.rstrip("/"),
            database,
            f"Azure Data Explorer {cluster} / {database} (configured by you)",
            headers={"Authorization": f"Bearer {token}"},
        )
