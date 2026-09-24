"""Opt-in Cortex XSIAM tenant runner (``--runner xsiam``); it sends samples to YOUR tenant.

There is no local XSIAM engine. This runner uses a tenant **you** configure, and only the
documented public interfaces:

* the HTTP log collector ``POST https://api-<tenant>/logs/v1/event`` (raw lines, per-collector
  API key)
  (https://cortex-docs.paloaltonetworks.com/cortex-xsiam/configure-cortex-xsiam/cortex-xsiam-data-sources/vendor-specific-data-sources-and-connectors/http-log-collector/set-up-an-http-log-collector-to-receive-logs.md);
* the XQL query API ``/public_api/v1/xql/start_xql_query`` and ``get_query_results``, with a
  standard API key and key ID, and ``/public_api/v2/xql/delete_dataset``
  (https://cortex-docs.paloaltonetworks.com/xsiam-api/cortex-platform/xql-query.md).

**Preconditions and limits (no documented API exists for these):**

* You install the generated Parsing Rule (and Data Model Rule) yourself in the Parsing/Data
  Model Rules editor, for a dedicated collector whose vendor/product match ``xsiam.vendor`` /
  ``xsiam.product``, writing to the dataset named in ``ROSETTALOG_XSIAM_DATASET``. The runner
  cannot check which rule is installed.
* Ingested events cannot be deleted one by one. With ``ROSETTALOG_XSIAM_DELETE_DATASET=1`` the
  runner deletes the whole dedicated dataset when the session ends; otherwise nothing is deleted.

Modeled values are read with ``datamodel dataset in(<ds>)``, the same form Palo Alto's
``demisto-sdk`` uses to test modeling rules. This runner is covered by stubbed-HTTP tests only.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from rosettalog.plugins import BackendResult, NotComparable, RealValue
from rosettalog.timefmt.joda import format_timestamp
from rosettalog.verify.real.docker import RealEngineError

ENV = {
    "api_url": "ROSETTALOG_XSIAM_API_URL",
    "api_key": "ROSETTALOG_XSIAM_API_KEY",
    "api_key_id": "ROSETTALOG_XSIAM_API_KEY_ID",
    "collector_url": "ROSETTALOG_XSIAM_COLLECTOR_URL",
    "collector_key": "ROSETTALOG_XSIAM_COLLECTOR_KEY",
    "dataset": "ROSETTALOG_XSIAM_DATASET",
}
DELETE_ENV = "ROSETTALOG_XSIAM_DELETE_DATASET"
TIME_FIELD = "_time"


def http(
    method: str, url: str, body: bytes, headers: Mapping[str, str], *, timeout: float = 120
) -> Any:
    """HTTPS request returning parsed JSON (or ``None`` for an empty body)."""
    if not url.startswith("https://"):
        raise RealEngineError(f"refusing non-HTTPS URL {url}")
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:1500]
        raise RealEngineError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    return json.loads(data) if data.strip() else None


def xql_quote(value: str) -> str:
    """A double-quoted XQL string literal (quotes escaped as in Palo Alto's content)."""
    return '"' + value.replace('"', '\\"') + '"'


@dataclass
class XsiamSession:
    config: dict[str, str]
    description: str

    def _api(self, path: str, request_data: dict[str, Any]) -> Any:
        headers = {
            "Authorization": self.config["api_key"],
            "x-xdr-auth-id": self.config["api_key_id"],
            "Content-Type": "application/json",
        }
        body = json.dumps({"request_data": request_data}).encode()
        return http("POST", self.config["api_url"].rstrip("/") + path, body, headers)

    def ingest(self, logs: Sequence[str]) -> None:
        headers = {"Authorization": self.config["collector_key"], "Content-Type": "text/plain"}
        http("POST", self.config["collector_url"], "\n".join(logs).encode(), headers)

    def query(self, xql: str, *, timeout: float = 300) -> list[dict[str, Any]]:
        started = self._api("/public_api/v1/xql/start_xql_query", {"query": xql})
        query_id = started["reply"]
        deadline = time.monotonic() + timeout
        while True:
            reply = self._api(
                "/public_api/v1/xql/get_query_results",
                {"query_id": query_id, "pending_flag": True, "limit": 1000, "format": "json"},
            )["reply"]
            status = reply.get("status")
            if status == "SUCCESS":
                return list(reply.get("results", {}).get("data", []))
            if status != "PENDING":
                raise RealEngineError(f"XQL query failed ({status}): {reply}")
            if time.monotonic() > deadline:
                raise RealEngineError("timed out waiting for XQL query results")
            time.sleep(5)

    def delete_dataset(self) -> None:
        self._api("/public_api/v2/xql/delete_dataset", {"dataset_name": self.config["dataset"]})

    def extract_batch(
        self, result: BackendResult, logs: Sequence[str], *, now: datetime
    ) -> list[dict[str, RealValue]]:
        dataset = self.config["dataset"]
        if result.options.get("target_dataset") != dataset:
            raise RealEngineError(
                f"the generated rule writes to '{result.options.get('target_dataset')}' but "
                f"{ENV['dataset']} is '{dataset}'; pass -O xsiam.target_dataset={dataset} and "
                "install that rule on the tenant"
            )
        start_ms = int(time.time() * 1000)
        self.ingest(logs)
        names = list(result.field_names.values())
        modeled = any(n.startswith("xdm.") for n in names)
        raw_log = f"{dataset}._raw_log" if modeled else "_raw_log"
        column = {n: (n if n.startswith("xdm.") or n == TIME_FIELD else
                      f"{dataset}.{n}" if modeled else n) for n in names}  # fmt: skip
        source = f"datamodel dataset in({dataset})" if modeled else f"dataset = {dataset}"
        insert = f"{dataset}._insert_time" if modeled else "_insert_time"
        wanted = ", ".join(xql_quote(log) for log in logs)
        xql = (
            f"config timeframe = 10y | {source} | filter {raw_log} in({wanted}) "
            f"| dedup {raw_log} by desc {insert} "
            f"| fields {raw_log}, {insert}, {', '.join(dict.fromkeys(column.values()))}"
        )
        rows: dict[str, dict[str, Any]] = {}
        deadline = time.monotonic() + 600
        while True:
            for row in self.query(xql):
                if int(row.get(insert) or 0) >= start_ms:
                    rows[str(row.get(raw_log))] = row
            if all(log in rows for log in logs):
                break
            if time.monotonic() > deadline:
                missing = [log[:60] for log in logs if log not in rows]
                raise RealEngineError(f"samples not found in {dataset}: {missing}")
            time.sleep(10)
        year_from_ingest = any(f.code == "XSIAM_YEAR_FROM_INGEST_TIME" for f in result.findings)
        out: list[dict[str, RealValue]] = []
        for log in logs:
            row = rows[log]
            values: dict[str, RealValue] = {}
            for name, col in column.items():
                values[name] = _value(row.get(col), name == TIME_FIELD)
            if year_from_ingest and now.year != datetime.now(UTC).year:
                values[TIME_FIELD] = NotComparable(
                    "the date has no year and XSIAM uses the ingestion year, which differs "
                    "from the samples' reference_time"
                )
            out.append(values)
        return out


def _value(value: Any, is_time: bool) -> str | None:
    if value is None or value == "":
        return None
    if is_time:
        return format_timestamp(datetime.fromtimestamp(int(value) / 1000, tz=UTC))
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


class XsiamRunner:
    """Opt-in: runs against a Cortex XSIAM tenant you configure (sends the samples there)."""

    name: ClassVar[str] = "xsiam"
    target: ClassVar[str] = "xsiam"
    image: ClassVar[str] = "Cortex XSIAM tenant (ROSETTALOG_XSIAM_API_URL); not a container"

    def unavailable_reason(self) -> str | None:
        missing = [v for v in ENV.values() if not os.environ.get(v)]
        if missing:
            return f"set {', '.join(missing)} to use a Cortex XSIAM tenant"
        for key in ("api_url", "collector_url"):
            if not os.environ[ENV[key]].startswith("https://"):
                return f"{ENV[key]} must be an https:// URL"
        return None

    @contextmanager
    def session(self) -> Iterator[XsiamSession]:
        config = {key: os.environ[var] for key, var in ENV.items()}
        session = XsiamSession(
            config,
            f"Cortex XSIAM tenant {config['api_url']} / dataset {config['dataset']} "
            "(configured by you; rule installed by you)",
        )
        try:
            yield session
        finally:
            if os.environ.get(DELETE_ENV) == "1":
                session.delete_dataset()
