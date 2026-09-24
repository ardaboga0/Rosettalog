"""Real Splunk runner: load generated props/transforms, ingest samples, read extracted fields.

Uses the official image with the documented license variables
(https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.4/install-splunk-enterprise-in-virtual-and-containerized-environments/deploy-and-run-splunk-enterprise-inside-a-docker-container):
``SPLUNK_START_ARGS=--accept-license``, ``SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com``
and a random per-run ``SPLUNK_PASSWORD``. The image is amd64-only (Apple Silicon: Rosetta).

Per verification call the generated files are installed as app ``rosettalog_verify`` (knowledge
objects exported system-wide), Splunk is restarted so index-time settings (TIME_PREFIX,
TIME_FORMAT, SHOULD_LINEMERGE) apply to data ingested afterwards, the samples are ingested with
a oneshot input from a unique source, and a search returns the fields. Index-time vs search-time
scope of each field is taken from ``BackendResult.settings`` by the harness.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from rosettalog.plugins import BackendResult, NotComparable, RealValue
from rosettalog.timefmt.joda import Comp, format_timestamp
from rosettalog.verify.emulators.splunk import SplunkEmulator
from rosettalog.verify.real.docker import (
    Container,
    RealEngineError,
    container,
    docker_available,
    wait_until,
)

IMAGE = "splunk/splunk:10.4.3"
PLATFORM = "linux/amd64"
URL_ENV = "ROSETTALOG_SPLUNK_URL"
PASSWORD_ENV = "ROSETTALOG_SPLUNK_PASSWORD"
CONTAINER_ENV = "ROSETTALOG_SPLUNK_CONTAINER"
INDEX = "rl_verify"
APP = "rosettalog_verify"
APP_DIR = f"/opt/splunk/etc/apps/{APP}"
LOCAL_META = "[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n"
SERVER_CERT = "/opt/splunk/etc/auth/server.pem"


def pinned_tls(cert_pem: str) -> ssl.SSLContext:
    """TLS context that trusts exactly splunkd's own certificate (read from the container).

    Certificate verification stays on; only the hostname check is off because Splunk's default
    certificate is not issued for 127.0.0.1. Pinning the leaf (partial-chain) means no other
    certificate is accepted.
    """
    context = ssl.create_default_context(cadata=cert_pem)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.check_hostname = False
    return context


def leaf_certificate(pem_bundle: str) -> str:
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    start = pem_bundle.find(begin)
    stop = pem_bundle.find(end, start)
    if start == -1 or stop == -1:
        raise RealEngineError("no certificate found in splunkd's server.pem")
    return pem_bundle[start : stop + len(end)] + "\n"


@dataclass
class SplunkSession:
    base_url: str
    password: str
    box: Container
    description: str

    def __post_init__(self) -> None:
        self._tls: ssl.SSLContext | None = None

    def _context(self) -> ssl.SSLContext:
        """splunkd's certificate, read lazily: it may only exist once first start completes."""
        if self._tls is None:
            self._tls = pinned_tls(leaf_certificate(self.box.exec("cat", SERVER_CERT, user="root")))
        return self._tls

    def rest(self, method: str, path: str, data: dict[str, str] | None = None) -> str:
        params = {**(data or {}), "output_mode": "json"}
        url = self.base_url + path
        body = None
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
        else:
            url += "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, data=body, method=method)
        token = base64.b64encode(f"admin:{self.password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(request, context=self._context(), timeout=300) as response:
                return str(response.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:1500]
            raise RealEngineError(f"Splunk {method} {path} -> HTTP {exc.code}: {detail}") from exc

    def ready(self) -> bool:
        self.rest("GET", "/services/server/info")
        return True

    def restart(self) -> None:
        """Restart splunkd so index-time settings apply to data ingested afterwards.

        Uses the synchronous CLI inside the container: the REST self-restart
        (/services/server/control/restart) sometimes shut splunkd down without bringing it back
        (seen with Splunk 10.4.3 under Rosetta).
        """
        self.box.exec(
            "/opt/splunk/bin/splunk", "restart", "--answer-yes", "--no-prompt",
            user="splunk", timeout=900,
        )  # fmt: skip
        wait_until(self.ready, timeout=300, what="Splunk REST API after restart", interval=3)

    def install(self, result: BackendResult) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / APP
            (root / "local").mkdir(parents=True)
            (root / "metadata").mkdir()
            for f in result.files:
                (root / "local" / f.path).write_text(f.content, encoding="utf-8")
            (root / "metadata" / "local.meta").write_text(LOCAL_META, encoding="utf-8")
            self.box.exec("rm", "-rf", APP_DIR, user="root")
            self.box.copy_in(str(root), "/opt/splunk/etc/apps/")
            self.box.exec("chown", "-R", "splunk:splunk", APP_DIR, user="root")
        self.restart()

    def extract_batch(
        self, result: BackendResult, logs: Sequence[str], *, now: datetime
    ) -> list[dict[str, RealValue]]:
        sourcetype = result.options["sourcetype"]
        self.install(result)
        source = f"/tmp/rosettalog-{secrets.token_hex(6)}.log"
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("\n".join(logs) + "\n")
            local = fh.name
        try:
            self.box.copy_in(local, source)
        finally:
            os.unlink(local)
        self.box.exec("chmod", "644", source, user="root")
        self.rest(
            "POST",
            "/services/data/inputs/oneshot",
            {"name": source, "sourcetype": sourcetype, "index": INDEX, "host": "rosettalog"},
        )
        fields = sorted({n for n in result.field_names.values() if n != "_time"})
        query = (
            f'search index={INDEX} source="{source}" sourcetype="{sourcetype}" '
            f"| eval rl_epoch=_time | table _raw rl_epoch timestartpos {' '.join(fields)}"
        )
        rows: list[dict[str, Any]] = []
        # Within 32-bit epoch range: later bounds are rejected by Splunk 10.4.3.
        far_future = int(time.time()) + 366 * 86400

        def indexed() -> bool:
            nonlocal rows
            out = self.rest(
                "POST",
                "/services/search/jobs/export",
                # Absolute epoch bounds: relative "+Ny" is rejected by Splunk 10.4.3.
                {"search": query, "earliest_time": "1", "latest_time": str(far_future)},
            )
            rows = [
                json.loads(line)["result"]
                for line in out.splitlines()
                if line.strip() and '"result"' in line
            ]
            return len(rows) >= len(logs)

        wait_until(indexed, timeout=300, what="sample events to be searchable", interval=3)
        by_raw = {r.get("_raw"): r for r in rows}
        timestamp = SplunkEmulator(result).timestamp
        out: list[dict[str, RealValue]] = []
        for log in logs:
            row = by_raw.get(log)
            if row is None:
                raise RealEngineError(f"sample not found in Splunk results: {log[:80]!r}")
            values: dict[str, RealValue] = {}
            for canonical, name in result.field_names.items():
                if name == "_time":
                    values[name] = time_value(row, log, timestamp, now)
                    continue
                value = row.get(name)
                values[name] = (
                    None
                    if value in (None, "")
                    else json.dumps(value)
                    if isinstance(value, list)
                    else str(value)
                )
                _ = canonical
            out.append(values)
        return out


def time_value(row: dict[str, Any], log: str, timestamp: Any, now: datetime) -> RealValue:
    """Splunk's ``_time`` for one event, or why it cannot be compared (seen with 10.4.3)."""
    if timestamp is not None and not (
        Comp.YEAR4 in timestamp.comps or Comp.YEAR2 in timestamp.comps
    ):
        # Checked first: an inferred year can also make Splunk reject the timestamp entirely.
        return NotComparable(
            "TIME_FORMAT has no year; Splunk infers it from neighbouring events (an "
            "out-of-order event was assigned the next year and rejected by MAX_DAYS_HENCE)."
        )
    if row.get("timestartpos") is None:
        return None  # not taken from the event (index time / previous event's time)
    if timestamp is not None and timestamp.extract(log, now) is None:
        return NotComparable(
            "TIME_FORMAT did not match; Splunk's automatic timestamp recognition found a "
            "timestamp elsewhere in the event, which is not emulated."
        )
    return format_timestamp(datetime.fromtimestamp(float(row["rl_epoch"]), UTC))


class SplunkRunner:
    name: ClassVar[str] = "splunk"
    target: ClassVar[str] = "splunk"
    image: ClassVar[str] = f"{IMAGE} ({PLATFORM})"

    def unavailable_reason(self) -> str | None:
        return docker_available()

    @contextmanager
    def session(self) -> Iterator[SplunkSession]:
        url, password = os.environ.get(URL_ENV), os.environ.get(PASSWORD_ENV)
        existing = os.environ.get(CONTAINER_ENV)
        if url and password and existing:
            box = Container(existing)
            yield SplunkSession(url.rstrip("/"), password, box, f"Splunk at {url} ({URL_ENV})")
            return
        password = "Rl" + secrets.token_urlsafe(18)
        env = {
            "SPLUNK_START_ARGS": "--accept-license",
            "SPLUNK_GENERAL_TERMS": "--accept-sgt-current-at-splunk-com",
            "SPLUNK_PASSWORD": password,
        }
        with container(
            IMAGE, ports=[8089], env=env, platform=PLATFORM, prefix="rosettalog-splunk"
        ) as box:
            session = SplunkSession(
                f"https://127.0.0.1:{box.host_port(8089)}",
                password,
                box,
                f"{IMAGE} ({PLATFORM}, local container)",
            )
            try:
                # Wait for the image's healthcheck (its Ansible provisioning must finish): the
                # REST API answers earlier, and restarting splunkd during provisioning makes the
                # container exit.
                wait_until(box.healthy, timeout=900, what="Splunk provisioning", interval=5)
                wait_until(session.ready, timeout=300, what="Splunk REST API", interval=3)
            except RealEngineError as exc:
                raise RealEngineError(f"{exc}\n{box.logs_tail()}") from exc
            try:
                session.rest("POST", "/services/data/indexes", {"name": INDEX})
            except RealEngineError as exc:
                if "409" not in str(exc):
                    raise
            yield session
