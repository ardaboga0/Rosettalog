"""Real Elasticsearch runner: execute generated pipelines with the ingest ``_simulate`` API.

https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ingest-simulate
Starts the pinned official image locally (bound to 127.0.0.1), or reuses the engine at
``ROSETTALOG_ELASTIC_URL``. Only the synthetic samples being verified are sent to it.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from rosettalog.plugins import BackendResult, RealValue
from rosettalog.verify.real.docker import (
    RealEngineError,
    container,
    docker_available,
    http_json,
    wait_until,
)

IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:9.5.4"
URL_ENV = "ROSETTALOG_ELASTIC_URL"


def flatten(obj: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, path + "."))
        else:
            out[path] = value
    return out


@dataclass
class ElasticSession:
    base_url: str
    description: str

    def extract_batch(
        self, result: BackendResult, logs: Sequence[str], *, now: datetime
    ) -> list[dict[str, RealValue]]:
        pipeline_file = next((f for f in result.files if f.path.endswith(".json")), None)
        if pipeline_file is None:
            raise RealEngineError("no pipeline JSON in backend output")
        source_field = result.options.get("source_field", "message")
        body = {
            "pipeline": json.loads(pipeline_file.content),
            "docs": [{"_source": {source_field: log}} for log in logs],
        }
        response = http_json("POST", f"{self.base_url}/_ingest/pipeline/_simulate", body)
        assert isinstance(response, dict)
        rows: list[dict[str, RealValue]] = []
        for index, doc in enumerate(response["docs"]):
            if "error" in doc:
                raise RealEngineError(f"sample {index + 1} failed in Elasticsearch: {doc['error']}")
            source = flatten(doc["doc"]["_source"])
            row: dict[str, RealValue] = {}
            for name in result.field_names.values():
                value = source.get(name)
                row[name] = None if value in (None, "") else str(value)
            rows.append(row)
        return rows


class ElasticRunner:
    name: ClassVar[str] = "elastic"
    target: ClassVar[str] = "elastic"
    image: ClassVar[str] = IMAGE

    def unavailable_reason(self) -> str | None:
        if os.environ.get(URL_ENV):
            return None
        return docker_available()

    @contextmanager
    def session(self) -> Iterator[ElasticSession]:
        url = os.environ.get(URL_ENV)
        if url:
            yield ElasticSession(url.rstrip("/"), f"Elasticsearch at {url} ({URL_ENV})")
            return
        env = {
            "discovery.type": "single-node",
            "xpack.security.enabled": "false",
            "ES_JAVA_OPTS": "-Xms1g -Xmx1g",
        }
        with container(IMAGE, ports=[9200], env=env, prefix="rosettalog-es") as c:
            base = f"http://127.0.0.1:{c.host_port(9200)}"

            def healthy() -> bool:
                health = http_json("GET", f"{base}/_cluster/health", timeout=10)
                return isinstance(health, dict) and health.get("status") in ("green", "yellow")

            try:
                wait_until(healthy, timeout=240, what="Elasticsearch to become healthy")
            except RealEngineError as exc:
                raise RealEngineError(f"{exc}\n{c.logs_tail()}") from exc
            yield ElasticSession(base, f"{IMAGE} (local container)")
