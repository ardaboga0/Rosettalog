"""Real Elasticsearch runner: execute generated pipelines with the ingest ``_simulate`` API.

https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ingest-simulate
Starts the pinned official image locally (bound to 127.0.0.1), or reuses the engine at
``ROSETTALOG_ELASTIC_URL``. Only the synthetic samples being verified are sent to it.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from rosettalog.plugins import (
    EVENT_ID_FIELD,
    EVENT_TIME_FIELD,
    BackendResult,
    RealValue,
    TargetQuery,
)
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

    def run_detection(
        self, query: TargetQuery, content: str, events: Sequence[Mapping[str, str | int]]
    ) -> set[str]:
        """Index ``events`` into a temporary index and run the query; the index is always deleted.

        String fields are mapped as ``keyword``; the sample time is ``@timestamp``.

        * Lucene: a ``query_string`` search on that index.
        * ES|QL: run unmodified except for its source. pySigma emits ``from *``, which is
          pointed at the temporary index so that no other index is read.
        * EQL: ``_eql/search`` on that index. EQL needs an event category field; it is set to the
          event id field, which ``any where`` queries do not look at.

        For correlation queries (``query.group_by``), the alerting groups are read from the
        ES|QL result columns or the EQL sequences' ``join_keys``.
        """
        index = f"rl-verify-{secrets.token_hex(6)}"
        mapping = {
            "mappings": {
                "properties": {"@timestamp": {"type": "date"}},
                "dynamic_templates": [
                    {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}
                ],
            }
        }
        http_json("PUT", f"{self.base_url}/{index}", mapping)
        try:
            for n, event in enumerate(events):
                doc: dict[str, object] = dict(event)
                if EVENT_TIME_FIELD in doc:
                    doc["@timestamp"] = doc.pop(EVENT_TIME_FIELD)
                http_json("PUT", f"{self.base_url}/{index}/_doc/{n}", doc)
            http_json("POST", f"{self.base_url}/{index}/_refresh")
            return self._run(query, content.strip(), index, len(events))
        finally:
            http_json("DELETE", f"{self.base_url}/{index}")

    def _run(self, query: TargetQuery, text: str, index: str, n: int) -> set[str]:
        group_by = query.group_by
        if query.language == "lucene":
            body = {"query": {"query_string": {"query": text}}, "size": n + 1}
            response = http_json("POST", f"{self.base_url}/{index}/_search", body)
            assert isinstance(response, dict)
            return {h["_source"][EVENT_ID_FIELD] for h in response["hits"]["hits"]}
        if query.language == "esql":
            if not text.startswith("from * "):
                raise RealEngineError(f"unexpected ES|QL source clause: {text[:60]!r}")
            esql = f"from {index} " + text.removeprefix("from * ")
            if group_by is None:
                esql += f" | keep {EVENT_ID_FIELD}"
            response = http_json("POST", f"{self.base_url}/_query", {"query": esql})
            assert isinstance(response, dict)
            columns = [c["name"] for c in response["columns"]]
            rows = [dict(zip(columns, row, strict=True)) for row in response["values"]]
            if group_by is None:
                return {str(r[EVENT_ID_FIELD]) for r in rows}
            return {_key(group_by, [r.get(f) for f in group_by]) for r in rows}
        if query.language == "eql":
            body = {"query": text, "size": n + 1, "event_category_field": EVENT_ID_FIELD}
            response = http_json("POST", f"{self.base_url}/{index}/_eql/search", body)
            assert isinstance(response, dict)
            hits = response["hits"]
            if group_by is None:
                return {e["_source"][EVENT_ID_FIELD] for e in hits.get("events", [])}
            return {_key(group_by, s.get("join_keys", [])) for s in hits.get("sequences", [])}
        raise RealEngineError(f"Elasticsearch cannot run {query.language} queries")


def _key(group_by: Sequence[str], values: Sequence[object]) -> str:
    """Group key in generated field names (``(all)`` without group-by)."""
    if not group_by:
        return "(all)"
    return ",".join(f"{f}={v}" for f, v in zip(group_by, values, strict=False))


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
