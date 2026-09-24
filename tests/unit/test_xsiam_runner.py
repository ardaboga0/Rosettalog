"""The opt-in XSIAM tenant runner, with stubbed HTTP only (no tenant is available)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from rosettalog.backends.xsiam import XsiamBackend
from rosettalog.verify.real import xsiam
from rosettalog.verify.real.docker import RealEngineError
from tests.conftest import ROOT, parse_lsx

ENV = {
    "ROSETTALOG_XSIAM_API_URL": "https://api-tenant.example.org",
    "ROSETTALOG_XSIAM_API_KEY": "key",
    "ROSETTALOG_XSIAM_API_KEY_ID": "7",
    "ROSETTALOG_XSIAM_COLLECTOR_URL": "https://api-tenant.example.org/logs/v1/event",
    "ROSETTALOG_XSIAM_COLLECTOR_KEY": "ckey",
    "ROSETTALOG_XSIAM_DATASET": "acme_fw_raw",
}
LOG = "<13>Mar 14 09:26:53 fw01 action=deny src=192.0.2.10 spt=5000"


class FakeTenant:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, str, object, dict]] = []

    def __call__(self, method, url, body, headers, *, timeout=120):
        payload = body.decode() if url.endswith("/logs/v1/event") else json.loads(body)
        self.calls.append((method, url, payload, headers))
        if url.endswith("start_xql_query"):
            return {"reply": "q-1"}
        if url.endswith("get_query_results"):
            return {
                "reply": {
                    "status": "SUCCESS",
                    "number_of_results": len(self.rows),
                    "results": {"data": self.rows},
                }
            }
        return None


def configure(monkeypatch, **extra: str) -> None:
    for k, v in {**ENV, **extra}.items():
        monkeypatch.setenv(k, v)


def test_unavailable_without_configuration(monkeypatch) -> None:
    for k in ENV:
        monkeypatch.delenv(k, raising=False)
    assert "ROSETTALOG_XSIAM_API_URL" in (xsiam.XsiamRunner().unavailable_reason() or "")
    configure(monkeypatch, ROSETTALOG_XSIAM_COLLECTOR_URL="http://insecure.example.org")
    assert "https" in (xsiam.XsiamRunner().unavailable_reason() or "")


def test_ingests_queries_and_maps_values(monkeypatch) -> None:
    configure(monkeypatch)
    artifact = parse_lsx(ROOT / "examples" / "acme_firewall" / "acme_fw.lsx.xml")
    result = XsiamBackend().generate(artifact, {"vendor": "acme", "product": "fw"})
    ds = "acme_fw_raw"
    row = {
        f"{ds}._raw_log": LOG,
        f"{ds}._insert_time": 4102444800000,  # far future: always newer than the run start
        "xdm.source.ipv4": "192.0.2.10",
        "xdm.source.port": 5000,
        "_time": 1773480413120,
    }
    fake = FakeTenant([row])
    monkeypatch.setattr(xsiam, "http", fake)
    with xsiam.XsiamRunner().session() as session:
        [values] = session.extract_batch(result, [LOG], now=datetime(2026, 6, 1, tzinfo=UTC))
    ingest, start = fake.calls[0], fake.calls[1]
    assert ingest[1] == ENV["ROSETTALOG_XSIAM_COLLECTOR_URL"]
    assert ingest[2] == LOG
    assert ingest[3]["Authorization"] == "ckey"
    query = start[2]["request_data"]["query"]
    assert query.startswith(
        f"config timeframe = 10y | datamodel dataset in({ds}) | filter {ds}._raw_log in("
    )
    assert start[3] == {
        "Authorization": "key",
        "x-xdr-auth-id": "7",
        "Content-Type": "application/json",
    }
    assert values["xdm.source.ipv4"] == "192.0.2.10"
    assert values["xdm.source.port"] == "5000"
    assert values["_time"] == "2026-03-14T09:26:53.120Z"
    assert not any(c[1].endswith("delete_dataset") for c in fake.calls)  # not opted in


def test_refuses_a_different_dataset(monkeypatch) -> None:
    configure(monkeypatch)
    result = XsiamBackend().generate(
        parse_lsx(ROOT / "examples" / "acme_firewall" / "acme_fw.lsx.xml"), {}
    )
    monkeypatch.setattr(xsiam, "http", FakeTenant([]))
    with (
        xsiam.XsiamRunner().session() as session,
        pytest.raises(RealEngineError, match="target_dataset"),
    ):
        session.extract_batch(result, [LOG], now=datetime(2026, 6, 1, tzinfo=UTC))


def test_deletes_the_dataset_only_when_opted_in(monkeypatch) -> None:
    configure(monkeypatch, ROSETTALOG_XSIAM_DELETE_DATASET="1")
    fake = FakeTenant([])
    monkeypatch.setattr(xsiam, "http", fake)
    with xsiam.XsiamRunner().session():
        pass
    [call] = fake.calls
    assert call[1].endswith("/public_api/v2/xql/delete_dataset")
    assert call[2] == {"request_data": {"dataset_name": "acme_fw_raw"}}


def test_refuses_plain_http() -> None:
    with pytest.raises(RealEngineError, match="non-HTTPS"):
        xsiam.http("POST", "http://example.org", b"", {})
