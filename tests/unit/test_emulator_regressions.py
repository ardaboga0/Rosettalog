"""Regression tests for emulator divergences found by real-engine differential testing.

Every entry names the real engine and version that exposed the divergence. These tests run
without containers.
"""

from __future__ import annotations

import json

import pytest

from rosettalog.backends.elastic import ElasticBackend
from rosettalog.plugins import BackendResult, GeneratedFile
from rosettalog.verify.emulators.elastic import ElasticEmulationError, ElasticEmulator
from tests.conftest import EXAMPLES, NOW, parse_lsx

ACME = EXAMPLES / "acme_firewall" / "acme_fw.lsx.xml"
ACME_TCP_DENY = (
    '<134>Mar 14 09:26:53 acme-fw01 AcmeFW[2211]: ts="2026-03-14 09:26:53.120" action=deny '
    'proto=TCP src=10.1.2.3 spt=51514 dst=203.0.113.10 dpt=443 user=alice cat="policy"'
)


def test_elastic_date_locale_english_is_rejected_by_real_engine() -> None:
    """Elasticsearch 9.5.4: `"locale": "ENGLISH"` fails with "Unknown language: ENGLISH", so
    @timestamp stayed empty while the emulator parsed it (sample 'tcp deny', field DeviceTime).
    The backend must not set a locale, and the emulator must refuse one."""
    result = ElasticBackend().generate(parse_lsx(ACME), {})
    pipeline = json.loads(result.files[0].content)
    dates = [p["date"] for p in pipeline["processors"] if "date" in p]
    assert dates
    assert all("locale" not in d for d in dates)
    assert ElasticEmulator(result).extract(ACME_TCP_DENY, now=NOW)["@timestamp"] == (
        "2026-03-14T09:26:53.120Z"
    )
    dates[0]["locale"] = "ENGLISH"
    tampered = BackendResult(
        target="elastic",
        artifact_id="t",
        files=[GeneratedFile(path="p.json", content=json.dumps(pipeline))],
        field_names=result.field_names,
        options=result.options,
    )
    with pytest.raises(ElasticEmulationError, match="locale"):
        ElasticEmulator(tampered)
