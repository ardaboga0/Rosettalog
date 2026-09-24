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


def test_splunk_auto_kv_extraction_is_disabled_and_not_emulated() -> None:
    """Splunk 10.4.3: with the default KV_MODE=auto, 'user=alice' produced a `user` field from
    automatic extraction although our transforms did not (sample 'tcp deny', field UserName
    context). The backend now emits KV_MODE = none and the emulator refuses auto KV."""
    from rosettalog.backends.splunk import SplunkBackend
    from rosettalog.verify.emulators.splunk import SplunkEmulationError, SplunkEmulator

    result = SplunkBackend().generate(parse_lsx(ACME), {"sourcetype": "acme:fw"})
    props = next(f for f in result.files if f.path == "props.conf")
    assert "KV_MODE = none" in props.content
    SplunkEmulator(result)  # accepted
    auto = result.model_copy(
        update={
            "files": [
                f.model_copy(update={"content": f.content.replace("KV_MODE = none\n", "")})
                for f in result.files
            ]
        }
    )
    with pytest.raises(SplunkEmulationError, match="KV_MODE"):
        SplunkEmulator(auto)


def test_splunk_named_groups_are_not_emitted() -> None:
    """Splunk 10.4.3: `REGEX = \\buser=(?<user>[^\\s"]+)` with `FORMAT = rl_7_User::$1` created
    a `user` field from the named group but no rl_7_User, so EVAL-user became null (sample
    'tcp deny', field UserName) while the emulator gave 'alice'. Named groups are now emitted as
    plain groups for PCRE, and the emulator refuses named groups in REGEX."""
    from rosettalog.backends.splunk import SplunkBackend
    from rosettalog.regex.translate import translate
    from rosettalog.verify.emulators.splunk import SplunkEmulationError, SplunkEmulator

    assert translate(r"\buser=(?<user>[^\s\"]+)", "pcre").pattern == r'\buser=([^\s"]+)'
    assert translate(r"(a)(?<n>b)\k<n>", "pcre").pattern == r"(a)(b)\g{2}"
    result = SplunkBackend().generate(parse_lsx(ACME), {"sourcetype": "acme:fw"})
    transforms = next(f for f in result.files if f.path == "transforms.conf").content
    import re

    assert not re.search(r"\(\?P?<[A-Za-z]", transforms)  # no named groups (lookbehind is fine)
    user = SplunkEmulator(result).extract(ACME_TCP_DENY, now=NOW)["user"]
    assert user == "alice"
    named = result.model_copy(
        update={
            "files": [
                f.model_copy(update={"content": f.content.replace("user=(", "user=(?<user>")})
                for f in result.files
            ]
        }
    )
    with pytest.raises(SplunkEmulationError, match="named capture"):
        SplunkEmulator(named)


def test_splunk_time_not_comparable_when_year_inferred_or_auto_recognised() -> None:
    """Splunk 10.4.3 on the Tessivor samples: 'login fail' (format without year) got year 2027
    from event order and was rejected; 'tunnel up' did not match TIME_FORMAT but Splunk's
    automatic recognition found a timestamp. Neither is emulated, so the runner must report them
    as not comparable instead of claiming an emulator divergence."""
    from rosettalog.backends.splunk import SplunkBackend
    from rosettalog.plugins import NotComparable
    from rosettalog.verify.emulators.splunk import SplunkEmulator
    from rosettalog.verify.real.splunk import time_value
    from tests.conftest import FIXTURES

    tessivor = SplunkBackend().generate(parse_lsx(FIXTURES / "tessivor_vpn.lsx.xml"), {})
    ts = SplunkEmulator(tessivor).timestamp
    row = {"timestartpos": "0", "rl_epoch": "1774340100"}
    assert isinstance(time_value(row, "Mar 14 23:59:59 x", ts, NOW), NotComparable)
    rejected = {"rl_epoch": "1774340100"}  # no timestartpos: Splunk rejected the inferred year
    assert isinstance(time_value(rejected, "Mar 14 23:59:59 x", ts, NOW), NotComparable)
    codes = {f.code for f in tessivor.findings}
    assert {"SPLUNK_YEAR_INFERENCE", "SPLUNK_TIMESTAMP_FALLBACK"} <= codes

    acme = SplunkBackend().generate(parse_lsx(ACME), {"sourcetype": "acme:fw"})
    ts = SplunkEmulator(acme).timestamp
    matched = {"timestartpos": "49", "rl_epoch": "1773480413.12"}
    assert time_value(matched, ACME_TCP_DENY, ts, NOW) == "2026-03-14T09:26:53.120Z"
    assert time_value({"rl_epoch": "1"}, "no timestamp", ts, NOW) is None
    auto = {"timestartpos": "5", "rl_epoch": "1773480413"}
    assert isinstance(time_value(auto, "no ts= here 2026-03-14 09:26:53", ts, NOW), NotComparable)
