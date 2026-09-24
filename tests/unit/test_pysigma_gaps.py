"""Pin the pinned pySigma backends' behaviour behind the documented downstream gaps.

If one of these fails after a pySigma upgrade, the gap may be fixed upstream: update
docs/rules-support-matrix.md, tests/real/test_rules_differential.py and this file.
"""

from __future__ import annotations

import importlib

import pytest

from rosettalog.backends.sigma.pysigma import TARGETS, load_collection, package_version

pytest.importorskip("sigma.backends.splunk")

PINNED = {
    "pysigma": "1.5.1",
    "pysigma-backend-splunk": "2.1.0",
    "pysigma-backend-kusto": "1.0.1",
    "pysigma-backend-elasticsearch": "2.1.1",
}


def convert(target: str, selection: str) -> str:
    rule = f"title: t\nlogsource: {{product: x}}\ndetection:\n  sel:\n    {selection}\n  condition: sel\n"
    t = TARGETS[target]
    backend = getattr(importlib.import_module(t.module), t.cls)()
    return str(backend.convert(load_collection(rule))[0])


def test_versions_are_the_pinned_ones() -> None:
    assert {p: package_version(p) for p in PINNED} == PINNED


@pytest.mark.parametrize("target", sorted(set(TARGETS) - {"eql"}))
def test_g0_cased_is_refused(target: str) -> None:
    with pytest.raises(Exception, match="Case-sensitive string matching is not supported"):
        convert(target, "f|cased: Abc")


def test_g0_eql_supports_cased() -> None:
    assert convert("eql", "f|cased: Abc") == 'any where f == "Abc"'


def test_g1_elasticsearch_matches_case_sensitively() -> None:
    assert convert("lucene", "f|contains: adm") == "f:*adm*"
    assert convert("esql", "f|contains: adm").endswith('where f like "*adm*"')


def test_g2_lucene_regex_passed_through_with_anchors() -> None:
    assert convert("lucene", "f|re: '^a$'") == "f:/^a$/"
    assert convert("esql", "f|re: '^a$'").endswith('where f rlike "^a$"')


BASES = """title: a
name: r_a
logsource: {product: x}
detection: {sel: {u: a}, condition: sel}
---
title: b
name: r_b
logsource: {product: x}
detection: {sel: {u: b}, condition: sel}
---
title: c
name: r
"""


def convert_correlation(target: str, correlation: str) -> str:
    t = TARGETS[target]
    backend = getattr(importlib.import_module(t.module), t.cls)()
    return str(backend.convert(load_collection(BASES + correlation))[-1])


EVENT_COUNT = "correlation: {type: event_count, rules: [r_a], group-by: [ip], timespan: 5m, condition: {gte: 3}}\n"


def test_g3_fixed_buckets_splunk_esql() -> None:
    assert "| bin _time span=5m" in convert_correlation("splunk", EVENT_COUNT)
    assert "date_trunc(5minutes, @timestamp)" in convert_correlation("esql", EVENT_COUNT)


def test_g4_eql_value_count_joins_on_the_counted_field() -> None:
    corr = "correlation: {type: value_count, rules: [r_a], group-by: [ip], timespan: 1m, condition: {gte: 3, field: port}}\n"
    assert convert_correlation("eql", corr).endswith("by port with runs=3")


def test_g5_eql_temporal_ordered_is_malformed() -> None:
    corr = (
        "correlation: {type: temporal_ordered, rules: [r_a, r_b], group-by: [ip], timespan: 2m}\n"
    )
    assert "by  with runs=2" in convert_correlation("eql", corr)


def test_g6_eql_temporal_sample_has_no_maxspan() -> None:
    corr = "correlation: {type: temporal, rules: [r_a, r_b], group-by: [ip], timespan: 10m}\n"
    query = convert_correlation("eql", corr)
    assert query.startswith("sample by ip")
    assert "maxspan" not in query


@pytest.mark.parametrize("target", ["kusto", "lucene"])
def test_no_correlation_support(target: str) -> None:
    with pytest.raises(NotImplementedError, match="does not support correlation rules"):
        convert_correlation(target, EVENT_COUNT)


def test_temporal_ordered_refused_by_splunk_and_esql() -> None:
    corr = "correlation: {type: temporal_ordered, rules: [r_a, r_b], timespan: 2m}\n"
    for target in ("splunk", "esql"):
        with pytest.raises(NotImplementedError, match="temporal_ordered"):
            convert_correlation(target, corr)


def test_g7_eql_compares_numbers_with_colon() -> None:
    assert convert("eql", "f: 22") == "any where f:22"


def test_g8_eql_regex_is_case_insensitive_operator() -> None:
    assert convert("eql", "f|re: 'adm'") == 'any where f regex~ "adm"'


@pytest.mark.parametrize("name", ["xql", "xsiam", "cortexxdr"])
def test_xql_target_is_a_documented_gap(name: str) -> None:
    from rosettalog.backends.sigma.pysigma import parse_targets
    from rosettalog.errors import InputError

    with pytest.raises(InputError, match=r"pysigma<1\.0\.0"):
        parse_targets(f"splunk,{name}")
