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


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_g0_cased_is_refused(target: str) -> None:
    with pytest.raises(Exception, match="Case-sensitive string matching is not supported"):
        convert(target, "f|cased: Abc")


def test_g1_elasticsearch_matches_case_sensitively() -> None:
    assert convert("lucene", "f|contains: adm") == "f:*adm*"
    assert convert("esql", "f|contains: adm").endswith('where f like "*adm*"')


def test_g2_lucene_regex_passed_through_with_anchors() -> None:
    assert convert("lucene", "f|re: '^a$'") == "f:/^a$/"
    assert convert("esql", "f|re: '^a$'").endswith('where f rlike "^a$"')
