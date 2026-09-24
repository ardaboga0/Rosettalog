"""Rules: the pySigma query on the real engine vs the Sigma rule (Sigma emulator) vs the source.

Run with ``uv run pytest -m real_engine --real-engine [--real-targets elastic,splunk]`` (needs
Docker and the ``sigma-backends`` extra). Every rule sample set is converted with each pinned
pySigma backend and run on the matching real engine.

A difference between a query and the Sigma rule is a gap in the downstream converter (or engine),
not something Rosettalog hides or patches. Every known one is pinned in ``KNOWN_GAPS`` with the
reason, and documented in docs/rules-support-matrix.md; a new difference fails the test until it
is triaged: a pySigma/engine gap (add it here and to the docs) or a Rosettalog bug (fix it and
add a regression test).
"""

from __future__ import annotations

import importlib

import pytest

from rosettalog.backends.sigma.pysigma import TARGETS
from rosettalog.pipeline import load_artifacts
from rosettalog.plugins import get_backend
from rosettalog.verify.rule_harness import verify_rule
from rosettalog.verify.rule_samples import load_rule_samples
from tests.conftest import ROOT, rule_sample_sets

#: (sample set dir, artifact id, pySigma target) -> (events the query also matches, events it
#: misses) compared with the Sigma rule, and why.
KNOWN_GAPS: dict[tuple[str, str, str], tuple[set[str], set[str], str]] = {
    # Sigma plain/contains values are case-insensitive. The Elasticsearch backends emit
    # case-sensitive matches (Lucene wildcard, ES|QL LIKE) on keyword fields: 'SysADM' is missed.
    ("rules", "acme_admin_login_test_net", "lucene"): (set(), {"e3"}, "G1 case-sensitive"),
    ("rules", "acme_admin_login_test_net", "esql"): (set(), {"e3"}, "G1 case-sensitive"),
    # Lucene regular expressions have no ^/$ anchors (they are literal characters) and must
    # match the whole value; pySigma passes the Sigma regex through unchanged.
    ("rules", "tessivor_auth_failure_not_ssh", "lucene"): (set(), {"e4", "e7"}, "G2 anchors"),
    ("rules", "tessivor_auth_failure_not_ssh", "esql"): (set(), {"e4", "e7"}, "G2 anchors"),
    # Confirmation cases: G1 (case) and G2 (whole-value regex) as above. EQL's "regex~" is the
    # case-insensitive regex operator, while Sigma regexes are case-sensitive (G8).
    ("01-value-case", "rl_rules_01_equals", "lucene"): (set(), {"e2", "e3"}, "G1"),
    ("01-value-case", "rl_rules_01_equals", "esql"): (set(), {"e2", "e3"}, "G1"),
    ("01-value-case", "rl_rules_01_contains", "lucene"): (set(), {"e1", "e3", "e4"}, "G1"),
    ("01-value-case", "rl_rules_01_contains", "esql"): (set(), {"e1", "e3", "e4"}, "G1"),
    ("02-regex-find", "rl_rules_02_regex", "lucene"): (set(), {"e2"}, "G2"),
    ("02-regex-find", "rl_rules_02_regex", "esql"): (set(), {"e2"}, "G2"),
    ("02-regex-find", "rl_rules_02_regex", "eql"): ({"e3"}, {"e2"}, "G2 + G8"),
    # Correlations (hits are alerting groups). Splunk/ES|QL count in fixed buckets (bin _time,
    # date_trunc), so groups whose events straddle a bucket boundary are missed.
    ("rules-stateful", "tessivor_vpn_bruteforce", "esql"): (set(), {"SourceIp=192.0.2.21"}, "G3"),
    ("rules-stateful", "tessivor_vpn_bruteforce", "splunk"): (set(), {"SourceIp=192.0.2.21"}, "G3"),
    ("rules-stateful", "acme_config_and_login", "splunk"): (set(), {"UserName=ivan"}, "G3"),
    ("rules-stateful", "acme_config_and_login", "esql"): (set(), {"UserName=ivan"}, "G3"),
    # EQL value_count: "[...] by <field> with runs=N" joins on the counted field (N events with
    # the SAME value) instead of counting distinct values.
    ("rules-stateful", "acme_port_scan", "eql"): (
        {"SourceIp=192.0.2.31"},
        {"SourceIp=192.0.2.30"},
        "G4",
    ),
    # EQL temporal: "sample by ..." has no maxspan, so the timespan is ignored.
    ("rules-stateful", "acme_config_and_login", "eql"): ({"UserName=heidi"}, set(), "G6"),
}

#: (sample set dir, artifact id, pySigma target) -> part of the engine's error message.
KNOWN_ERRORS: dict[tuple[str, str, str], tuple[str, str]] = {
    # EQL temporal_ordered is rendered as "... by  with runs=2", which Elasticsearch rejects.
    ("rules-stateful", "tessivor_fail_then_success", "eql"): ("extraneous input 'with'", "G5"),
    ("07-sequence-gaps", "rl_rules_07_sequence", "eql"): ("extraneous input 'with'", "G5"),
    ("08-sequence-window", "rl_rules_08_sequence", "eql"): ("extraneous input 'with'", "G5"),
    # EQL compares numbers with ":" ("dst_port:22"), which Elasticsearch rejects for numeric
    # fields: "first argument of [:] must be [string] ... consider using [==] instead".
    ("rules", "tessivor_auth_failure_not_ssh", "eql"): ("must be [string]", "G7"),
    ("rules", "acme_blocked_host_event", "eql"): ("must be [string]", "G7"),
}

PAIRS = rule_sample_sets()


@pytest.mark.real_engine
@pytest.mark.parametrize("language", sorted(TARGETS))
@pytest.mark.parametrize(("samples", "rules"), PAIRS, ids=lambda p: str(p.relative_to(ROOT)))
def test_pysigma_query_on_real_engine(language, samples, rules, real_session) -> None:
    try:
        importlib.import_module(TARGETS[language].module)
    except ImportError:  # requested real-engine tests must not silently pass
        pytest.fail(f"{TARGETS[language].package} is not installed (extra 'sigma-backends')")
    session = real_session(TARGETS[language].runner_target)
    sample_set = load_rule_samples(samples)
    problems = []
    for artifact in load_artifacts([rules]):
        result = get_backend("sigma").generate(artifact, {"pysigma_targets": language})
        if not result.queries:
            continue  # conversion refused: reported as PYSIGMA_BACKEND_GAP, nothing to run
        outcome = verify_rule(artifact, result, sample_set, {session_target(language): session})
        emulator, real = outcome.run("emulator"), outcome.run("real")
        assert emulator is not None
        assert emulator.hits is not None
        assert real is not None, "no real-engine run"
        key = (samples.parent.name, artifact.id, language)
        if key in KNOWN_ERRORS:
            assert real.error is not None, f"{artifact.id}: known error {KNOWN_ERRORS[key]} is gone"
            assert KNOWN_ERRORS[key][0] in real.error, real.error
            continue
        assert real.error is None, f"{artifact.id}: {real.error}"
        extra = set(real.hits or []) - set(emulator.hits)
        missing = set(emulator.hits) - set(real.hits or [])
        known = KNOWN_GAPS.get(key)
        if (extra, missing) != ((known[0], known[1]) if known else (set(), set())):
            problems.append(
                f"{artifact.id}: query also matches {sorted(extra)}, misses {sorted(missing)} "
                f"(known: {known})"
            )
    assert not problems, "Untriaged differences from the Sigma rule:\n" + "\n".join(problems)


def session_target(language: str) -> str:
    return TARGETS[language].runner_target
