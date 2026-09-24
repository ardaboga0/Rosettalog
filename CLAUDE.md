# CLAUDE.md

Guidance for AI coding assistants (and humans) working in this repository.

## Scope

Rosettalog is **defensive SIEM migration tooling**. It translates detection and parsing content
(QRadar LSX today; later, rules exported to Sigma and AQL through external translators) into
other SIEMs' formats. It never connects to a SIEM or
sends data anywhere. Stay within this scope. Do not add features for evading detection or for
accessing systems.

**Positioning: parsing migration first; integrate with, don't duplicate, rule converters.** The
core value is migrating *parsing logic* with honest findings and field-level verification. Do
**not** write an AQL grammar or translator, or a rule-to-query converter. Existing projects
(Uncoder.io, pySigma, ARuleCon) do that.
- M2 (AQL): only an integration point plus an optional adapter to an external translator, whose
  output and gaps become findings.
- M3 (rules/building blocks): IR detection model → Sigma only; target queries come from pySigma.
- M3 (rules → Sigma) is merged, on IR input (`*.ir.json`, documented in
  `docs/rules-ir-format.md`). **Open item:** the QRadar rule-export parser. It waits for QRadar
  CE answers to Q1-Q5 (`docs/rules-support-matrix.md`). Do not guess the rule XML encoding;
  build the parser as its own PR from a real CE export. M2 has not been started and needs the
  maintainer's approval.
- **pySigma boundary:** only `backends/sigma/pysigma.py` talks to pySigma. Never post-process
  or "fix" pySigma output. A refused construct is `PYSIGMA_BACKEND_GAP`; a query that does not
  mean what the Sigma rule means (seen on a real engine) is `VERIFY_RULE_DOWNSTREAM_GAP`. Pin
  it in `tests/real/test_rules_differential.py` and `tests/unit/test_pysigma_gaps.py` and
  document it in `docs/rules-support-matrix.md`. pySigma and its backends are optional, pinned
  extras.
- **Never invent a Sigma logsource.** Use a user-supplied `sigma.logsource_map`; otherwise
  `product: qradar` with `SIGMA_LOGSOURCE_UNMAPPED`.
- A rule test Sigma cannot express may only be dropped where that **broadens** the rule
  (`SIGMA_TEST_DROPPED`). Never narrow a rule silently.
- Rule fixtures are synthetic. Never use IBM-shipped rules, building blocks or content packs.

- **Cortex XSIAM (M5):** XSIAM output is **emulator-verified only**; never describe it as
  verified on XSIAM unless a tenant runner ran. Documented facts the backend relies on:
  - XQL uses RE2;
  - `config case_sensitive` defaults to false;
  - the rules of an INGEST group run independently, so write one statement;
  - XDM fields must exist in the schema, so never invent them.

  Undocumented behaviour may only be relied on when Palo Alto's shipped content
  (`demisto/content`) evidences it, and then with a finding. The `xsiam` tenant runner is like
  `sentinel-adx`: it sends data off the machine only when the user configures it, uses only
  synthetic samples, never runs on a schedule or on pull requests, and is stub-tested only.

## Non-negotiable rules

1. **Honesty over coverage.** Every element is translated faithfully, or produces a `Finding`
   (PARTIAL or UNSUPPORTED) that explains exactly what differs. Never drop logic, guess
   semantics or "best effort" silently. New codes go in `docs/findings-codes.md`
   (`tests/unit/test_docs.py` enforces this).
   **Assumptions** (where IBM's docs are silent or ambiguous) are registered in
   `src/rosettalog/frontends/qradar_lsx/assumptions.yaml`, the single source, with an ID, a
   confirmation case and a status (`unconfirmed`/`confirmed`/`refuted`). There are two kinds:
   - `per-artifact`: the construct only appears in some artifacts. Emit the PARTIAL finding
     listed in the entry wherever it occurs.
   - `global`: the assumption applies to every artifact. Emit **no** per-artifact finding. The
     pipeline lists every global assumption whose status is not `confirmed` in the report's
     top-level "Unconfirmed global assumptions" section (MD and JSON). Confirmed entries drop
     out automatically; refuted ones stay, marked, until the code is fixed.

   A *target* difference whose relevance depends on an assumption (e.g. Splunk trims values;
   this only matters if QRadar preserves whitespace, A06) is a finding with `depends_on`
   (`AssumptionDependency`: a topic plus unconfirmed/confirmed/refuted variants). Backends
   reference the assumption's `topic`, never a source-specific id, and the pipeline resolves it
   against the registry. If documented evidence contradicts an unconfirmed assumption, record
   it in `evidence_against`, which is shown as "unconfirmed, evidence against", and keep the
   behaviour until the assumption is observed.
   The doc tables in `docs/lsx-support-matrix.md` and `examples/confirmation/README.md` are
   generated from the YAML (`uv run python -m rosettalog.frontends.qradar_lsx.docs_sync`).
   Never edit them by hand; `tests/unit/test_assumptions.py` fails when they are stale.
2. **Fixtures are synthetic or from public docs.** Never add vendor-shipped content (IBM DSMs,
   content packs) or real logs. Use fictional vendor names that you have checked are not a real
   company or product. IPv4 addresses must be RFC 5737 (documentation) or RFC 1918 (private);
   everything else is forbidden. `0.0.0.0` is allowed only where it has a documented meaning,
   with an allowlist entry and reason in `tests/unit/test_fixture_hygiene.py` (enforced).
3. **The core is SIEM-agnostic.** `pipeline.py`, `ir/`, `report/` and `verify/harness.py` must
   not reference a specific source or target. Plugins are registered through entry points in
   `pyproject.toml`.
4. **Emulators interpret generated text.** They do not use backend internals, and they raise on
   unsupported constructs.
5. **Ground truth.** Every sample in `examples/` and tests has `expected` values for *every*
   field the parser produces, plus a `ground_truth_source` ("observed on QRadar CE x.y",
   "derived from IBM docs" or "assumed"). Tests enforce this. Never label assumed values as
   observed.
6. **Assumptions are frozen until confirmed.** The assumed LSX behaviours in the registry
   (confirmation cases in `examples/confirmation/`) must not be changed until observed QRadar CE
   results are recorded. If a confirmation case's `expected`
   changes to observed values and the tests fail, fix the frontend or emulator and its finding,
   not the expected values.
7. **Deployment scope.** Every generated setting is declared in `BackendResult.settings` as
   index-time, search-time or query-time. A translated field that depends on index-time
   configuration needs a finding (e.g. `SPLUNK_INDEX_TIME_DEPENDENCY`).
8. **Real engines are opt-in and local.** Real-engine runners (`rosettalog.verify.real`, group
   `rosettalog.runners`) must pin their image, publish ports on 127.0.0.1 only, label containers
   `rosettalog.verify=1`, and always remove them. Only the synthetic samples being verified may
   be sent to an engine. Nothing leaves the machine unless the user explicitly configures a
   remote service (e.g. ADX). Default tests and CI never need Docker:
   `@pytest.mark.real_engine` tests are skipped unless `--real-engine` is given.
9. **Emulator divergences.** When a target emulator disagrees with the real engine, fix the
   emulator (or the backend, if the real engine rejects our output) and add a container-free
   regression test to `tests/unit/test_emulator_regressions.py` that names the engine version
   and sample.

## Layout

- `src/rosettalog/ir/`: pydantic IR (`models.py`: `Artifact`, `ParserSpec`, `MatchGroup`,
  `FieldRule`, expression nodes), `findings.py` (`Status`, `Finding`, `aggregate_status`), and
  `fields.py` with `data/field_map.yaml` (QRadar → ASIM/CIM names).
- `src/rosettalog/regex/`: Java regex `tokenizer.py`, and `translate.py` (targets `re2`, `pcre`,
  `python`; returns the pattern plus issues).
- `src/rosettalog/timefmt/joda.py`: Joda-Time `ext-data` formats → regex, strptime, parse.
- `src/rosettalog/frontends/qradar_lsx/`: LSX → IR (hardened lxml parser).
- `src/rosettalog/backends/{sentinel,splunk,elastic}/`: IR → KQL / props+transforms / ingest
  pipeline JSON. `common.py` holds shared helpers.
- `src/rosettalog/regex/grok.py`, `onig_emulation.py`: grok patterns (Oniguruma, Ruby syntax)
  and their Python emulation. `src/rosettalog/timefmt/javatime.py`: Joda → java.time.
- `src/rosettalog/verify/real/`: opt-in real-engine runners and `docker.py`.
- `src/rosettalog/verify/`: `samples.py`, `harness.py`, `emulators/` (`source.py` evaluates the IR;
  `kql.py` and `splunk.py` interpret the generated output; `pcre.py` converts PCRE for the
  `regex` module).
- `src/rosettalog/report/`: report models, Markdown, JSON (+ schema).
- `src/rosettalog/pipeline.py`, `cli.py`: orchestration and the typer CLI.
- `tests/`: `unit/`, `golden/` (pinned outputs), `e2e/` (CLI), `fixtures/lsx/` (synthetic).
- `examples/acme_firewall/`: synthetic end-to-end example.
- `examples/confirmation/`: one minimal LSX, `sample.log` and `samples.yaml` per assumed LSX
  behaviour, to run on QRadar CE. `sample.log` and `samples.yaml` must stay identical (tested).

## Conventions

- Python 3.11+, `from __future__ import annotations`, full type hints, `mypy --strict` clean.
- Pydantic v2 frozen models for the IR. Dataclasses are fine for internal helpers.
- ruff (line length 100). Run `uv run ruff format . && uv run ruff check .`.
- Finding codes are `UPPER_SNAKE`, prefixed by area (`LSX_`, `RE2_`, `REGEX_`, `DATE_`, `KQL_`,
  `SPLUNK_`, `FIELD_`, `VERIFY_`). Messages say what differs and what the impact is. Suggestions
  say what a human should do.
- Generated output must be deterministic, and must not contain versions, timestamps or absolute
  paths (golden tests depend on this).
- When changing generated output intentionally, run `uv run pytest --update-golden` and review
  the diff.

## Commands

```bash
uv sync
uv run pytest
uv run mypy src
uv run ruff check . && uv run ruff format --check .
uv run rosettalog convert examples/acme_firewall/acme_fw.lsx.xml --to sentinel --to splunk \
    -s examples/acme_firewall/samples.yaml -o out/
```

## Known assumptions

The registry is `src/rosettalog/frontends/qradar_lsx/assumptions.yaml` (rule 1). A generated
view is in `docs/lsx-support-matrix.md` under "Assumed behaviours". Do not change these
semantics until observed results are recorded (rule 6).

The source emulator approximates Java regex with the Python `regex` module in ASCII mode. The
remaining known differences are listed in `docs/architecture.md`.
