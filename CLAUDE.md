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
- M2 and M3 have not been started and need the maintainer's approval.

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
