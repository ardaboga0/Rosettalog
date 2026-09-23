# CLAUDE.md

Guidance for AI coding assistants (and humans) working in this repository.

## Scope

Rosettalog is **defensive SIEM migration tooling**. It translates detection and parsing content
(QRadar LSX today; AQL and rules later) into other SIEMs' formats. It never connects to a SIEM or
sends data anywhere. Stay within this scope. Do not add features for evading detection or for
accessing systems.

## Non-negotiable rules

1. **Honesty over coverage.** Every element is translated faithfully, or produces a `Finding`
   (PARTIAL or UNSUPPORTED) that explains exactly what differs. Never drop logic, guess
   semantics or "best effort" silently. When IBM's docs are ambiguous, emit a PARTIAL finding
   that states the assumption. New codes go in `docs/findings-codes.md`
   (`tests/unit/test_docs.py` enforces this).
2. **Fixtures are synthetic or from public docs.** Never add vendor-shipped content (IBM DSMs,
   content packs) or real logs. Use fictional vendors and RFC 5737 IP ranges.
3. **The core is SIEM-agnostic.** `pipeline.py`, `ir/`, `report/` and `verify/harness.py` must
   not reference a specific source or target. Plugins are registered through entry points in
   `pyproject.toml`.
4. **Emulators interpret generated text.** They do not use backend internals, and they raise on
   unsupported constructs.

## Layout

- `src/rosettalog/ir/`: pydantic IR (`models.py`: `Artifact`, `ParserSpec`, `MatchGroup`,
  `FieldRule`, expression nodes), `findings.py` (`Status`, `Finding`, `aggregate_status`), and
  `fields.py` with `data/field_map.yaml` (QRadar → ASIM/CIM names).
- `src/rosettalog/regex/`: Java regex `tokenizer.py`, and `translate.py` (targets `re2`, `pcre`,
  `python`; returns the pattern plus issues).
- `src/rosettalog/timefmt/joda.py`: Joda-Time `ext-data` formats → regex, strptime, parse.
- `src/rosettalog/frontends/qradar_lsx/`: LSX → IR (hardened lxml parser).
- `src/rosettalog/backends/{sentinel,splunk}/`: IR → KQL / props+transforms. `common.py` holds
  shared helpers.
- `src/rosettalog/verify/`: `samples.py`, `harness.py`, `emulators/` (`source.py` evaluates the IR;
  `kql.py` and `splunk.py` interpret the generated output; `pcre.py` converts PCRE for the
  `regex` module).
- `src/rosettalog/report/`: report models, Markdown, JSON (+ schema).
- `src/rosettalog/pipeline.py`, `cli.py`: orchestration and the typer CLI.
- `tests/`: `unit/`, `golden/` (pinned outputs), `e2e/` (CLI), `fixtures/lsx/` (synthetic).
- `examples/acme_firewall/`: synthetic end-to-end example.

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

## Known assumptions (keep findings in sync if you change these)

- With several match groups, the first group (by `order`) whose EventName pattern matches is
  applied (`LSX_MATCHGROUP_SELECTION_ASSUMED`).
- `event-match-multiple`: EventName comes from the capture, and the category and severity apply
  when the pattern matches.
- `event-match-single` builds EventCategory/EventSeverity lookups keyed by EventName. A matcher
  EventCategory is the fallback.
- An empty capture counts as "no value" on every engine.
