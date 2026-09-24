"""Evaluate a generated Sigma rule (the YAML text) against events.

It interprets the subset the Sigma backend emits and raises on anything else. Semantics follow
the Sigma specification v2.1.0
(https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md,
https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md):

* The keys of a selection map are ANDed, and the values of a list are ORed.
* Plain values are case-insensitive, match the whole value, and treat ``*``/``?`` as wildcards
  (``\\`` escapes them). ``cased`` makes the match case-sensitive; ``contains`` adds ``*``
  around the value.
* ``re`` is case-sensitive unless ``i`` is given. The spec does not say whether a regex must
  match the whole value; it is evaluated as a search (anywhere in the value), which is how
  SigmaHQ rules use it.
* A field the event does not have matches no value.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import regex as pyregex
import yaml

from rosettalog.plugins import BackendResult

KNOWN_MODIFIERS = {"contains", "cased", "re", "i", "m", "s"}


class SigmaEvalError(Exception):
    """The rule uses a construct this evaluator does not interpret."""


def wildcard_regex(value: str) -> str:
    """A Sigma plain value as a regex over the whole field value."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)


class _Selection:
    def __init__(self, body: Any) -> None:
        if not isinstance(body, dict):
            raise SigmaEvalError("only map selections are interpreted")
        self.items: list[tuple[str, list[str], set[str]]] = []
        for key, raw in body.items():
            name, *mods = str(key).split("|")
            unknown = set(mods) - KNOWN_MODIFIERS
            if unknown:
                raise SigmaEvalError(f"modifier(s) {', '.join(sorted(unknown))} not interpreted")
            values = raw if isinstance(raw, list) else [raw]
            if any(not isinstance(v, str | int) for v in values):
                raise SigmaEvalError(f"non-string value in {key}")
            self.items.append((name, [str(v) for v in values], set(mods)))

    def matches(self, event: Mapping[str, object]) -> bool:
        return all(self._item(name, values, mods, event) for name, values, mods in self.items)

    @staticmethod
    def _item(name: str, values: list[str], mods: set[str], event: Mapping[str, object]) -> bool:
        raw = event.get(name)
        if raw is None:
            return False
        actual = str(raw)
        for value in values:
            if "re" in mods:
                flags = pyregex.ASCII
                flags |= pyregex.IGNORECASE if "i" in mods else 0
                flags |= pyregex.MULTILINE if "m" in mods else 0
                flags |= pyregex.DOTALL if "s" in mods else 0
                if pyregex.search(value, actual, flags=flags, timeout=2):
                    return True
                continue
            pattern = wildcard_regex(value)
            if "contains" in mods:
                pattern = f".*{pattern}.*"
            flags = pyregex.DOTALL | (0 if "cased" in mods else pyregex.IGNORECASE)
            if pyregex.fullmatch(pattern, actual, flags=flags):
                return True
        return False


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


class SigmaRuleEvaluator:
    def __init__(self, text: str) -> None:
        rule = yaml.safe_load(text)
        detection = dict(rule["detection"])
        condition = detection.pop("condition")
        if not isinstance(condition, str):
            raise SigmaEvalError("only a single condition string is interpreted")
        self.selections = {k: _Selection(v) for k, v in detection.items()}
        self.tokens = self._tokenize(condition)

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        tokens: list[str] = []
        pos = 0
        while pos < len(text.rstrip()):
            m = _TOKEN.match(text, pos)
            if m is None:
                raise SigmaEvalError(f"cannot parse condition at {text[pos:]!r}")
            tokens.append(m.group(1))
            pos = m.end()
        if any(t in ("of", "1", "them") for t in tokens):
            raise SigmaEvalError("'x of' conditions are not interpreted")
        return tokens

    def matches(self, event: Mapping[str, object]) -> bool:
        self._pos = 0
        self._event = event
        result = self._or()
        if self._pos != len(self.tokens):
            raise SigmaEvalError(f"unexpected token {self.tokens[self._pos]!r}")
        return result

    # precedence (lowest to highest): or, and, not, parentheses
    def _peek(self) -> str | None:
        return self.tokens[self._pos] if self._pos < len(self.tokens) else None

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._pos += 1
            right = self._and()
            value = value or right
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._pos += 1
            right = self._not()
            value = value and right
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._pos += 1
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise SigmaEvalError("condition ends unexpectedly")
        self._pos += 1
        if tok == "(":
            value = self._or()
            if self._peek() != ")":
                raise SigmaEvalError("missing ')'")
            self._pos += 1
            return value
        if tok not in self.selections:
            raise SigmaEvalError(f"unknown search identifier {tok!r}")
        return self.selections[tok].matches(self._event)


class SigmaEmulator:
    """Target emulator for the ``sigma`` backend: decides which events a generated rule matches."""

    target = "sigma"
    engine_note = (
        "Sigma emulation: Rosettalog's interpreter of the Sigma specification v2.1.0 for the "
        "constructs it generates; not pySigma and not a SIEM."
    )

    def __init__(self, result: BackendResult) -> None:
        rule = next((f for f in result.files if f.path.endswith(".yml")), None)
        if rule is None:
            raise SigmaEvalError("no Sigma rule in the backend output")
        self.rule = SigmaRuleEvaluator(rule.content)

    def extract(self, log: str, *, now: object) -> dict[str, str | None]:
        raise SigmaEvalError("Sigma rules do not extract fields")

    def matches(self, event: Mapping[str, object]) -> bool:
        return self.rule.matches(event)
