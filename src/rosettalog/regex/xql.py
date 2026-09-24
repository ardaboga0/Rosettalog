"""Regular expressions for Cortex XSIAM Parsing Rules (XQL).

XQL "utilizes the RE2 regular expression implementation"
(https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/functions/regexcapture.md),
so the body is emitted by the ``re2`` translator (the same one used for Kusto) and validated
with Google RE2. Parsing Rules capture several groups with ``regexcapture(field, "...")``, which
returns an object keyed by *named* groups. Every capture group is therefore renamed to ``gN`` (N =
its Java group number), and the whole pattern is wrapped in ``(?P<m>...)`` so that "the pattern
matched" is observable even when every group is empty. This is the same technique used for
Elastic grok (``rosettalog.regex.grok``).

The documentation says ``(?i)`` "must be added only once at the beginning of the inline regular
expression". A case-insensitive pattern therefore gets one leading ``(?i)``. Flags anywhere else
are reported (``XSIAM_REGEX_INLINE_FLAGS``) because the docs do not say that they work.

String literals: Palo Alto's shipped Parsing Rules pass backslashes through unchanged
(``"\\d{4}"``, and ``"[\\\\/]"`` for "backslash or slash") and write a double quote as ``\\"``
(563 uses in ``demisto/content``). ``\\"`` is a literal quote in RE2 whether or not XQL unescapes
it first, so :func:`xql_regex_literal` is safe under both readings.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import re2

from rosettalog.ir.findings import Status
from rosettalog.regex.tokenizer import GroupKind, Kind, RegexSyntaxError, Token, tokenize
from rosettalog.regex.translate import RegexIssue, translate_tokens

MATCH_GROUP = "m"


@dataclass(frozen=True)
class XqlPattern:
    pattern: str | None
    """RE2 pattern with named groups ``m`` (whole match) and ``g1``..``gN``; ``None`` if not
    translatable."""
    issues: tuple[RegexIssue, ...]
    groups: int = 0


def group_name(group: int) -> str:
    return MATCH_GROUP if group == 0 else f"g{group}"


def xql_regex_literal(pattern: str) -> str:
    """A double-quoted XQL string holding ``pattern`` (see the module docstring)."""
    return '"' + pattern.replace('"', '\\"') + '"'


def _inline_flags(tokens: list[Token]) -> bool:
    return any(
        t.kind is Kind.FLAGS or (t.kind is Kind.GROUP_OPEN and t.group is GroupKind.SCOPED_FLAGS)
        for t in tokens
    )


def to_xql(source: str, *, case_insensitive: bool = False) -> XqlPattern:
    try:
        tokens = tokenize(source)
    except RegexSyntaxError as exc:
        issue = RegexIssue(
            Status.UNSUPPORTED,
            "REGEX_PARSE_ERROR",
            f"Could not parse the Java regex: {exc}. Nothing was translated.",
        )
        return XqlPattern(None, (issue,))
    number = 0
    renamed: list[Token] = []
    for tok in tokens:
        if tok.kind is Kind.GROUP_OPEN and tok.group in (GroupKind.CAPTURE, GroupKind.NAMED):
            number += 1
            name = group_name(number)
            tok = replace(tok, group=GroupKind.NAMED, name=name, text=f"(?P<{name}>")
        renamed.append(tok)
    result = translate_tokens(renamed, "re2")
    # The RE2 findings name Kusto; the engine is the same, the product here is XSIAM.
    relabeled = tuple(
        replace(i, message=i.message.replace("(KQL)", "(XQL)")) for i in result.issues
    )
    if result.pattern is None:
        return XqlPattern(None, relabeled)
    issues = list(relabeled)
    if _inline_flags(tokens):
        issues.append(
            RegexIssue(
                Status.PARTIAL,
                "XSIAM_REGEX_INLINE_FLAGS",
                "The pattern sets regex flags inside the expression. RE2 supports them, but the "
                "XQL documentation only describes a single leading (?i); verify on a tenant.",
            )
        )
    body = f"(?P<{MATCH_GROUP}>{result.pattern})"
    pattern = ("(?i)" if case_insensitive else "") + body
    try:
        opts = re2.Options()
        opts.log_errors = False
        re2.compile(pattern, opts)
    except Exception as exc:  # engine-specific error types
        issues.append(
            RegexIssue(
                Status.UNSUPPORTED,
                "RE2_COMPILE_ERROR",
                f"Translated pattern does not compile with RE2: {exc}",
            )
        )
        return XqlPattern(None, tuple(issues))
    return XqlPattern(pattern, tuple(issues), number)
