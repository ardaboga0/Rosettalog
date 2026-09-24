"""Build Elasticsearch grok patterns from Java regexes.

Grok only turns *named* captures into document fields, and in Oniguruma's Ruby syntax the
presence of named groups can stop unnamed groups from capturing. Every capture group is therefore
renamed to ``<prefix>_g<N>`` (N = its Java group number) and numeric/named backreferences are
rewired. The whole pattern is wrapped in ``(?<prefix>_m ...)`` so that "the pattern matched" is
observable even when all groups are empty. The body is emitted by the ``onig`` translator.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import regex as pyregex

from rosettalog.ir.findings import Status
from rosettalog.regex.onig_emulation import onig_to_python
from rosettalog.regex.tokenizer import GroupKind, Kind, RegexSyntaxError, tokenize
from rosettalog.regex.translate import RegexIssue, translate_tokens


@dataclass(frozen=True)
class GrokPattern:
    pattern: str | None
    """Oniguruma pattern for a grok ``patterns`` entry, or ``None`` if not translatable."""
    issues: tuple[RegexIssue, ...]
    match_field: str
    """Field set (possibly to "") whenever the pattern matched."""
    groups: int = 0
    """Number of capture groups, each extracted as ``<prefix>_g<N>``."""

    def group_field(self, group: int) -> str:
        return (
            self.match_field if group == 0 else self.match_field.removesuffix("_m") + f"_g{group}"
        )


def to_grok(source: str, prefix: str, *, case_insensitive: bool = False) -> GrokPattern:
    match_field = f"{prefix}_m"
    try:
        tokens = tokenize(source)
    except RegexSyntaxError as exc:
        issue = RegexIssue(
            Status.UNSUPPORTED,
            "REGEX_PARSE_ERROR",
            f"Could not parse the Java regex: {exc}. Nothing was translated.",
        )
        return GrokPattern(None, (issue,), match_field)
    names: dict[str, str] = {}
    number = 0
    renamed = []
    for tok in tokens:
        if tok.kind is Kind.GROUP_OPEN and tok.group in (GroupKind.CAPTURE, GroupKind.NAMED):
            number += 1
            new_name = f"{prefix}_g{number}"
            if tok.group is GroupKind.NAMED:
                names[tok.name] = new_name
            tok = replace(tok, group=GroupKind.NAMED, name=new_name, text=f"(?<{new_name}>")
        renamed.append(tok)
    tokens = [
        replace(t, ref=f"{prefix}_g{t.ref}" if isinstance(t.ref, int) else names.get(t.ref, t.ref))
        if t.kind is Kind.BACKREF and t.ref is not None
        else t
        for t in renamed
    ]
    result = translate_tokens(tokens, "onig")
    if result.pattern is None:
        return GrokPattern(None, result.issues, match_field)
    body = ("(?i)" if case_insensitive else "") + result.pattern
    pattern = f"(?<{match_field}>{body})"
    try:
        pyregex.compile(onig_to_python(pattern))
    except (pyregex.error, ValueError) as exc:  # our own emission must always be valid
        issue = RegexIssue(
            Status.UNSUPPORTED, "REGEX_COMPILE_ERROR", f"Generated grok pattern is invalid: {exc}"
        )
        return GrokPattern(None, (*result.issues, issue), match_field)
    return GrokPattern(pattern, result.issues, match_field, number)
