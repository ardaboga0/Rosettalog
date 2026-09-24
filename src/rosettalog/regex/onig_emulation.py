"""Run the Oniguruma (Ruby syntax) patterns emitted by the ``onig`` translator on Python ``regex``.

Only the constructs Rosettalog emits are converted; anything else is passed through and will
surface as a compile error. Differences handled: ``\\x{H}`` escapes, ``\\k<name>`` backrefs, Ruby's
``(?m)`` (= dot-all, Python's ``s``), ``\\Z``/``\\z``, always-line-anchored ``^``/``$`` (compiled
with MULTILINE) and class unions of the form ``[A[^B]]``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import regex as pyregex


def _cp(hex_digits: str) -> str:
    cp = int(hex_digits, 16)
    if cp <= 0xFF:
        return f"\\x{cp:02X}"
    return f"\\u{cp:04X}" if cp <= 0xFFFF else f"\\U{cp:08X}"


def _class(pattern: str, i: int) -> tuple[str, int]:
    """Convert one bracket expression starting at ``i``; return (python text, next index)."""
    j = i + 1
    negated = pattern.startswith("^", j)
    if negated:
        j += 1
    members: list[str] = []
    nested: list[str] = []
    while j < len(pattern) and pattern[j] != "]":
        c = pattern[j]
        if c == "\\":
            if pattern.startswith("x{", j + 1):
                end = pattern.index("}", j)
                members.append(_cp(pattern[j + 3 : end]))
                j = end + 1
            else:
                members.append(pattern[j : j + 2])
                j += 2
        elif c == "[":
            inner, j = _class(pattern, j)
            nested.append(inner)
        else:
            members.append(c)
            j += 1
    end = j + 1
    base = "[" + ("^" if negated else "") + "".join(members) + "]"
    if not nested:
        return base, end
    if negated:
        raise ValueError("negated class with nested classes is not emitted by Rosettalog")
    parts = ([base] if members else []) + nested
    return "(?:" + "|".join(parts) + ")", end


def onig_to_python(pattern: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            e = pattern[i + 1]
            if e == "x" and pattern.startswith("{", i + 2):
                end = pattern.index("}", i)
                out.append(_cp(pattern[i + 3 : end]))
                i = end + 1
            elif e == "k" and pattern.startswith("<", i + 2):
                end = pattern.index(">", i)
                out.append(f"(?P={pattern[i + 3 : end]})")
                i = end + 1
            elif e == "Z":
                out.append(r"(?=\n?\Z)")
                i += 2
            elif e == "z":
                out.append(r"\Z")
                i += 2
            else:
                out.append(pattern[i : i + 2])
                i += 2
        elif c == "[":
            text, i = _class(pattern, i)
            out.append(text)
        elif c == "(" and pattern.startswith("(?", i):
            m = pyregex.match(r"\(\?([imx]*)(?:-([imx]*))?([:)])", pattern[i:])
            if m:
                on, off = (m.group(1) or "").replace("m", "s"), (m.group(2) or "").replace("m", "s")
                out.append("(?" + on + ("-" + off if off else "") + m.group(3))
                i += m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


@lru_cache(maxsize=2048)
def compile_onig(pattern: str) -> Any:
    # Ruby syntax: ^/$ always match at line boundaries; \w etc. are emitted as explicit classes.
    return pyregex.compile(onig_to_python(pattern), pyregex.ASCII | pyregex.MULTILINE)
