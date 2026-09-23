"""Run PCRE patterns (Splunk's dialect) on the Python ``regex`` module.

``regex`` is close to PCRE; this converts the few escapes that are spelled differently. Anything
unknown is passed through unchanged and will surface as a compile error, not a silent change.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import regex as pyregex

_HSPACE = r"\t \xA0\u1680\u180E\u2000-\u200A\u202F\u205F\u3000"
_VSPACE = r"\n-\r\x85\u2028\u2029"


class PcreConversionError(ValueError):
    pass


def _cp(hex_digits: str) -> str:
    cp = int(hex_digits, 16)
    if cp <= 0xFF:
        return f"\\x{cp:02X}"
    return f"\\u{cp:04X}" if cp <= 0xFFFF else f"\\U{cp:08X}"


def pcre_to_python(pattern: str) -> str:
    out: list[str] = []
    i = 0
    in_class = False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            e = pattern[i + 1]
            if e == "x" and pattern.startswith("{", i + 2):
                end = pattern.index("}", i)
                out.append(_cp(pattern[i + 3 : end]))
                i = end + 1
                continue
            if e == "g" and pattern.startswith("{", i + 2):
                end = pattern.index("}", i)
                out.append(f"\\g<{pattern[i + 3 : end]}>")
                i = end + 1
                continue
            if e == "k" and pattern.startswith("<", i + 2):
                end = pattern.index(">", i)
                out.append(f"(?P={pattern[i + 3 : end]})")
                i = end + 1
                continue
            if e in "hv":
                members = _HSPACE if e == "h" else _VSPACE
                out.append(members if in_class else f"[{members}]")
                i += 2
                continue
            if e in "HV":
                if in_class:
                    raise PcreConversionError(f"cannot emulate \\{e} inside a character class")
                out.append(f"[^{_HSPACE if e == 'H' else _VSPACE}]")
                i += 2
                continue
            if e == "R" and not in_class:
                out.append(r"(?>\r\n|[\n-\r\x85\u2028\u2029])")
                i += 2
                continue
            if e == "Z" and not in_class:
                out.append(r"(?=\n?\Z)")
                i += 2
                continue
            if e == "z" and not in_class:
                out.append(r"\Z")
                i += 2
                continue
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
            out.append(c)
            i += 1
            if pattern.startswith("^", i):
                out.append("^")
                i += 1
            if pattern.startswith("]", i):
                out.append(r"\]")
                i += 1
            continue
        if c == "]" and in_class:
            in_class = False
        out.append(c)
        i += 1
    return "".join(out)


@lru_cache(maxsize=2048)
def compile_pcre(pattern: str) -> Any:
    # PCRE without UCP (Splunk's default) treats \w \d \s \b and (?i) as ASCII-only.
    return pyregex.compile(pcre_to_python(pattern), pyregex.ASCII)
