"""Fixture policy: IPv4 addresses in examples/ and tests/ must be documentation or private ones.

Allowed: RFC 5737 documentation ranges and RFC 1918 private ranges. ``0.0.0.0`` is allowed only in
the files listed in ``UNSPECIFIED_ALLOWED``, where it has a documented meaning. Anything else
(public, loopback, link-local, multicast, ...) fails this test.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from tests.conftest import EXAMPLES, ROOT

ALLOWED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24",  # RFC 5737 TEST-NET-1
        "198.51.100.0/24",  # RFC 5737 TEST-NET-2
        "203.0.113.0/24",  # RFC 5737 TEST-NET-3
        "10.0.0.0/8",  # RFC 1918
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
    )
]
UNSPECIFIED_ALLOWED = {
    # QRadar shows 0.0.0.0 for IP properties an extension did not set.
    "examples/confirmation/README.md": "QRadar default for unset IP properties",
    "tests/unit/test_fixture_hygiene.py": "this file documents the rule",
}
DOTTED_QUAD = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
SKIP_DIRS = {"__pycache__", ".pytest_cache"}


def _text_files() -> list[Path]:
    files = []
    for base in (EXAMPLES, ROOT / "tests"):
        for path in base.rglob("*"):
            if path.is_file() and not SKIP_DIRS & set(path.parts):
                files.append(path)
    return files


def violations(text: str, rel: str) -> list[str]:
    found = []
    for match in DOTTED_QUAD.finditer(text):
        try:
            addr = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue  # not an address (e.g. an octet > 255)
        if addr.is_unspecified:
            if rel not in UNSPECIFIED_ALLOWED:
                found.append(f"{rel}: {addr} (0.0.0.0 needs a documented meaning)")
        elif not any(addr in net for net in ALLOWED_NETWORKS):
            found.append(f"{rel}: {addr}")
    return found


def test_only_documentation_and_private_ipv4_in_fixtures() -> None:
    problems = []
    for path in _text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        problems += violations(text, path.relative_to(ROOT).as_posix())
    assert not problems, "Forbidden IPv4 addresses:\n" + "\n".join(problems)


def test_checker_rejects_public_and_special_addresses() -> None:
    public = ".".join(["8", "8", "8", "8"])
    loopback = ".".join(["127", "0", "0", "1"])
    unspecified = ".".join(["0"] * 4)
    assert violations(f"a {public} b", "x") == [f"x: {public}"]
    assert violations(loopback, "x") == [f"x: {loopback}"]
    assert violations(unspecified, "x")
    assert not violations(unspecified, "examples/confirmation/README.md")
    parts = (
        ["192", "0", "2", "7"],
        ["10", "1", "2", "3"],
        ["172", "20", "0", "1"],
        ["192", "168", "1", "1"],
    )
    ok = " ".join(".".join(p) for p in parts)
    assert not violations(ok, "x")
    assert not violations("version 1.2.3.4.5 and 999.1.1.1", "x")
