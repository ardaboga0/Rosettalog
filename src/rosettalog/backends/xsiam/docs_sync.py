"""Regenerate the doc tables built from the XSIAM ``unknowns.yaml`` (from the repo root)::

uv run python -m rosettalog.backends.xsiam.docs_sync
"""

from __future__ import annotations

import sys
from pathlib import Path

from rosettalog.backends.xsiam.unknowns import generated_docs


def main(root: Path) -> None:
    for path, content in generated_docs(root).items():
        path.write_text(content, encoding="utf-8")
        print(f"updated {path}")


if __name__ == "__main__":  # pragma: no cover
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd())
