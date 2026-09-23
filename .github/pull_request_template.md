## What and why

<!-- Short description. Link issues with "Fixes #123". -->

## Checklist

- [ ] Tests added/updated; `uv run pytest`, `uv run mypy src`, `uv run ruff check .` pass
- [ ] Golden files regenerated (`pytest --update-golden`) and the diff is explained above, if output changed
- [ ] Every untranslatable or approximated construct produces a finding; new codes are in `docs/findings-codes.md`
- [ ] `docs/lsx-support-matrix.md` updated if translation behaviour changed
- [ ] All fixtures/examples are **synthetic or from public documentation** (no vendor-shipped content, no real logs)
