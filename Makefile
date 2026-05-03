# Sanctum — convenience targets. Thin wrappers around scripts/ and the
# project's Python tooling. The substantive logic lives in scripts/ to keep
# behaviour identical whether invoked via make, the shell, or CI.

.PHONY: help test lint format smoke check-secrets submission-dry-run report eval-report

help:
	@echo "Sanctum make targets:"
	@echo "  test                — pytest"
	@echo "  lint                — ruff check ."
	@echo "  format              — black ."
	@echo "  smoke               — MCP stdio handshake smoke test"
	@echo "  check-secrets       — scan tracked files for secrets / framework leakage"
	@echo "  submission-dry-run  — stash .claude/, run checks, restore (verifies"
	@echo "                        Sanctum stands without private framework tooling)"
	@echo "  report              — generate self-contained HTML case report from ledger"
	@echo "                        (requires SANCTUM_LEDGER_HMAC_KEY; optional --case filter)"
	@echo "  eval-report         — generate HTML accuracy report from latest EvalReport JSON"
	@echo "                        (pass ARGS='path/to/report.json' to target a specific run)"

test:
	pytest -q

lint:
	ruff check .

format:
	black .

smoke:
	./scripts/smoke_test_mcp_stdio.sh

check-secrets:
	./scripts/check_no_secrets.sh

submission-dry-run:
	./scripts/submission_dry_run.sh

report:
	python3 scripts/generate_report.py $(ARGS)

eval-report:
	python3 scripts/generate_eval_report.py $(ARGS)
