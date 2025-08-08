.DEFAULT_GOAL := check
UV ?= uv
COV_MIN ?= 90

.PHONY: setup fmt format-check lint typecheck test cov check demo eval tune bench loc clean

setup:
	$(UV) sync --frozen

fmt:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

format-check: setup
	$(UV) run ruff format --check .

lint: setup
	$(UV) run ruff check .

typecheck: setup
	$(UV) run mypy

test: setup
	$(UV) run pytest

cov: setup
	$(UV) run pytest --cov=trailwatch --cov-report=term --cov-fail-under=$(COV_MIN)

## The one gate: format + lint (zero warnings) + strict types + tests with coverage threshold.
check: format-check lint typecheck cov

demo: setup
	./scripts/demo.sh

## Held-out evaluation (seeds 1001-1005, never used for tuning) with ablations.
eval: setup
	$(UV) run trailwatch eval --seeds 1001-1005 --days 90 --ablations --json eval/heldout.json | tee eval/heldout.md

## Parameter search on the tuning seeds only (1-3).
tune: setup
	$(UV) run trailwatch tune --seeds 1-3 --days 90 --budget 0.05 \
	  --grid scoring.threshold=40,50,60,75,90 --grid scoring.half_life_hours=3,6,12 | tee eval/tune.md

bench: setup
	$(UV) run python scripts/bench.py

loc:
	@echo "source:"; find src -name '*.py' | xargs wc -l | tail -n 1
	@echo "tests:";  find tests -name '*.py' | xargs wc -l | tail -n 1

clean:
	rm -rf demo-out .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist
