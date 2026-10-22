.PHONY: help install test lint fmt typecheck check run demo serve eval docker-build up down clean-demo

help:  ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-14s %s\n", $$1, $$2}'

install:  ## Install with dev extras (editable)
	pip install -e ".[dev]"

test:  ## Run the test suite (network-free)
	pytest

lint:  ## ruff lint + format check
	ruff check .
	ruff format --check .

fmt:  ## Auto-format and fix lint
	ruff format .
	ruff check --fix .

typecheck:  ## mypy (strict)
	mypy vulntriage

check: lint typecheck test  ## Everything CI runs

run:  ## One real pipeline run (needs Docker + Trivy)
	vulntriage run

demo:  ## Full pipeline on bundled fixtures, then serve the dashboard
	vulntriage run --demo
	vulntriage serve --demo

serve:  ## Dashboard on 127.0.0.1:8080
	vulntriage serve

eval:  ## Regenerate docs/EVALUATION.md from the demo dataset
	vulntriage eval --demo

docker-build:  ## Build the container image
	docker build -f docker/Dockerfile -t vulntriage:local .

up:  ## docker compose up (dashboard on 127.0.0.1:8080)
	docker compose up -d --build

down:  ## Stop the stack (keeps volumes)
	docker compose down

clean-demo:  ## Remove the demo database and demo reports only
	rm -rf data/demo reports/demo
