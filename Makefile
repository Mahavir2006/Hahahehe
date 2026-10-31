# Makefile for CascadeShield - AI-Based Critical Infrastructure Cyber-Risk Prediction

.PHONY: help setup chain deploy test test-chain test-backend test-dashboard lint demo verify-spec clean

# Default target
help:
	@echo "Available targets:"
	@echo "  make setup          - Install Python + Node deps, compile contracts, generate data, train model"
	@echo "  make chain          - Start local Hardhat chain"
	@echo "  make deploy         - Deploy + seed contracts"
	@echo "  make test           - Run all tests (chain + backend + dashboard)"
	@echo "  make test-chain     - Hardhat tests + coverage + gas report"
	@echo "  make test-backend   - Pytest all (offline LLM)"
	@echo "  make test-dashboard - Vitest tests"
	@echo "  make lint           - Python (ruff, mypy) + Solidity (solhint) + TS (eslint, tsc)"
	@echo "  make demo           - Full automated demo (run_demo.py)"
	@echo "  make verify-spec    - Run scripts/verify_spec.py (traceability gate)"
	@echo "  make clean          - Remove generated artifacts"

# ============================================================================
# SETUP
# ============================================================================
setup: install-python install-node install-hardhat compile-contracts generate-data train-model

install-python:
	python -m pip install --upgrade pip
	pip install -r requirements.txt

install-node:
	cd chain && npm install

install-hardhat:
	cd chain && npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox @openzeppelin/contracts @openzeppelin/contracts-upgradeable hardhat-gas-reporter solhint

compile-contracts:
	cd chain && npx hardhat compile

generate-data:
	python data/generate_dataset.py --output-dir data
	python data/build_ml_dataset.py

train-model:
	python -m backend.risk.train_model

evaluate:
	python -m backend.risk.evaluate_model

# ============================================================================
# CHAIN
# ============================================================================
chain:
	cd chain && npx hardhat node

deploy:
	cd chain && npx hardhat run scripts/deploy.ts --network localhost
	cd chain && npx hardhat run scripts/seed.ts --network localhost

# ============================================================================
# TESTS
# ============================================================================
test: test-chain test-backend test-dashboard

test-chain:
	cd chain && npx hardhat test
	cd chain && npx hardhat coverage

test-backend:
	python -m pytest backend/tests -v --tb=short -m "not live_llm"

test-dashboard:
	cd dashboard && npm test

# ============================================================================
# LINT
# ============================================================================
lint: lint-python lint-solidity lint-typescript

lint-python:
	cd backend && ruff check . && mypy .

lint-solidity:
	cd chain && npx solhint contracts/**/*.sol

lint-typescript:
	cd dashboard && npm run lint

# ============================================================================
# DEMO & VERIFY
# ============================================================================
demo:
	python scripts/run_demo.py

verify-spec:
	python scripts/verify_spec.py

# ============================================================================
# CLEAN
# ============================================================================
clean:
	rm -rf chain/artifacts chain/cache chain/coverage chain/deployments
	rm -rf backend/risk/artifacts backend/__pycache__ backend/**/__pycache__
	rm -rf dashboard/node_modules dashboard/dist dashboard/coverage
	rm -rf data/orgs data/advisories data/*.json data/*.csv
	rm -rf docs/VERIFICATION_REPORT.md docs/DECISIONS.md docs/DEVIATIONS.md
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# ============================================================================
# DEVELOPMENT HELPERS
# ============================================================================
# Start all services for development
dev: chain
	@echo "Chain running. In another terminal run: make deploy"
	@echo "Then: cd backend && uvicorn api.main:app --reload"
	@echo "And: cd dashboard && npm run dev"

# Run a specific test file
test-file:
	@if [ -z "$(FILE)" ]; then echo "Usage: make test-file FILE=path/to/test.py"; exit 1; fi
	cd backend && python -m pytest $(FILE) -v --tb=long

# Run tests with coverage
test-cov:
	cd backend && python -m pytest tests/ --cov=backend --cov-report=term-missing --cov-report=html