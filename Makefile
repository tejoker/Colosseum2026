# SauronID Makefile — minimal, opinionated.
.PHONY: help build clean test verify empirical demo demo-strict bench docs

help:  ## Show this help
	@echo "SauronID — agent-binding stack"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build:  ## Build Rust core (release) + TS clients
	cd core && cargo build --release
	cd redteam && (test -d node_modules || npm install --silent) && npm run build --silent
	cd agentic && (test -d node_modules || npm install --silent) && (test -f tsconfig.json && tsc -p . || true)

clean:  ## Remove build artefacts and DB files
	cd core && cargo clean && rm -f sauron.db sauron.db-shm sauron.db-wal
	rm -rf redteam/dist agentic/dist
	rm -f /tmp/sauron-*.log

test:  ## Run cargo test for the workspace
	cd core && cargo test --release --workspace

demo:  ## Quickstart: build + start + invariants (advisory mode)
	./scripts/dev/quickstart.sh

demo-strict:  ## Quickstart in fail-closed mode + 16-attack empirical
	SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh

empirical:  ## Run 16-attack empirical suite against an already-running server
	SAURON_REQUIRE_CALL_SIG=1 \
	  SAURON_CORE_URL=http://127.0.0.1:3001 \
	  SAURON_ADMIN_KEY=$${SAURON_ADMIN_KEY:-super_secret_hackathon_key} \
	  node redteam/dist/scenarios/empirical-suite.js

redteam:  ## Run Tavily-driven autonomous red-team agent (15 attacks; needs running server)
	SAURON_CORE_URL=http://127.0.0.1:3001 \
	  SAURON_ADMIN_KEY=$${SAURON_ADMIN_KEY:-super_secret_hackathon_key} \
	  node redteam/dist/scenarios/tavily-redteam.js

verify: build  ## cargo test + invariants + empirical (full release gate)
	cd core && cargo clippy --release -- -D warnings || true
	cd core && cargo test --release --workspace
	./scripts/dev/quickstart.sh
	SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh

bench:  ## Latency benchmark on /agent/payment/authorize with full call-sig stack
	@./scripts/dev/quickstart.sh > /dev/null 2>&1 && \
	  node redteam/dist/bench/call-sig.js 2>/dev/null || node /tmp/bench-callsig.mjs

docs:  ## Open the empirical comparison doc
	@cat docs/empirical-comparison.md | less

.DEFAULT_GOAL := help
