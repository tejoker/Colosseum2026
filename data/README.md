# `data/` — operational utilities (not a synthetic dataset factory)

This repository's objective is **SauronID**: a cryptographic agent-binding stack (Rust core, ZKP issuer, agentic A-JWT, per-call signatures, anchoring, UIs) for any company deploying AI agents. The **Python KYC adapter** for bank-style user upserts lives under **`legacy/KYC/`** and is optional. Runtime truth lives in **core + your databases**, not in generated CSVs.

What remains here:

- **`ingest/`** — optional protobuf fraud-ingest service (companies send `Event` batches; risk scoring + SSE). Wire it in your own deployment if you use that path.
- **`proto/`** — protobuf definitions for ingest.
- **`sauron/`** — internal **analytics API** (`app.py`) that reads the live Rust backend (`SAURON_URL`) and, if you add them yourself, optional parquet files under `sauron/data/` for extra dashboard charts.

Dev seeding for the Rust backend is **`core/seed.sh`** (HTTP-only minimal clients + users). There is no bundled synthetic persona/companies pipeline anymore.
