#!/bin/bash
set -e
echo "=== Sauron analytics API (live Rust + optional local parquets) ==="
exec uvicorn app:app --host 0.0.0.0 --port 8002
