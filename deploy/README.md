# Deploy index

Pick the file for your scenario:

| Scenario | Use |
|---|---|
| Just try it (one command, dev mode, seeded demo data) | `docker-compose.yml` at the **repo root**: `docker compose up` |
| Local full dev stack incl. Hardhat EVM node | `deploy/docker-compose.yml` (requires `SAURON_ADMIN_KEY` in env or `.env`) |
| Production-shaped compose (no default secrets, fail-closed flags pinned) | `deploy/docker-compose.prod.yml` |
| Single-VM public demo behind Caddy TLS | `deploy/docker-compose.deploy.yml` + `deploy.sh` + `.env.deploy.example` |
| Local Postgres for the core's postgres backend | `deploy/docker-compose-postgres.yml` |
| Native systemd units on a VM (no Docker) | `deploy/native/` (`vm-setup.sh`, `*.service`, env examples) |
| Kubernetes via Helm | `deploy/helm/sauronid/` (`helm install sauronid deploy/helm/sauronid`; create the secret first — see chart NOTES.txt) |
| Kubernetes via Terraform (wraps the Helm chart, existing cluster only) | `deploy/terraform/` |
| Raw agent network isolation manifests (non-Helm clusters) | `deploy/kubernetes/agent-network-isolation.yaml` (see its README) |
| AWS Nitro Enclaves attestation build | `deploy/nitro/` |
