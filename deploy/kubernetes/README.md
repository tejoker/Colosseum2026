# Hostile-agent network boundary

Apply `agent-network-isolation.yaml` in every namespace that runs agent
workloads. Label untrusted agent pods `sauronid.io/role=agent` and the core pod
`sauronid.io/role=core`. The policy denies agent ingress and direct egress,
then permits only cluster DNS and TCP/3001 to SauronID core. The core egress
gateway is therefore the only application-layer route to external services.

This manifest requires a CNI that enforces Kubernetes NetworkPolicy. Deployment
validation must include a negative probe from an agent pod to a public IP and
the cloud metadata endpoint, plus a positive probe to the core service. A YAML
file in this repository is not evidence that a particular cluster applied it.

Core itself must not carry the `sauronid.io/role=agent` label: it needs external
network access to the explicitly allowlisted targets, OpenTimestamps calendars,
and configured issuer services. Apply a separate least-privilege policy for the
core based on the deployment's exact dependencies.
