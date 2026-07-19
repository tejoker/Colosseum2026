# SauronID Terraform module

Installs the local Helm chart (`../helm/sauronid`) as a `helm_release` into an
existing Kubernetes cluster, using your kubeconfig. Usage:

    terraform init && terraform apply -var namespace=sauronid

It deliberately does NOT provision a cluster, registries, DNS, or secrets:
bring an existing cluster, push the images somewhere it can pull, and create
the `existingSecret` with kubectl (see the chart's values.yaml / NOTES.txt) —
keeping secrets out of Terraform state.
