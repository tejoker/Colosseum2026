output "release_name" {
  description = "Installed Helm release name."
  value       = helm_release.sauronid.name
}

output "namespace" {
  description = "Namespace the release was installed into."
  value       = helm_release.sauronid.namespace
}

output "release_status" {
  description = "Helm release status."
  value       = helm_release.sauronid.status
}
