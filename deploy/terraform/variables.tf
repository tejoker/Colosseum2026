variable "kubeconfig_path" {
  description = "Path to the kubeconfig for the target cluster."
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Kubeconfig context to use (empty = current context)."
  type        = string
  default     = ""
}

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "sauronid"
}

variable "namespace" {
  description = "Namespace to install into (created if missing)."
  type        = string
  default     = "sauronid"
}

variable "core_image_tag" {
  description = "Image tag for the core deployment."
  type        = string
  default     = "latest"
}

variable "dashboard_image_tag" {
  description = "Image tag for the dashboard deployment."
  type        = string
  default     = "latest"
}

variable "values" {
  description = "Chart value overrides, merged over deploy/helm/sauronid/values.yaml."
  type        = any
  default     = {}
}
