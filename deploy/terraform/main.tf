terraform {
  required_version = ">= 1.5"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kubeconfig_context
  }
}

resource "helm_release" "sauronid" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = true
  chart            = "${path.module}/../helm/sauronid"

  set {
    name  = "core.image.tag"
    value = var.core_image_tag
  }

  set {
    name  = "dashboard.image.tag"
    value = var.dashboard_image_tag
  }

  # Arbitrary chart value overrides (secrets stay out of terraform state:
  # create the existingSecret with kubectl, not here).
  values = [yamlencode(var.values)]
}
