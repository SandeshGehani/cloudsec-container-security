terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "3.5.0"
    }
  }
}

provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}

variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "kube_context" {
  type    = string
  default = "kind-container-security"
}

variable "image" {
  type    = string
  default = "taskboard:hardened"
}

resource "kubernetes_namespace_v1" "app" {
  metadata {
    name = "taskboard-terraform"
  }
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name      = "taskboard"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec {
    replicas = 1
    selector {
      match_labels = { app = "taskboard" }
    }
    template {
      metadata {
        labels = { app = "taskboard" }
      }
      spec {
        automount_service_account_token = false
        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
          fs_group        = 10001
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }
        container {
          name              = "taskboard"
          image             = var.image
          image_pull_policy = "IfNotPresent"
          port {
            container_port = 8080
          }
          security_context {
            privileged                 = false
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 10001
            capabilities {
              drop = ["ALL"]
            }
          }
          resources {
            requests = { cpu = "100m", memory = "64Mi" }
            limits   = { cpu = "500m", memory = "256Mi" }
          }
          readiness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 3
          }
          liveness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 10
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }
        volume {
          name = "tmp"
          empty_dir {
            size_limit = "64Mi"
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "app" {
  metadata {
    name      = "taskboard"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec {
    type     = "ClusterIP"
    selector = { app = "taskboard" }
    port {
      port        = 8080
      target_port = 8080
    }
  }
}

resource "kubernetes_network_policy_v1" "app" {
  metadata {
    name      = "taskboard-isolation"
    namespace = kubernetes_namespace_v1.app.metadata[0].name
  }
  spec {
    pod_selector {
      match_labels = { app = "taskboard" }
    }
    policy_types = ["Ingress", "Egress"]
    ingress {
      from {
        pod_selector {}
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
  }
}
