# Instance Templates for Confidential Compute workloads
resource "google_compute_instance_template" "tee_templates" {
  for_each = var.workloads

  name_prefix = "tee-${each.key}-template-"
  description = "Instance template for TEE Confidential Compute ${each.key} workloads"

  machine_type = each.value.machine_type

  # Enable confidential computing
  confidential_instance_config {
    enable_confidential_compute = true
  }

  # Shielded VM configuration
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # Advanced machine features for confidential computing
  advanced_machine_features {
    enable_nested_virtualization = false
    threads_per_core             = 2
  }

  # Scheduling configuration for confidential compute
  scheduling {
    on_host_maintenance         = each.value.use_spot_instances ? "TERMINATE" : "MIGRATE"
    preemptible                 = each.value.use_spot_instances
    provisioning_model          = each.value.use_spot_instances ? "SPOT" : "STANDARD"
    automatic_restart           = !each.value.use_spot_instances
    instance_termination_action = each.value.use_spot_instances ? "STOP" : "TERMINATE"
  }

  disk {
    source_image = "${var.image_project}/${var.image_family}"
    auto_delete  = true
    boot         = true
    disk_type    = "pd-balanced"
    disk_size_gb = each.value.disk_size_gb
  }

  network_interface {
    network = var.network
    access_config {
      # Ephemeral public IP
    }
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  metadata = {
    tee-image-reference        = each.value.tee_image_reference
    tee-container-log-redirect = var.image_family == "confidential-space-debug" ? "true" : "false"
    tee-env-PROJECT_ID         = var.project_id
    tee-env-POOL_NAME          = each.value.pool_name
    tee-env-SECRET_ID          = each.value.secret_id
    tee-env-PROJECT_NUMBER     = var.project_number
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = concat(var.network_tags, ["tee-traffic"])
}

# Managed Instance Groups for workloads
resource "google_compute_instance_group_manager" "tee_instance_groups" {
  for_each = var.workloads

  name = each.value.instance_group_name
  zone = var.zone

  base_instance_name = "tee-${each.key}-instance"
  target_size        = each.value.target_size

  version {
    instance_template = google_compute_instance_template.tee_templates[each.key].id
  }

  named_port {
    name = "tee"
    port = 8888
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.tee_health_checks[each.key].id
    initial_delay_sec = each.value.health_check_initial_delay
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = 1
    max_unavailable_fixed          = 0
    replacement_method             = "SUBSTITUTE"
  }
}

# Firewall rule to allow health check traffic to TEE instances
resource "google_compute_firewall" "allow_health_checks" {
  name    = "allow-health-checks-tee"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["8888"]
  }

  # Google Cloud health check IP ranges
  source_ranges = [
    "35.191.0.0/16",  # Google Cloud health check IPs
    "130.211.0.0/22", # Google Cloud health check IPs
    "0.0.0.0/0"       # Allow external traffic through load balancer
  ]

  target_tags = ["tee-traffic"]

  description = "Allow health check traffic to TEE instances"
}

# Firewall rule to allow load balancer traffic to TEE instances
resource "google_compute_firewall" "allow_lb_to_instances" {
  name    = "allow-lb-to-tee-instances"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["8888"]
  }

  # Load balancer IP ranges (Google Cloud load balancer source IPs)
  source_ranges = [
    "35.191.0.0/16",  # Google Cloud load balancer IPs
    "130.211.0.0/22", # Google Cloud load balancer IPs
    "0.0.0.0/0"       # Allow external traffic through load balancer
  ]

  target_tags = ["tee-traffic"]

  description = "Allow load balancer traffic to TEE instances"
}

# Firewall rule to allow external HTTP traffic to load balancer
resource "google_compute_firewall" "allow_external_to_lb" {
  name    = "allow-external-to-tee-lb"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]

  description = "Allow external HTTP traffic to TEE load balancer"
}

# Firewall rule to allow external HTTPS traffic to load balancer
resource "google_compute_firewall" "allow_external_https_to_lb" {
  name    = "allow-external-https-to-tee-lb"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]

  description = "Allow external HTTPS traffic to TEE load balancer"
}

# Health Checks for MIG auto-healing
resource "google_compute_health_check" "tee_health_checks" {
  for_each = var.workloads

  name = "${each.value.instance_group_name}-health-check"

  timeout_sec         = 15
  check_interval_sec  = 60
  healthy_threshold   = 1
  unhealthy_threshold = 5

  tcp_health_check {
    port = 8888
  }
}

# Global TCP Health Checks for Load Balancer
resource "google_compute_health_check" "tee_lb_health_checks" {
  for_each = var.workloads

  name = "${each.value.instance_group_name}-lb-health-check"

  timeout_sec         = 10
  check_interval_sec  = 30
  healthy_threshold   = 1
  unhealthy_threshold = 5

  tcp_health_check {
    port = 8888
  }
}

# Global Backend Services for HTTP Load Balancer
resource "google_compute_backend_service" "tee_backend_services" {
  for_each = var.workloads

  name                  = "${each.key}-backend-service"
  protocol              = "HTTP"
  load_balancing_scheme = "EXTERNAL"
  timeout_sec           = 300

  health_checks = [google_compute_health_check.tee_lb_health_checks[each.key].id]

  backend {
    group          = google_compute_instance_group_manager.tee_instance_groups[each.key].instance_group
    balancing_mode = "UTILIZATION"
  }

  port_name = "tee"

  connection_draining_timeout_sec = 60
}

# Global Static IP for HTTP Load Balancer
resource "google_compute_global_address" "tee_lb_ip" {
  name = "tee-load-balancer-ip"
}

# URL Map for HTTP Load Balancer - routes based on path with path rewriting
resource "google_compute_url_map" "tee_url_map" {
  name            = "tee-url-map"
  default_service = google_compute_backend_service.tee_backend_services["register"].id

  host_rule {
    hosts        = ["*"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.tee_backend_services["register"].id

    path_rule {
      paths   = ["/disclose", "/disclose/*"]
      service = google_compute_backend_service.tee_backend_services["disclose"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }

    path_rule {
      paths   = ["/register", "/register/*"]
      service = google_compute_backend_service.tee_backend_services["register"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }
    path_rule {
      paths   = ["/register-medium", "/register-medium/*"]
      service = google_compute_backend_service.tee_backend_services["register-medium"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }
    path_rule {
      paths   = ["/register-large", "/register-large/*"]
      service = google_compute_backend_service.tee_backend_services["register-large"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }
    path_rule {
      paths   = ["/dsc", "/dsc/*"]
      service = google_compute_backend_service.tee_backend_services["dsc"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }
    path_rule {
      paths   = ["/dsc-medium", "/dsc-medium/*"]
      service = google_compute_backend_service.tee_backend_services["dsc-medium"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }
    path_rule {
      paths   = ["/dsc-large", "/dsc-large/*"]
      service = google_compute_backend_service.tee_backend_services["dsc-large"].id
      route_action {
        url_rewrite {
          path_prefix_rewrite = "/"
        }
      }
    }
  }
}

# URL Map for HTTP to HTTPS redirect
resource "google_compute_url_map" "tee_http_redirect" {
  name = "tee-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

# HTTP Target Proxy (for redirecting to HTTPS)
resource "google_compute_target_http_proxy" "tee_http_proxy" {
  name    = "tee-http-proxy"
  url_map = google_compute_url_map.tee_http_redirect.id
}

# SSL Certificate
resource "google_compute_managed_ssl_certificate" "tee_ssl_cert" {
  name = "tee-ssl-certificate"

  managed {
    domains = [var.domain]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# HTTPS Target Proxy
resource "google_compute_target_https_proxy" "tee_https_proxy" {
  name             = "tee-https-proxy"
  url_map          = google_compute_url_map.tee_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.tee_ssl_cert.id]
}

# Global Forwarding Rule for HTTP Load Balancer (redirect to HTTPS)
resource "google_compute_global_forwarding_rule" "tee_forwarding_rule" {
  name                  = "tee-forwarding-rule"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "80"
  target                = google_compute_target_http_proxy.tee_http_proxy.id
  ip_address            = google_compute_global_address.tee_lb_ip.id
}

# Global Forwarding Rule for HTTPS Load Balancer
resource "google_compute_global_forwarding_rule" "tee_https_forwarding_rule" {
  name                  = "tee-https-forwarding-rule"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.tee_https_proxy.id
  ip_address            = google_compute_global_address.tee_lb_ip.id
}
