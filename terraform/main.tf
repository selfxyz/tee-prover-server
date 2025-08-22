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
    on_host_maintenance = each.value.use_spot_instances ? "TERMINATE" : "MIGRATE"
    preemptible = each.value.use_spot_instances
    provisioning_model = each.value.use_spot_instances ? "SPOT" : "STANDARD"
    automatic_restart = !each.value.use_spot_instances
    instance_termination_action = "STOP"
  }

  disk {
    source_image = "${var.image_project}/${var.image_family}"
    auto_delete  = true
    boot         = true
    disk_type    = "pd-standard"
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
    tee-container-log-redirect = "true"
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
    port = each.value.tee_port
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.tee_health_checks[each.key].id
    initial_delay_sec = each.value.health_check_initial_delay
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = 0
    max_unavailable_fixed          = 2
    replacement_method             = "RECREATE"
  }
}

# Firewall rule to allow health check traffic to TEE instances
resource "google_compute_firewall" "allow_health_checks" {
  name    = "allow-health-checks-tee"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = toset([for workload in var.workloads : tostring(workload.tee_port)])
  }

  # Google Cloud health check IP ranges
  source_ranges = [
    "35.191.0.0/16",    # Google Cloud health check IPs
    "130.211.0.0/22"    # Google Cloud health check IPs  
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
    ports    = toset([for workload in var.workloads : tostring(workload.tee_port)])
  }

  # Load balancer IP ranges (Google Cloud load balancer source IPs)
  source_ranges = [
    "35.191.0.0/16",     # Google Cloud load balancer IPs
    "130.211.0.0/22"     # Google Cloud load balancer IPs
  ]

  target_tags = ["tee-traffic"]
  
  description = "Allow load balancer traffic to TEE instances"
}

# Firewall rule to allow external traffic to load balancer ports
resource "google_compute_firewall" "allow_external_to_lb" {
  name    = "allow-external-to-tee-lb"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = [for k, v in local.workload_external_ports : v]
  }

  source_ranges = ["0.0.0.0/0"]
  
  description = "Allow external traffic to TEE load balancer ports"
}

# Health Checks for MIG auto-healing
resource "google_compute_health_check" "tee_health_checks" {
  for_each = var.workloads

  name = "${each.value.instance_group_name}-health-check"

  timeout_sec        = 10
  check_interval_sec = 30

  tcp_health_check {
    port = each.value.tee_port
  }
}

# Regional TCP Health Checks for Load Balancer
resource "google_compute_region_health_check" "tee_lb_health_checks" {
  for_each = var.workloads

  name   = "${each.value.instance_group_name}-lb-health-check"
  region = var.region

  timeout_sec         = 5
  check_interval_sec  = 10
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = each.value.tee_port
  }
}

# Regional Backend Services for Load Balancer
resource "google_compute_region_backend_service" "tee_backend_services" {
  for_each = var.workloads

  name                  = "${each.key}-backend-service"
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "EXTERNAL"

  health_checks = [google_compute_region_health_check.tee_lb_health_checks[each.key].id]

  backend {
    group = google_compute_instance_group_manager.tee_instance_groups[each.key].instance_group
  }

  connection_draining_timeout_sec = 60
}

# Static IP for Load Balancer
resource "google_compute_address" "tee_lb_ip" {
  name   = "tee-load-balancer-ip"
  region = var.region
}

# Network Load Balancer Forwarding Rules (one per workload)
resource "google_compute_forwarding_rule" "tee_forwarding_rules" {
  for_each = var.workloads

  name                  = "${each.key}-forwarding-rule"
  region                = var.region
  ip_address            = google_compute_address.tee_lb_ip.id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  
  # Use different external ports for each workload
  port_range = local.workload_external_ports[each.key]
  
  backend_service = google_compute_region_backend_service.tee_backend_services[each.key].id
}

# Local values for external port mapping
locals {
  workload_external_ports = {
    disclose = "8880"
    register = "8881" 
    dsc      = "8882"
  }
}
