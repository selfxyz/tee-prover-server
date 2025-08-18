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
    on_host_maintenance = "MIGRATE"
    min_node_cpus       = each.value.min_cpu_platform == "AMD Milan" ? 16 : null
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

  tags = var.network_tags
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
    name = "http"
    port = each.value.http_port
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

# Health Checks for workloads
resource "google_compute_health_check" "tee_health_checks" {
  for_each = var.workloads

  name = "${each.value.instance_group_name}-health-check"

  timeout_sec        = 10
  check_interval_sec = 30

  tcp_health_check {
    port = each.value.http_port
  }
}
