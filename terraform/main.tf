# Instance Template for Confidential Compute - Disclose
resource "google_compute_instance_template" "tee_disclose_template" {
  name_prefix = "tee-disclose-template-"
  description = "Instance template for TEE Confidential Compute disclose workloads"

  machine_type = var.machine_type
  
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
    threads_per_core            = 2
  }

  # Scheduling configuration for confidential compute
  scheduling {
    on_host_maintenance = "MIGRATE"
    min_node_cpus      = var.min_cpu_platform == "AMD Milan" ? 16 : null
  }

  disk {
    source_image = "${var.image_project}/${var.image_family}"
    auto_delete  = true
    boot         = true
    disk_type    = "pd-standard"
    disk_size_gb = var.disk_size_gb
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
    tee-image-reference        = var.disclose_tee_image_reference
    tee-container-log-redirect = "true"
    tee-env-PROJECT_ID        = var.project_id
    tee-env-POOL_NAME         = var.disclose_pool_name
    tee-env-SECRET_ID         = var.disclose_secret_id
    tee-env-PROJECT_NUMBER    = var.project_number
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = var.network_tags
}

# Managed Instance Group - Disclose
resource "google_compute_instance_group_manager" "tee_disclose_instance_group" {
  name = var.disclose_instance_group_name
  zone = var.zone

  base_instance_name = "tee-disclose-instance"
  target_size        = var.disclose_target_size

  version {
    instance_template = google_compute_instance_template.tee_disclose_template.id
  }

  named_port {
    name = "http"
    port = var.disclose_http_port
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.tee_disclose_health_check.id
    initial_delay_sec = var.disclose_health_check_initial_delay
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

# Health Check for the disclose instance group
resource "google_compute_health_check" "tee_disclose_health_check" {
  name = "${var.disclose_instance_group_name}-health-check"

  timeout_sec        = 10
  check_interval_sec = 30

  tcp_health_check {
    port = var.disclose_http_port
  }
}
