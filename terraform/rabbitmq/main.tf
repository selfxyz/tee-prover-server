# Data source to read RabbitMQ credentials from Secret Manager
data "google_secret_manager_secret_version" "rabbitmq_credentials" {
  secret = "rabbitmq"
}

locals {
  rabbitmq_credentials = jsondecode(data.google_secret_manager_secret_version.rabbitmq_credentials.secret_data)
}

# RabbitMQ VM Instance
resource "google_compute_instance" "rabbitmq" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  # Boot disk with Ubuntu 24.04
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  # Additional disk for RabbitMQ data
  attached_disk {
    source      = google_compute_disk.rabbitmq_data.id
    device_name = "rabbitmq-data"
  }

  network_interface {
    network    = var.network
    network_ip = var.internal_ip
    access_config {
      # Ephemeral public IP
    }
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  # Scheduling configuration for spot instances
  scheduling {
    preemptible                 = var.use_spot_instances
    on_host_maintenance         = var.use_spot_instances ? "TERMINATE" : "MIGRATE"
    automatic_restart           = !var.use_spot_instances
    provisioning_model          = var.use_spot_instances ? "SPOT" : "STANDARD"
    instance_termination_action = "STOP"
  }

  metadata = {
    startup-script = templatefile("${path.module}/startup-script.sh", {
      rabbitmq_user     = local.rabbitmq_credentials.rabbitmq_user
      rabbitmq_password = local.rabbitmq_credentials.rabbitmq_password
    })
  }

  tags = concat(var.network_tags, ["rabbitmq-server"])

  lifecycle {
    create_before_destroy = false
  }
}

# Persistent disk for RabbitMQ data
resource "google_compute_disk" "rabbitmq_data" {
  name = "${var.instance_name}-data"
  type = "pd-balanced"
  zone = var.zone
  size = var.data_disk_size_gb

  lifecycle {
    prevent_destroy = true
  }
}

# Firewall rule to allow RabbitMQ traffic within VPC
resource "google_compute_firewall" "rabbitmq_internal" {
  name    = "${var.instance_name}-internal"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["5672", "15672", "25672", "4369", "35672-35682"]
  }

  source_ranges = var.allowed_source_ranges
  target_tags   = ["rabbitmq-server"]

  description = "Allow RabbitMQ traffic from specified sources"
}

# Firewall rule to allow SSH access
resource "google_compute_firewall" "rabbitmq_ssh" {
  name    = "${var.instance_name}-ssh"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.ssh_source_ranges
  target_tags   = ["rabbitmq-server"]

  description = "Allow SSH access to RabbitMQ instance"
}
