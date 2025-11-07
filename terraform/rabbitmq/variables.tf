variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "instance_name" {
  description = "Name of the RabbitMQ instance"
  type        = string
  default     = "rabbitmq-server"
}

variable "machine_type" {
  description = "Machine type for the RabbitMQ instance"
  type        = string
  default     = "e2-micro"
}

variable "zone" {
  description = "GCP zone for the instance"
  type        = string
  default     = "us-west1-b"
}

variable "network" {
  description = "VPC network for the instance"
  type        = string
  default     = "default"
}

variable "boot_disk_size_gb" {
  description = "Size of the boot disk in GB"
  type        = number
  default     = 50
}

variable "data_disk_size_gb" {
  description = "Size of the RabbitMQ data disk in GB"
  type        = number
  default     = 10
}

variable "service_account_email" {
  description = "Service account email for the instance"
  type        = string
  default     = null
}

variable "network_tags" {
  description = "Network tags for the instance"
  type        = list(string)
  default     = []
}

variable "allowed_source_ranges" {
  description = "CIDR ranges allowed to access RabbitMQ ports"
  type        = list(string)
  default     = ["10.0.0.0/8"] # Default VPC internal range
}

variable "ssh_source_ranges" {
  description = "CIDR ranges allowed SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# RabbitMQ credentials are now read from GCP Secret Manager
# No need for these variables anymore

variable "use_spot_instances" {
  description = "Whether to use spot (preemptible) instances for cost savings"
  type        = bool
  default     = false
}

variable "internal_ip" {
  description = "Fixed internal IP address for the RabbitMQ instance (optional)"
  type        = string
  default     = null
}
