variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
}

variable "zone" {
  description = "The GCP zone for the instance group"
  type        = string
}

variable "image_project" {
  description = "Project containing the image"
  type        = string
}

variable "image_family" {
  description = "Image family to use"
  type        = string
}

variable "network" {
  description = "Network for the instances"
  type        = string
  default     = "default"
}

variable "service_account_email" {
  description = "Service account email for the instances"
  type        = string
}

variable "project_number" {
  description = "GCP project number"
  type        = string
}

variable "network_tags" {
  description = "Network tags for the instances"
  type        = list(string)
  default     = []
}

# Domain configuration
variable "domain" {
  description = "Domain name for the TEE services (e.g., tee.self.xyz)"
  type        = string
}

# Workload configurations map
variable "workloads" {
  description = "Map of workload configurations for different TEE types"
  type = map(object({
    machine_type               = string
    min_cpu_platform           = string
    disk_size_gb               = number
    tee_image_reference        = string
    instance_group_name        = string
    target_size                = number
    pool_name                  = string
    secret_id                  = string
    tee_port                   = number
    health_check_path          = string
    health_check_initial_delay = number
    use_spot_instances         = bool
  }))
}
