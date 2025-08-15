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

variable "machine_type" {
  description = "Machine type for the instances"
  type        = string
}

variable "min_cpu_platform" {
  description = "Minimum CPU platform for confidential computing"
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

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 10
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

# Disclose-specific variables
variable "disclose_tee_image_reference" {
  description = "TEE container image reference for disclose workloads"
  type        = string
}

variable "disclose_pool_name" {
  description = "Pool name for TEE disclose environment"
  type        = string
}

variable "disclose_secret_id" {
  description = "Secret ID for TEE disclose environment"
  type        = string
}

variable "disclose_instance_group_name" {
  description = "Name of the disclose managed instance group"
  type        = string
}

variable "disclose_target_size" {
  description = "Target number of instances in the disclose group"
  type        = number
  default     = 1
}

variable "disclose_http_port" {
  description = "HTTP port for disclose health checks"
  type        = number
  default     = 8080
}

variable "disclose_health_check_path" {
  description = "Path for disclose health check"
  type        = string
  default     = "/health"
}

variable "disclose_health_check_initial_delay" {
  description = "Initial delay for disclose health check in seconds"
  type        = number
  default     = 300
}
