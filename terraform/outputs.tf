output "instance_template_ids" {
  description = "Map of instance template IDs by workload type"
  value       = { for k, v in google_compute_instance_template.tee_templates : k => v.id }
}

output "instance_template_self_links" {
  description = "Map of instance template self links by workload type"
  value       = { for k, v in google_compute_instance_template.tee_templates : k => v.self_link }
}

output "instance_group_manager_ids" {
  description = "Map of managed instance group IDs by workload type"
  value       = { for k, v in google_compute_instance_group_manager.tee_instance_groups : k => v.id }
}

output "instance_group_manager_self_links" {
  description = "Map of managed instance group self links by workload type"
  value       = { for k, v in google_compute_instance_group_manager.tee_instance_groups : k => v.self_link }
}

output "instance_group_manager_status" {
  description = "Map of managed instance group status by workload type"
  value       = { for k, v in google_compute_instance_group_manager.tee_instance_groups : k => v.status }
}

output "health_check_ids" {
  description = "Map of health check IDs by workload type"
  value       = { for k, v in google_compute_health_check.tee_health_checks : k => v.id }
}
