output "disclose_instance_template_id" {
  description = "ID of the disclose instance template"
  value       = google_compute_instance_template.tee_disclose_template.id
}

output "disclose_instance_template_self_link" {
  description = "Self link of the disclose instance template"
  value       = google_compute_instance_template.tee_disclose_template.self_link
}

output "disclose_instance_group_manager_id" {
  description = "ID of the disclose managed instance group"
  value       = google_compute_instance_group_manager.tee_disclose_instance_group.id
}

output "disclose_instance_group_manager_self_link" {
  description = "Self link of the disclose managed instance group"
  value       = google_compute_instance_group_manager.tee_disclose_instance_group.self_link
}

output "disclose_instance_group_manager_status" {
  description = "Status of the disclose managed instance group"
  value       = google_compute_instance_group_manager.tee_disclose_instance_group.status
}

output "disclose_health_check_id" {
  description = "ID of the disclose health check"
  value       = google_compute_health_check.tee_disclose_health_check.id
}
