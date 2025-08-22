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

# Load Balancer Outputs
output "load_balancer_ip" {
  description = "External IP address of the load balancer"
  value       = google_compute_address.tee_lb_ip.address
}

output "load_balancer_endpoints" {
  description = "Load balancer endpoints for each workload"
  value = {
    for k, v in google_compute_forwarding_rule.tee_forwarding_rules : k => {
      external_ip   = google_compute_address.tee_lb_ip.address
      external_port = local.workload_external_ports[k]
      endpoint_url  = "${google_compute_address.tee_lb_ip.address}:${local.workload_external_ports[k]}"
      workload_type = k
    }
  }
}

output "backend_service_ids" {
  description = "Map of backend service IDs by workload type"
  value       = { for k, v in google_compute_region_backend_service.tee_backend_services : k => v.id }
}
