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

# HTTP Load Balancer Outputs
output "load_balancer_ip" {
  description = "External IP address of the HTTP load balancer"
  value       = google_compute_global_address.tee_lb_ip.address
}

output "load_balancer_endpoints" {
  description = "HTTP load balancer endpoints for each workload"
  value = {
    disclose = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "80"
      endpoint_url  = "http://${google_compute_global_address.tee_lb_ip.address}/disclose"
      workload_type = "disclose"
      path         = "/disclose"
    }
    register = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "80"
      endpoint_url  = "http://${google_compute_global_address.tee_lb_ip.address}/register"
      workload_type = "register"
      path         = "/register"
    }
    dsc = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "80"
      endpoint_url  = "http://${google_compute_global_address.tee_lb_ip.address}/dsc"
      workload_type = "dsc"
      path         = "/dsc"
    }
  }
}

output "backend_service_ids" {
  description = "Map of backend service IDs by workload type"
  value       = { for k, v in google_compute_backend_service.tee_backend_services : k => v.id }
}

output "url_map_id" {
  description = "URL map ID for the HTTP load balancer"
  value       = google_compute_url_map.tee_url_map.id
}

output "http_proxy_id" {
  description = "HTTP target proxy ID"
  value       = google_compute_target_http_proxy.tee_http_proxy.id
}
