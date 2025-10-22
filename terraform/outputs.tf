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
  description = "HTTPS load balancer endpoints for each workload"
  value = {
    disclose = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/disclose"
      workload_type = "disclose"
      path          = "/disclose"
      domain        = var.domain
    }
    register = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/register"
      workload_type = "register"
      path          = "/register"
      domain        = var.domain
    }
    register-medium = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/register-medium"
      workload_type = "register-medium"
      path          = "/register-medium"
      domain        = var.domain
    }
    register-large = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/register-large"
      workload_type = "register-large"
      path          = "/register-large"
      domain        = var.domain
    }
    dsc = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/dsc"
      workload_type = "dsc"
      path          = "/dsc"
      domain        = var.domain
    }
    dsc-medium = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/dsc-medium"
      workload_type = "dsc-medium"
      path          = "/dsc-medium"
      domain        = var.domain
    }
    dsc-large = {
      external_ip   = google_compute_global_address.tee_lb_ip.address
      external_port = "443"
      endpoint_url  = "https://${var.domain}/dsc-large"
      workload_type = "dsc-large"
      path          = "/dsc-large"
      domain        = var.domain
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
  description = "HTTP target proxy ID (for redirect)"
  value       = google_compute_target_http_proxy.tee_http_proxy.id
}

output "https_proxy_id" {
  description = "HTTPS target proxy ID"
  value       = google_compute_target_https_proxy.tee_https_proxy.id
}

output "ssl_certificate_id" {
  description = "SSL certificate ID"
  value       = google_compute_managed_ssl_certificate.tee_ssl_cert.id
}

output "ssl_certificate_status" {
  description = "SSL certificate status and details"
  value = {
    certificate_id     = google_compute_managed_ssl_certificate.tee_ssl_cert.id
    domains            = google_compute_managed_ssl_certificate.tee_ssl_cert.managed[0].domains
    creation_timestamp = google_compute_managed_ssl_certificate.tee_ssl_cert.creation_timestamp
  }
}

output "domain_configuration" {
  description = "Domain configuration instructions"
  value = {
    domain          = var.domain
    ip_address      = google_compute_global_address.tee_lb_ip.address
    dns_record_type = "A"
    instructions    = "Create an A record in CloudFlare: ${var.domain} -> ${google_compute_global_address.tee_lb_ip.address}"
  }
}
