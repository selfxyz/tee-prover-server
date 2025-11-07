output "instance_id" {
  description = "ID of the RabbitMQ instance"
  value       = google_compute_instance.rabbitmq.id
}

output "instance_name" {
  description = "Name of the RabbitMQ instance"
  value       = google_compute_instance.rabbitmq.name
}

output "internal_ip" {
  description = "Internal IP address of the RabbitMQ instance"
  value       = google_compute_instance.rabbitmq.network_interface[0].network_ip
}

output "external_ip" {
  description = "External IP address of the RabbitMQ instance"
  value       = google_compute_instance.rabbitmq.network_interface[0].access_config[0].nat_ip
}

output "zone" {
  description = "Zone where the RabbitMQ instance is deployed"
  value       = google_compute_instance.rabbitmq.zone
}

output "rabbitmq_amqp_url" {
  description = "RabbitMQ AMQP connection URL (internal)"
  value       = "amqp://${local.rabbitmq_credentials.rabbitmq_user}:${local.rabbitmq_credentials.rabbitmq_password}@${google_compute_instance.rabbitmq.network_interface[0].network_ip}:5672/"
  sensitive   = true
}

output "rabbitmq_management_url" {
  description = "RabbitMQ Management UI URL (external)"
  value       = "http://${google_compute_instance.rabbitmq.network_interface[0].access_config[0].nat_ip}:15672"
}

output "rabbitmq_management_url_internal" {
  description = "RabbitMQ Management UI URL (internal)"
  value       = "http://${google_compute_instance.rabbitmq.network_interface[0].network_ip}:15672"
}

output "data_disk_id" {
  description = "ID of the RabbitMQ data disk"
  value       = google_compute_disk.rabbitmq_data.id
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "gcloud compute ssh ${google_compute_instance.rabbitmq.name} --zone=${google_compute_instance.rabbitmq.zone} --project=${var.project_id}"
}
