# Example Terraform variables for RabbitMQ deployment
# Copy this file to terraform.tfvars and customize as needed

# Required: GCP Project ID
project_id = "self-protocol"

# Instance configuration
instance_name = "rabbitmq-server"
machine_type  = "e2-micro"  # Very small instance as requested
zone          = "us-west1-b"

# Network configuration (using default VPC as requested)
network = "default"

# Disk configuration
boot_disk_size_gb = 50  # Ubuntu 24.04 root disk
data_disk_size_gb = 10  # RabbitMQ data disk (balanced disk)

# Optional: Service account (leave null to use default)
# service_account_email = "your-service-account@your-project.iam.gserviceaccount.com"

# Network access configuration
allowed_source_ranges = [
  "10.128.0.0/9",    # Default VPC subnet range
  "10.0.0.0/8",      # Private networks
  "0.0.0.0/0",
]

# SSH access (restrict as needed for security)
ssh_source_ranges = [
  "0.0.0.0/0"  # Allow SSH from anywhere (change for production)
]

# Spot instances for cost savings
use_spot_instances = true

# Fixed internal IP address
internal_ip = "10.138.15.236"

# Optional: Additional network tags
network_tags = ["rabbitmq"]
