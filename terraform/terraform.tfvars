project_id = "self-protocol"

# Domain configuration
domain = "tee.self.xyz"

# Infrastructure settings
region = "us-west1"
zone   = "us-west1-b"

# Confidential Computing settings
image_project = "confidential-space-images"
# image_family  = "confidential-space-debug" # Debug image
image_family  = "confidential-space" # Production image

# Service account
service_account_email = "self-protocol-workload@self-protocol.iam.gserviceaccount.com"
project_number        = "1025466915061"

# Network settings
network      = "default"
network_tags = []

# Workload configurations
workloads = {
  # Lower resource usage
  disclose = {
    machine_type               = "n2d-standard-4"
    # min_cpu_platform           = "Intel Sapphire Rapids"
    # confidential_instance_type = "TDX"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 40
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-disclose:latest"
    instance_group_name        = "tee-disclose-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 300
    use_spot_instances         = true
  }
  register = {
    machine_type               = "n2d-highmem-48"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 100
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-register:latest"
    instance_group_name        = "tee-register-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 1500
    use_spot_instances         = true
  }
  register-medium = {
    machine_type               = "n2d-highmem-48"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 100
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-register-medium:latest"
    instance_group_name        = "tee-register-medium-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 1500
    use_spot_instances         = true
  }
  register-large = {
    machine_type               = "n2d-highmem-48"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 100
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-register-large:latest"
    instance_group_name        = "tee-register-large-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 1500
    use_spot_instances         = true
  }
  dsc = {
    machine_type               = "n2d-highmem-32"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 50
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-dsc:latest"
    instance_group_name        = "tee-dsc-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 300
    use_spot_instances         = true
  }
  dsc-medium = {
    machine_type               = "n2d-highmem-32"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 50
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-dsc-medium:latest"
    instance_group_name        = "tee-dsc-medium-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 300
    use_spot_instances         = true
  }
  dsc-large = {
    machine_type               = "n2d-highmem-32"
    min_cpu_platform           = "AMD Milan"
    confidential_instance_type = "SEV_SNP"
    disk_size_gb               = 50
    tee_image_reference        = "us-docker.pkg.dev/self-protocol/self-protocol-repository/tee-server-dsc-large:latest"
    instance_group_name        = "tee-dsc-large-instance-group"
    target_size                = 1
    pool_name                  = "cs-pool"
    secret_id                  = "DB_URL"
    tee_port                   = 8888
    health_check_path          = ""
    health_check_initial_delay = 300
    use_spot_instances         = true
  }

}
