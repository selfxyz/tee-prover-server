# TEE Prover Server Infrastructure

Terraform module for TEE (Trusted Execution Environment) Confidential Compute workloads on Google Cloud.

## What It Creates

- **Instance Templates** - Confidential Compute VMs with SEV encryption
- **Managed Instance Groups** - Auto-healing and rolling updates  
- **Health Checks** - TCP connectivity check on configured ports

Supports **disclose**, **register**, and **dsc** workload types simultaneously.

## Instance Configuration
- **Machine**: `n2d-standard-16` (AMD Milan)
- **Image**: Confidential Space debug
- **Encryption**: AMD SEV
- **Network**: Default VPC with public IP

## Prerequisites

- **OpenTofu/Terraform** (>= 1.6)
- **Google Cloud SDK** with appropriate permissions
- **GCP APIs enabled**: `compute.googleapis.com`

## Usage

1. **Configure variables** in `terraform.tfvars`:
   ```hcl
   project_id = "your-project-id"
   
   workloads = {
     disclose = {
       target_size = 2
       tee_image_reference = "your-disclose-image:latest"
       # ... other settings
     }
     register = {
       target_size = 1
       tee_image_reference = "your-register-image:latest"
       # ... other settings  
     }
     dsc = {
       target_size = 1
       tee_image_reference = "your-dsc-image:latest"
       # ... other settings
     }
   }
   ```

2. **Deploy**:
   ```bash
   tofu init
   tofu plan
   tofu apply
   ```

3. **Verify**:
   ```bash
   gcloud compute instance-groups managed list
   gcloud compute instances list --filter="name~'tee-(disclose|register|dsc)-instance'"
   ```

## Key Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_id` | GCP Project ID | Required |
| `workloads` | Map of workload configurations | Required |
| `zone` | GCP Zone | `us-west1-b` |

Each workload in the `workloads` map supports:
- `machine_type`, `target_size`, `tee_image_reference`
- `instance_group_name`, `pool_name`, `secret_id`
- `http_port`, `health_check_path`, etc.

## Operations

**Scaling specific workload:**
Edit `terraform.tfvars` and modify `target_size` for any workload, then:
```bash
tofu apply
```

**Update container image:**
Edit `terraform.tfvars` and modify `tee_image_reference` for any workload, then:
```bash
tofu apply
```

## Outputs

- `instance_template_ids` - Map of template IDs by workload type
- `instance_group_manager_ids` - Map of instance group IDs by workload type  
- `health_check_ids` - Map of health check IDs by workload type
