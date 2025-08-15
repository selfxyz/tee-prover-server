# TEE Prover Server Infrastructure

Terraform module for TEE (Trusted Execution Environment) Confidential Compute workloads on Google Cloud.

## What It Creates

- **Instance Template** - Confidential Compute VMs with SEV encryption
- **Managed Instance Group** - Auto-healing and rolling updates  
- **Health Check** - TCP connectivity check on port 8888

Currently configured for **disclose** workloads, designed to extend for `register` and `dsc` types.

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
   disclose_target_size = 2
   disclose_tee_image_reference = "your-container-image:latest"
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
   gcloud compute instances list --filter="name:tee-disclose-instance"
   ```

## Key Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_id` | GCP Project ID | Required |
| `disclose_target_size` | Number of instances | `1` |
| `disclose_tee_image_reference` | Container image | Required |
| `machine_type` | VM machine type | `n2d-standard-16` |
| `zone` | GCP Zone | `us-west1-b` |

## Operations

**Scaling:**
```bash
tofu apply -var="disclose_target_size=3"
```

**Update container image:**
```bash
tofu apply -var="disclose_tee_image_reference=new-image:latest"
```

## Outputs

- `disclose_instance_template_id`
- `disclose_instance_group_manager_id` 
- `disclose_health_check_id`
