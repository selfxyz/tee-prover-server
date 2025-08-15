# TEE Prover Server Infrastructure

This Terraform module provisions Google Cloud infrastructure for running TEE (Trusted Execution Environment) Confidential Compute workloads using managed instance groups.

## What It Does

This module creates:

- **Instance Template** for Confidential Compute VMs with SEV encryption
- **Managed Instance Group** with auto-healing and rolling updates
- **Health Check** for monitoring instance health
- **Auto-scaling** and **auto-healing** capabilities

The infrastructure is specifically configured for:
- ✅ **Confidential Computing** with AMD SEV encryption
- ✅ **Shielded VMs** with secure boot and vTPM
- ✅ **TEE workloads** using Confidential Space images
- ✅ **Container workloads** via metadata configuration

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Instance        │───▶│ Managed Instance │───▶│ Health Check    │
│ Template        │    │ Group            │    │                 │
│ (Confidential)  │    │ (Auto-healing)   │    │ (HTTP /health)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Current Configuration

This module currently supports **disclose** workloads. It's designed to be extended for additional workload types (`register`, `dsc`) in the future.

### Instance Specifications
- **Machine Type**: `n2d-standard-16` (AMD Milan)
- **Image**: Confidential Space debug image
- **Network**: Default VPC with public IP
- **Disk**: 10GB persistent disk
- **Encryption**: AMD SEV (Secure Encrypted Virtualization)

## Prerequisites

1. **OpenTofu/Terraform** (>= 1.6)
2. **Google Cloud SDK** configured with appropriate permissions
3. **GCP Project** with the following APIs enabled:
   ```bash
   gcloud services enable compute.googleapis.com
   gcloud services enable cloudresourcemanager.googleapis.com
   ```
4. **Service Account** with appropriate permissions for Confidential Compute

## Quick Start

### 1. Initialize Backend
```bash
# Create state bucket (one-time setup)
gcloud storage buckets create gs://self-tfstates \
  --project=self-protocol \
  --location=us-central1 \
  --uniform-bucket-level-access

gcloud storage buckets update gs://self-tfstates --versioning
gcloud storage buckets update gs://self-tfstates --retention-period=1d
```

### 2. Configure Variables
Edit `terraform.tfvars` to customize your deployment:

```hcl
# Required
project_id = "your-project-id"

# Optional overrides
region = "us-central1"
zone = "us-west1-b"
disclose_target_size = 2
disclose_tee_image_reference = "your-container-image:latest"
```

### 3. Deploy Infrastructure
```bash
# Initialize Terraform with GCS backend
tofu init

# Review planned changes
tofu plan

# Apply infrastructure
tofu apply
```

### 4. Verify Deployment
```bash
# Check instance group status
gcloud compute instance-groups managed list

# Check instances
gcloud compute instances list --filter="name:tee-disclose-instance"

# View health check status
gcloud compute health-checks list
```

## Configuration

### Key Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_id` | GCP Project ID | Required |
| `region` | GCP Region | `us-central1` |
| `zone` | GCP Zone | `us-west1-b` |
| `disclose_target_size` | Number of instances | `1` |
| `disclose_tee_image_reference` | Container image | TEE server image |
| `machine_type` | VM machine type | `n2d-standard-16` |

### Confidential Computing Settings

The module automatically configures:
- **SEV Encryption**: AMD Secure Encrypted Virtualization
- **Shielded VM**: Secure boot, vTPM, integrity monitoring
- **TEE Metadata**: Container image and environment variables
- **CPU Platform**: AMD Milan (required for Confidential Compute)

## Operations

### Scaling
```bash
# Scale instance group
tofu apply -var="disclose_target_size=3"
```

### Rolling Updates
```bash
# Update container image
tofu apply -var="disclose_tee_image_reference=new-image:latest"
```

### Monitoring
```bash
# View instance group details
gcloud compute instance-groups managed describe tee-disclose-instance-group --zone=us-west1-b

# Check health
gcloud compute backend-services get-health BACKEND_SERVICE_NAME
```

## Troubleshooting

### Common Issues

**Instance fails to start:**
- Check service account permissions
- Verify image reference is accessible
- Review instance logs: `gcloud compute instances get-serial-port-output INSTANCE_NAME`

**Health checks failing:**
- Verify application is listening on port 8080
- Check health endpoint returns 200 status
- Review firewall rules for health check traffic

**Confidential Compute errors:**
- Ensure AMD Milan CPU platform is available in the zone
- Verify project has Confidential Compute enabled
- Check for SEV-compatible machine types

### Logs
```bash
# Instance group manager logs
gcloud logging read "resource.type=gce_instance_group_manager"

# Instance serial console
gcloud compute instances get-serial-port-output INSTANCE_NAME --zone=ZONE
```

## Security Considerations

- ✅ **Confidential Computing** provides memory encryption
- ✅ **Shielded VMs** protect against rootkits and bootkits
- ✅ **Service Account** follows least privilege principle
- ✅ **State encryption** with GCS backend and versioning
- ⚠️ **Public IPs** are used (consider private networking for production)

## Future Enhancements

This module is designed to support multiple workload types:
- [ ] Add `register` workload type
- [ ] Add `dsc` workload type
- [ ] Private networking configuration
- [ ] Load balancer integration
- [ ] Multi-region deployment

## Outputs

The module provides outputs for integration with other infrastructure:

- `disclose_instance_template_id` - Instance template ID
- `disclose_instance_group_manager_id` - Instance group manager ID
- `disclose_health_check_id` - Health check ID

## Support

For issues related to:
- **Terraform configuration**: Check this README and variable descriptions
- **GCP Confidential Compute**: Review [Google Cloud documentation](https://cloud.google.com/confidential-computing)
- **TEE containers**: Check container logs and metadata configuration
