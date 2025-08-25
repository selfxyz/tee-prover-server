# TEE Prover Server Infrastructure

OpenTofu/Terraform module for TEE (Trusted Execution Environment) Confidential Compute workloads on Google Cloud with HTTP load balancing.

## What It Creates

- **Instance Templates** - Confidential Compute VMs with SEV encryption
- **Managed Instance Groups** - Auto-healing and rolling updates
- **Health Checks** - TCP connectivity check on port 8888
- **HTTP Load Balancer** - Single global load balancer with path-based routing
- **URL Map** - Routes traffic to different workloads based on URL path
- **Backend Services** - Global HTTP backend services for each workload

Supports **disclose**, **register**, and **dsc** workload types simultaneously on a single HTTP load balancer.

## Instance Configuration
- **Machine Types**:
  - Disclose: `n2d-standard-4`
  - Register: `n2d-highmem-64` (high memory for heavy processing)
  - DSC: `n2d-highmem-32`
- **Image**: Confidential Space debug
- **Encryption**: AMD SEV with Confidential Computing
- **Network**: Default VPC with public IP
- **Port**: All services run on port 8888

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

   # Test HTTP load balancer endpoints
   curl -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "method": "openpassport_health", "params": [], "id": 1}' \
     http://[LOAD_BALANCER_IP]/disclose

   curl -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "method": "openpassport_health", "params": [], "id": 1}' \
     http://[LOAD_BALANCER_IP]/register

   curl -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "method": "openpassport_health", "params": [], "id": 1}' \
     http://[LOAD_BALANCER_IP]/dsc
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
- `tee_port` (default: 8888), `health_check_initial_delay`
- `use_spot_instances` (for cost optimization)

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
- `load_balancer_ip` - External IP address of the HTTP load balancer
- `load_balancer_endpoints` - Map of HTTP endpoints for each workload
- `backend_service_ids` - Map of backend service IDs by workload type
- `url_map_id` - URL map ID for the HTTP load balancer
- `http_proxy_id` - HTTP target proxy ID

## HTTP Load Balancer Architecture

The infrastructure creates a single global HTTP load balancer with path-based routing:

- **Base URL**: `http://[LOAD_BALANCER_IP]`
- **Disclose endpoint**: `http://[LOAD_BALANCER_IP]/disclose`
- **Register endpoint**: `http://[LOAD_BALANCER_IP]/register`
- **DSC endpoint**: `http://[LOAD_BALANCER_IP]/dsc`

### Path Rewriting

The load balancer automatically rewrites paths before forwarding to backend instances:
- `/disclose` → `/` (forwarded to disclose backend)
- `/register` → `/` (forwarded to register backend)
- `/dsc` → `/` (forwarded to dsc backend)

This allows your TEE servers to continue serving at the root path (`/`) while providing clean, path-based routing for external clients.

## Health Checks

- **Type**: TCP health checks on port 8888
- **Intervals**:
  - MIG health checks: 60 seconds
  - Load balancer health checks: 30 seconds
- **Timeouts**: 10-15 seconds
- **Initial delay**: 300-900 seconds (varies by workload complexity)

## Troubleshooting

### Check Backend Health
```bash
gcloud compute backend-services get-health [WORKLOAD]-backend-service --global
```

### Debug Container Issues (SSH into instance)
```bash
# Check container status
sudo crictl ps -a

# Check container logs
sudo crictl logs [CONTAINER_ID]

# Check container runner service
sudo systemctl status container-runner.service
sudo journalctl -u container-runner.service -f
```

### Common Issues

1. **502 Bad Gateway**: Backend instances are unhealthy
   - Check container startup logs
   - Verify health check configuration
   - Ensure sufficient startup time

2. **Container not starting**:
   - Check metadata service access
   - Verify image registry permissions
   - Check resource constraints (memory/CPU)

3. **Context canceled errors**:
   - Increase `health_check_initial_delay`
   - Use larger machine types for resource-intensive workloads
   - Check metadata service connectivity
