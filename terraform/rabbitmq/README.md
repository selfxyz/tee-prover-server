# RabbitMQ + Redis Terraform Module

Simple Terraform module to deploy RabbitMQ and Redis on Google Cloud Platform using a single VM with Docker.

## Features

- **Simple VM deployment** - Single GCP VM running Ubuntu 24.04
- **Docker-based RabbitMQ** - Uses official `rabbitmq:4-management` image
- **Docker-based Redis** - Uses official `redis:7-alpine` image with persistence
- **Shared persistent storage** - 10GB balanced disk shared between RabbitMQ and Redis
- **VPC integration** - Works with default VPC, accessible by other VMs
- **Management UI** - RabbitMQ web interface available on port 15672
- **Auto-healing** - Systemd services ensure both containers restart on failure
- **Spot instance support** - Optional cost savings up to 80% with preemptible instances
- **Fixed internal IP** - Optional static internal IP for predictable networking

## Architecture

```
┌─────────────────────────────────────┐
│ GCP VM (e2-micro)                   │
│ ┌─────────────────────────────────┐ │
│ │ Ubuntu 24.04                    │ │
│ │ ┌─────────────────────────────┐ │ │
│ │ │ RabbitMQ Container          │ │ │
│ │ │ rabbitmq:4-management       │ │ │
│ │ │ Ports: 5672, 15672, etc.   │ │ │
│ │ └─────────────────────────────┘ │ │
│ │ ┌─────────────────────────────┐ │ │
│ │ │ Redis Container             │ │ │
│ │ │ redis:7-alpine              │ │ │
│ │ │ Port: 6379                  │ │ │
│ │ └─────────────────────────────┘ │ │
│ └─────────────────────────────────┘ │
│ Disks:                              │
│ • Boot: 50GB (pd-balanced)          │
│ • Data: 10GB (pd-balanced, shared)  │
└─────────────────────────────────────┘
```

## Quick Start

1. **Copy example configuration:**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Edit configuration:**
   ```bash
   # Edit terraform.tfvars with your project ID and credentials
   vim terraform.tfvars
   ```

3. **Deploy:**
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

4. **Access Services:**
   - **RabbitMQ AMQP**: `amqp://admin:password@INTERNAL_IP:5672/`
   - **RabbitMQ Management UI**: `http://EXTERNAL_IP:15672`
   - **Redis**: `redis://INTERNAL_IP:6379`

## Configuration

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `project_id` | GCP Project ID | `"my-project"` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `instance_name` | `"rabbitmq-server"` | VM instance name |
| `machine_type` | `"e2-micro"` | GCP machine type |
| `zone` | `"us-west1-b"` | GCP zone |
| `boot_disk_size_gb` | `50` | Root disk size |
| `data_disk_size_gb` | `10` | RabbitMQ data disk size |
| `rabbitmq_user` | `"admin"` | RabbitMQ admin username |
| `rabbitmq_password` | `"changeme123"` | RabbitMQ admin password |
| `use_spot_instances` | `false` | Use spot instances for cost savings |
| `internal_ip` | `null` | Fixed internal IP address (optional) |

## Network Access

### Firewall Rules Created

1. **RabbitMQ + Redis Internal Access:**
   - Ports: `5672, 15672, 25672, 4369, 35672-35682, 6379`
   - Source: VPC internal ranges (configurable)
   - Target: `rabbitmq-server` tag

2. **SSH Access:**
   - Port: `22`
   - Source: Configurable (default: `0.0.0.0/0`)
   - Target: `rabbitmq-server` tag

### Default Access Ranges

- **Internal VPC**: `10.128.0.0/9` (default VPC range)
- **Private networks**: `10.0.0.0/8`

## Outputs

| Output | Description |
|--------|-------------|
| `internal_ip` | Internal IP for VPC clients |
| `external_ip` | External IP for management |
| `rabbitmq_amqp_url` | Connection string for clients |
| `rabbitmq_management_url` | Management UI URL |
| `ssh_command` | SSH command to connect |

## Usage Examples

### Basic Deployment

```hcl
module "rabbitmq" {
  source = "./rabbitmq"
  
  project_id = "my-project"
  
  rabbitmq_user     = "myapp"
  rabbitmq_password = "secure-password"
}
```

### Production Configuration

```hcl
module "rabbitmq" {
  source = "./rabbitmq"
  
  project_id    = "my-project"
  instance_name = "prod-rabbitmq"
  machine_type  = "e2-small"  # Slightly larger for production
  
  # Restrict access to VPC only
  allowed_source_ranges = ["10.128.0.0/9"]
  ssh_source_ranges     = ["10.128.0.0/9"]
  
  # Use spot instances for cost savings
  use_spot_instances = true
  
  # Fixed internal IP for predictable networking
  internal_ip = "10.138.15.236"
  
  rabbitmq_user     = "prod-user"
  rabbitmq_password = var.rabbitmq_password  # From secret
}
```

### Cost-Optimized Configuration

```hcl
module "rabbitmq" {
  source = "./rabbitmq"
  
  project_id = "my-project"
  
  # Enable spot instances for up to 80% cost savings
  use_spot_instances = true
  
  # Small instance for development
  machine_type = "e2-micro"
  
  rabbitmq_user     = "dev-user"
  rabbitmq_password = var.rabbitmq_password
}
```

### Client Connection

From another VM in the same VPC:

```python
import pika

# Connect to RabbitMQ
connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host='INTERNAL_IP',  # Use internal_ip output
        port=5672,
        credentials=pika.PlainCredentials('admin', 'password')
    )
)
channel = connection.channel()

# Use RabbitMQ...
```

## Monitoring & Management

### Check RabbitMQ Status

```bash
# SSH to the instance
gcloud compute ssh rabbitmq-server --zone=us-west1-b

# Check service status
sudo systemctl status rabbitmq

# Check container logs
sudo docker logs rabbitmq

# Check RabbitMQ status
sudo docker exec rabbitmq rabbitmqctl status
```

### Management UI

Access the web interface at `http://EXTERNAL_IP:15672`:
- Username: `admin` (or configured value)
- Password: `changeme123` (or configured value)

### Backup & Recovery

Data is stored on a persistent disk (`/opt/rabbitmq/data`) that survives instance recreation.

## Security Considerations

1. **Change default password** in production
2. **Restrict source ranges** to your VPC/networks only
3. **Use internal IP** for client connections within VPC
4. **Consider using Cloud SQL** for high availability needs
5. **Regular backups** of the data disk

## Troubleshooting

### RabbitMQ not starting

```bash
# Check startup script logs
sudo tail -f /var/log/startup-script.log

# Check Docker service
sudo systemctl status docker

# Check RabbitMQ service
sudo systemctl status rabbitmq
```

### Connection issues

1. Verify firewall rules allow your source IP
2. Check if using internal vs external IP correctly
3. Ensure RabbitMQ is fully started (can take 1-2 minutes)

### Data persistence

Data is stored on `/opt/rabbitmq/data` mounted from the persistent disk. This survives instance restarts and recreations.
