#!/bin/bash

# RabbitMQ VM Startup Script
# This script installs Docker and runs RabbitMQ container with persistent data

set -e

# Log all output
exec > >(tee /var/log/startup-script.log) 2>&1

echo "Starting RabbitMQ setup at $(date)"

# Update system packages
apt-get update
apt-get upgrade -y

# Install Docker
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Create rabbitmq user for running containers
useradd -r -s /bin/false rabbitmq || true

# Mount and format the data disk
DATA_DEVICE="/dev/disk/by-id/google-rabbitmq-data"
MOUNT_POINT="/opt/rabbitmq/data"

# Wait for the disk to be available
while [ ! -e "$DATA_DEVICE" ]; do
    echo "Waiting for data disk to be available..."
    sleep 5
done

# Check if disk is already formatted
if ! blkid "$DATA_DEVICE"; then
    echo "Formatting data disk..."
    mkfs.ext4 -F "$DATA_DEVICE"
fi

# Create mount point and mount the disk
mkdir -p "$MOUNT_POINT"
mount "$DATA_DEVICE" "$MOUNT_POINT"

# Add to fstab for persistent mounting
DISK_UUID=$(blkid -s UUID -o value "$DATA_DEVICE")
echo "UUID=$DISK_UUID $MOUNT_POINT ext4 defaults 0 2" >> /etc/fstab

# Set proper ownership and permissions
chown -R 999:999 "$MOUNT_POINT"  # RabbitMQ container runs as uid 999
chmod 755 "$MOUNT_POINT"

# Create RabbitMQ configuration directory
mkdir -p /opt/rabbitmq/config
chown -R 999:999 /opt/rabbitmq/config

# Create RabbitMQ configuration file
cat > /opt/rabbitmq/config/rabbitmq.conf << EOF
# RabbitMQ Configuration
default_user = ${rabbitmq_user}
default_pass = ${rabbitmq_password}

# Enable management plugin
management.tcp.port = 15672
management.tcp.ip = 0.0.0.0

# AMQP port
listeners.tcp.default = 5672

# Memory and disk thresholds
vm_memory_high_watermark.relative = 0.6
disk_free_limit.relative = 2.0

# Logging
log.console = true
log.console.level = info
EOF

chown 999:999 /opt/rabbitmq/config/rabbitmq.conf

# Create systemd service for RabbitMQ container
cat > /etc/systemd/system/rabbitmq.service << EOF
[Unit]
Description=RabbitMQ Container
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/docker stop rabbitmq
ExecStartPre=-/usr/bin/docker rm rabbitmq
ExecStart=/usr/bin/docker run --rm --name rabbitmq \\
    -p 5672:5672 \\
    -p 15672:15672 \\
    -p 25672:25672 \\
    -p 4369:4369 \\
    -p 35672-35682:35672-35682 \\
    -v /opt/rabbitmq/data:/var/lib/rabbitmq \\
    -v /opt/rabbitmq/config/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf \\
    -e RABBITMQ_DEFAULT_USER=${rabbitmq_user} \\
    -e RABBITMQ_DEFAULT_PASS=${rabbitmq_password} \\
    rabbitmq:4-management
ExecStop=/usr/bin/docker stop rabbitmq
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

# Enable and start RabbitMQ service
systemctl daemon-reload
systemctl enable rabbitmq.service
systemctl start rabbitmq.service

# Wait for RabbitMQ to be ready
echo "Waiting for RabbitMQ to start..."
sleep 30

# Check if RabbitMQ is running
if systemctl is-active --quiet rabbitmq.service; then
    echo "RabbitMQ service is running successfully"
    
    # Wait a bit more for full initialization
    sleep 15
    
    # Test connection
    if docker exec rabbitmq rabbitmqctl status > /dev/null 2>&1; then
        echo "RabbitMQ is ready and responding"
    else
        echo "RabbitMQ is starting but not fully ready yet"
    fi
else
    echo "RabbitMQ service failed to start"
    systemctl status rabbitmq.service
fi

echo "RabbitMQ setup completed at $(date)"
echo "Management UI available at: http://$(curl -s http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip -H "Metadata-Flavor: Google"):15672"
echo "Default credentials: ${rabbitmq_user}/${rabbitmq_password}"
