#!/bin/sh

set -e

# query ip of instance and store
/app/vet --url vsock://3:1300/instance/ip > /app/ip.txt
cat /app/ip.txt

# query init
/app/vet --url vsock://3:1300/self/init-params > /app/.env
cat /app/.env

ip=$(cat /app/ip.txt)

# setting an address for loopback
ifconfig lo $ip mtu 9001
ip addr add $ip dev lo

# localhost dns
echo "127.0.0.1 localhost" > /etc/hosts

ifconfig
ip addr
cat /etc/hosts

# adding a default route
ip route add default dev lo src $ip
route -n

# create ipset with all "internal" (unroutable) addresses
ipset create internal hash:net
ipset add internal 0.0.0.0/8
ipset add internal 10.0.0.0/8
ipset add internal 100.64.0.0/10
ipset add internal 127.0.0.0/8
ipset add internal 169.254.0.0/16
ipset add internal 172.16.0.0/12
ipset add internal 192.0.0.0/24
ipset add internal 192.0.2.0/24
ipset add internal 192.88.99.0/24
ipset add internal 192.168.0.0/16
ipset add internal 198.18.0.0/15
ipset add internal 198.51.100.0/24
ipset add internal 203.0.113.0/24
ipset add internal 224.0.0.0/4
ipset add internal 233.252.0.0/24
ipset add internal 240.0.0.0/4
ipset add internal 255.255.255.255/32

# create ipset with the ports supported for routing
ipset create portfilter bitmap:port range 0-65535
ipset add portfilter 1024-61439
ipset add portfilter 80
ipset add portfilter 443

# iptables rules to route traffic to a nfqueue to be picked up by the proxy
iptables -A OUTPUT -p tcp -s $ip -m set --match-set portfilter src -m set ! --match-set internal dst -j NFQUEUE --queue-num 0
iptables -t nat -vL
iptables -vL

/app/supervisord &
SUPERVISOR_PID=$!

# Wait for Docker daemon to be ready
until docker info >/dev/null 2>&1; do
    echo "[setup.sh] Waiting for Docker daemon..."
    sleep 1
done

ulimit -s 500000

source /app/.env

/bin/docker run --network=host \
    -p 8888:8888 $IMAGE_NAME \
    --server-address=0.0.0.0:8888 \
    --database-url=$DATABASE_URL \
    --circuit-folder=/circuits \
    --zkey-folder=/zkeys \
    --rapidsnark-path=/rapidsnark
wait $SUPERVISOR_PID
