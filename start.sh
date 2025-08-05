#!/bin/sh

ip addr add 127.0.0.1/8 dev lo
ip addr add 127.0.0.2/8 dev lo
ip link set dev lo up
socat VSOCK-LISTEN:8888,fork tcp-connect:127.0.0.1:8888,reuseaddr & # for the json rpc server
socat tcp-listen:8889,fork vsock-connect:3:8889,reuseaddr & # for the db

# assume that I get the db url string from the parent instance
DB_PARAMS=$(socat -u vsock-listen:8890,reuseaddr - | head -n 1)

DB_USER=$(echo "$DB_PARAMS" | sed -E 's#^postgres://([^:]+):.*#\1#')
DB_PASS=$(echo "$DB_PARAMS" | sed -E 's#^postgres://[^:]+:([^@]+)@.*#\1#')
DB_NAME=$(echo "$DB_PARAMS" | sed -E 's#^.*/([^/]+)$#\1#')

DATABASE_URL="postgres://$DB_USER:$DB_PASS@127.0.0.2:8889/$DB_NAME"

ulimit -s 500000

./usr/local/bin/tee-server \
    --server-address=127.0.0.1:8888 \
    --database-url=$DATABASE_URL \
    --circuit-folder=/circuits \
    --zkey-folder=/zkeys \
    --rapidsnark-path=/rapidsnark
