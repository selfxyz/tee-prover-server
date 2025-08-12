#!/bin/sh

ulimit -s 500000

./tee-server \
    --server-address=0.0.0.0:8888 \
    --database-url=$DATABASE_URL \
    --circuit-folder=/circuits \
    --zkey-folder=/zkeys \
    --rapidsnark-path=/rapidsnark
