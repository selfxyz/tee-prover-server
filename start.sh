#!/bin/sh

./update_creds.sh

export GOOGLE_APPLICATION_CREDENTIALS=./creds.json

ulimit -s 500000

./tee-server \
    --server-address=0.0.0.0:8888 \
    --project-id=$PROJECT_ID \
    --secret-id=$SECRET_ID \
    --circuit-folder=/circuits \
    --zkey-folder=/zkeys \
    --rapidsnark-path=/rapidsnark
