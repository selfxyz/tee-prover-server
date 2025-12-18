#!/bin/sh

./update_creds.sh

export GOOGLE_APPLICATION_CREDENTIALS=./creds.json

ulimit -s 500000

# Start Redis in the background
redis-server --daemonize yes

# Wait for Redis to be ready
for i in {1..20}; do
  if redis-cli ping >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

./tee-server \
    --server-address=0.0.0.0:8888 \
    --project-id=$PROJECT_ID \
    --secret-id=$SECRET_ID \
    --circuit-folder=/circuits \
    --zkey-folder=/zkeys \
    --rapidsnark-path=/rapidsnark
