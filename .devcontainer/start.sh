#!/bin/sh
# Start the fixture-only stack. Uses the host docker socket when mounted,
# otherwise starts dockerd inside this dev container (demo lab only).
set -e
if [ ! -S /var/run/docker.sock ]; then
  nohup dockerd --iptables=false >/tmp/dockerd.log 2>&1 &
  for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
fi
cd /workspaces/fuzzcore
[ -f .env ] || python3 infra/ci_env.py
docker compose up -d --build
