#!/bin/sh
# Demo-lab tooling: docker CLI, compose plugin, compose engine binaries.
set -e
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-26.1.4.tgz -o /tmp/docker.tgz
  tar xz -C /usr/local/bin --strip-components=1 -f /tmp/docker.tgz
fi
mkdir -p /usr/local/lib/docker/cli-plugins
if [ ! -x /usr/local/lib/docker/cli-plugins/docker-compose ]; then
  curl -fsSL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi
cd /workspaces/fuzzcore
[ -f .env ] || python3 infra/ci_env.py
