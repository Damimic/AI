#!/usr/bin/env bash
# Generates a self-signed TLS cert/key for LOCAL DEVELOPMENT ONLY.
#
# This is not how production TLS should work — a real deployment needs a
# certificate from a real CA (e.g. Let's Encrypt), not a self-signed one.
# This script exists purely so `kepler-backend` can satisfy its
# TLS-required-by-default rule during local testing without reaching for
# KEPLER_INSECURE_HTTP.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p dev-certs

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout dev-certs/dev.key \
  -out dev-certs/dev.crt \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "wrote dev-certs/dev.crt and dev-certs/dev.key (local dev only, gitignored)"
