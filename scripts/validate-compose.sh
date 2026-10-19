#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/secrets"
touch "$scratch/secrets/tls.crt" "$scratch/secrets/tls.key"

cat > "$scratch/.env" <<EOF
OPENBAO_IMAGE=quay.io/openbao/openbao@sha256:0000000000000000000000000000000000000000000000000000000000000000
OPENBAO_HOST_PORT=8200
OPENBAO_TLS_CERT_FILE=$scratch/secrets/tls.crt
OPENBAO_TLS_KEY_FILE=$scratch/secrets/tls.key
EOF

grep -Fqx 'audit "file" "local-file" {' "$root/config/openbao.hcl"
grep -Fqx '    file_path = "/openbao/audit/audit.log"' "$root/config/openbao.hcl"
if command -v docker >/dev/null 2>&1; then
  docker compose --project-directory "$root" --env-file "$scratch/.env" -f "$root/compose.yaml" config --quiet
fi
printf '%s
' 'openbao-agent-guard: compose and HCL templates validated.'
