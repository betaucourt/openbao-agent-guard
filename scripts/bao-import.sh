#!/usr/bin/env bash
# bao-import.sh ??? put a secret INTO the broker without exposing its value.
#
# The value is read from a local file (or hidden stdin prompt) and piped
# straight into jq/curl via stdin. It never appears in argv, in the process
# table, in this script's output, or in chat transcripts.
#
#   # Tier 3 (agent-readable) ??? normal secrets
#   ./scripts/bao-import.sh secret/data/recovery/ssh/ci-admin ~/.ssh/ci-admin key
#
#   # Tier 1 (root only) ??? cloud provider / BMC credentials
#   ./scripts/bao-import.sh restricted/data/infra/cloud-provider ~/token.txt token
#
#   # from a literal value (prompted, hidden)
#   ./scripts/bao-import.sh secret/data/auth/owner - admin-email
#
# Verification is by SHA-256: the stored value is hashed and compared to the
# source file. Proof of correct storage WITHOUT reading or displaying the value.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VAULT_PATH="${1:-}"
SRC="${2:-}"
FIELD="${3:-}"

BAO_ADDR="${BAO_ADDR:-https://127.0.0.1:8200}"
BAO_CACERT_DEFAULT="$REPO_ROOT/secrets/openbao.localhost.crt"
if [ -z "${BAO_CACERT:-}" ] || [ ! -r "$BAO_CACERT" ]; then BAO_CACERT="$BAO_CACERT_DEFAULT"; fi

die() { printf 'import: %s
' "$1" >&2; exit "${2:-1}"; }

[ -n "$VAULT_PATH" ] && [ -n "$FIELD" ] || { sed -n '2,20p' "$0"; exit 1; }
case "$VAULT_PATH" in
  secret/*)     TIER=3 ;;
  services/*)   TIER=2 ;;
  restricted/*) TIER=1 ;;
  *) die "path '$VAULT_PATH' is not under secret/, services/ or restricted/" 3 ;;
esac

: "${BAO_TOKEN:?Set BAO_TOKEN (operator/root token) in your environment.}"

# --- build the payload without ever echoing or passing the value in argv -----
if [ "$SRC" = "-" ]; then
  printf 'Value for %s.%s (hidden): ' "$VAULT_PATH" "$FIELD"
  read -rs VAL; echo
else
  [ -r "$SRC" ] || die "source not readable: $SRC" 2
  VAL="$(cat "$SRC")"
fi

SRC_HASH="$(printf '%s' "$VAL" | shasum -a 256 | cut -d' ' -f1)"

# Pipe $VAL over stdin into jq (-Rs) so the secret never enters process argv
RESP=$(printf '%s' "$VAL"       | jq -Rs --arg f "$FIELD" '{data:{($f):.}}'       | curl -sS --cacert "$BAO_CACERT" -H "X-Vault-Token: $BAO_TOKEN"           -X POST "$BAO_ADDR/v1/$VAULT_PATH" -d @-)
unset VAL

ERR=$(printf '%s' "$RESP" | jq -r '.errors // empty' 2>/dev/null || echo "")
[ -n "$ERR" ] && die "write failed: $ERR" 1

# --- verify by hash, never by reading ---------------------------------------
STORED=$(curl -sS --cacert "$BAO_CACERT" -H "X-Vault-Token: $BAO_TOKEN"            "$BAO_ADDR/v1/$VAULT_PATH" | jq -r --arg f "$FIELD" '.data.data[$f] // ""')
STORED_HASH="$(printf '%s' "$STORED" | shasum -a 256 | cut -d' ' -f1)"
unset STORED

printf 'imported  %s
' "$VAULT_PATH"
printf '  tier    %s
' "$TIER"
printf '  field   %s
' "$FIELD"
printf '  version %s
' "$(printf '%s' "$RESP" | jq -r '.data.version // "?"')"
printf '  src     sha256 %s
' "$SRC_HASH"
printf '  stored  sha256 %s
' "$STORED_HASH"
if [ "$SRC_HASH" = "$STORED_HASH" ]; then
  printf '  VERIFY  MATCH ??? bytes identical, value never displayed
'
else
  die "VERIFY FAILED ??? stored value differs from source" 1
fi
