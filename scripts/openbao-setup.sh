#!/usr/bin/env bash
# openbao-setup.sh ??? provision the three-tier secret layout on the local broker.
#
# Run THIS YOURSELF, in your own terminal. The agent never sees the root token.
#
#   export BAO_TOKEN='<root token from operator init>'
#   ./scripts/openbao-setup.sh
#
# Idempotent ??? safe to re-run. Creates only what is missing.
#
#   Tier 1  restricted/  no agent grant exists. Root-only. NEVER agent-readable.
#   Tier 2  services/    agent has NO grant. Human mints a short-TTL scoped token.
#   Tier 3  secret/      agent read+list, 24h renewable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BAO_ADDR="${BAO_ADDR:-https://127.0.0.1:8200}"
BAO_CACERT="${BAO_CACERT:-$REPO_ROOT/secrets/openbao.localhost.crt}"
TOKEN_DIR="${TOKEN_DIR:-$HOME/.config/bao}"

: "${BAO_TOKEN:?Set BAO_TOKEN in your environment. Never pass it as an argument.}"

bao() { BAO_ADDR="$BAO_ADDR" BAO_CACERT="$BAO_CACERT" BAO_TOKEN="$BAO_TOKEN" command bao "$@"; }
apic() { curl -sS --cacert "$BAO_CACERT" -H "X-Vault-Token: $BAO_TOKEN" "$@"; }
jqf()  { jq -e "$1" >/dev/null 2>&1; }
# ok() exits 0 ONLY when the response carries no "errors" key.
ok()   { jq -e 'has("errors") | not' >/dev/null 2>&1; }

# --- 0. preflight ------------------------------------------------------------
if [ -z "${BAO_TOKEN:-}" ]; then
  echo "[!] BAO_TOKEN is empty."
  exit 1
fi
case "$BAO_TOKEN" in
  *"<"*">"*|"paste"*|"your"*|"<root"*)
    echo "[!] BAO_TOKEN looks like placeholder text, not a real token."
    exit 1
    ;;
esac

if ! apic "$BAO_ADDR/v1/auth/token/lookup-self" | jqf '.data.policies'; then
  echo "[!] BAO_TOKEN rejected by the broker (401/invalid)."
  exit 1
fi
echo "[*] root token accepted"
echo "[*] Target: $BAO_ADDR"

if ! apic "$BAO_ADDR/v1/sys/seal-status" | jqf '.sealed == false'; then
  echo "[!] SEALED. Unseal first:  bao operator unseal"
  exit 1
fi
echo "[*] unsealed"

# --- 1. mounts ---------------------------------------------------------------
for m in restricted services secret; do
  if apic "$BAO_ADDR/v1/sys/mounts" | jqf ".data["$m/"]"; then
    echo "[*] mount $m/ exists"
  else
    printf '[*] mounting KV v2 at %s/
' "$m"
    resp=$(apic -X POST "$BAO_ADDR/v1/sys/mounts/$m" -d '{"type":"kv","options":{"version":"2"}}')
    err=$(printf '%s' "$resp" | jq -r '.errors // empty')
    [ -n "$err" ] && { echo "[!] $m: $err"; exit 1; }
  fi
done

# --- 2. policies -------------------------------------------------------------
put_policy() {
  local n="$1" p="$2"
  if apic "$BAO_ADDR/v1/sys/policies/acl/$n" | ok; then
    printf '[*] policy %s exists
' "$n"
  else
    printf '[*] writing policy %s
' "$n"
    jq -n --arg p "$p" '{policy:$p}' | apic -X PUT "$BAO_ADDR/v1/sys/policies/acl/$n" -d @- >/dev/null
  fi
}

# Tier 3 ??? agent. Read+list ONLY on secret/. No create/update/delete/sudo.
put_policy agent-read '
path "secret/data/*"     { capabilities = ["read", "list"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
'

# Tier 3 identity ??? same rights, human-minted, 15 min, loopback-bound.
put_policy human-t3 '
path "secret/data/*"     { capabilities = ["read", "list"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
'

# Tier 2 ??? human-minted, short TTL, loopback-bound.
put_policy service-read '
path "services/data/recovery/*"     { capabilities = ["read", "list"] }
path "services/metadata/recovery/*" { capabilities = ["read", "list"] }
path "services/data/projects/*"     { capabilities = ["read", "list"] }
path "services/metadata/projects/*" { capabilities = ["read", "list"] }
'

put_policy infra-ops '
path "services/data/recovery/ssh/hypervisor"          { capabilities = ["read"] }
path "services/metadata/recovery/ssh/hypervisor"      { capabilities = ["read", "list"] }
path "services/data/recovery/ssh/bastion-admin"       { capabilities = ["read"] }
path "services/metadata/recovery/ssh/bastion-admin"   { capabilities = ["read", "list"] }
'

ADMIN_HCL='
path "secret/*"       { capabilities = ["create","read","update","delete","list"] }
path "services/*"     { capabilities = ["create","read","update","delete","list"] }
path "restricted/*"   { capabilities = ["create","read","update","delete","list"] }
path "auth/token/create"       { capabilities = ["create","update"] }
path "auth/token/create/tier2" { capabilities = ["create","update"] }
path "auth/token/lookup-self"  { capabilities = ["read"] }
path "auth/token/renew-self"   { capabilities = ["update"] }
path "auth/token/revoke-self"  { capabilities = ["update"] }
path "sys/mounts"     { capabilities = ["read"] }
path "sys/policies/acl"   { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["read"] }
path "sys/health"     { capabilities = ["read"] }
path "sys/seal-status"{ capabilities = ["read"] }
path "sys/leases/*"   { capabilities = ["create","update"] }
path "sys/wrapping/*" { capabilities = ["create","update"] }
path "cubbyhole/*"    { capabilities = ["create","read","update","delete"] }'

put_policy admin "$ADMIN_HCL"

# --- 2b. auth methods -------------------------------------------------------
if apic "$BAO_ADDR/v1/sys/auth" | jqf '.data["userpass/"]'; then
  echo "[*] userpass enabled"
else
  echo "[*] enabling userpass"
  apic -X POST "$BAO_ADDR/v1/sys/auth/userpass" -d '{"type":"userpass"}' >/dev/null
fi

if apic "$BAO_ADDR/v1/sys/auth" | jqf '.data["approle/"]'; then
  echo "[*] approle enabled"
else
  echo "[*] enabling approle"
  apic -X POST "$BAO_ADDR/v1/sys/auth/approle" -d '{"type":"approle"}' >/dev/null
fi

OP_USER="${OP_USER:-bao-operator}"
if apic "$BAO_ADDR/v1/auth/userpass/users/$OP_USER" | ok; then
  echo "[*] user $OP_USER exists"
else
  : "${HUMAN_PW:?Set HUMAN_PW to create user $OP_USER. Not passed as an argument.}"
  echo "[*] creating user $OP_USER (admin policy, NOT root, 15m TTL)"
  printf '%s' "$HUMAN_PW"     | jq -Rs '{password:., token_policies:["default","admin"], token_ttl:"15m"}'     | apic -X POST "$BAO_ADDR/v1/auth/userpass/users/$OP_USER" -d @- >/dev/null
  unset HUMAN_PW
fi

if apic "$BAO_ADDR/v1/auth/token/roles" | jqf '.data["tier2"]'; then
  echo "[*] token role tier2 exists"
else
  echo "[*] token role tier2 (15m, loopback-bound, no root fallback)"
  apic -X POST "$BAO_ADDR/v1/auth/token/roles/tier2" -d '{
    "allowed_policies":["service-read","infra-ops","human-t3"],
    "orphan":true, "period":"768h",
    "token_bound_cidrs":["127.0.0.1","::1"],
    "token_explicit_max_ttl":900, "token_max_ttl":900, "token_num_uses":0
  }' >/dev/null
fi

# --- 3. tier-3 agent token ---------------------------------------------------
mkdir -p "$TOKEN_DIR"; chmod 700 "$TOKEN_DIR"
tok="$TOKEN_DIR/agent-read.token"

if [ -s "$tok" ]; then
  echo "[*] reusing agent token $tok"
else
  echo "[*] minting Tier 3 agent token (24h, renewable by root)"
  r=$(apic -X POST "$BAO_ADDR/v1/auth/token/create"       -d '{"policies":["agent-read"],"ttl":"24h","renewable":true,"display_name":"agent-read"}')
  e=$(printf '%s' "$r" | jq -r '.errors // empty')
  [ -n "$e" ] && { echo "[!] $e"; exit 1; }
  printf '%s' "$r" | jq -r '.auth.client_token' >"$tok"
  chmod 600 "$tok"
  echo "[*] written to $tok (0600)"
fi

# --- 4. verify the tiers are actually separated ------------------------------
echo
echo "[*] verifying tier separation..."
rt=$(cat "$tok")

http() { curl -sS -o /dev/null -w '%{http_code}' --cacert "$BAO_CACERT"            -H "X-Vault-Token: $rt" "$BAO_ADDR$1"; }
verdict() { case "$1" in
  403) echo "DENIED (correct)" ;;
  404) echo "EMPTY (granted, no data yet)" ;;
  200) echo "READABLE" ;;
  401) echo "TOKEN INVALID" ;;
  *)   echo "HTTP $1" ;;
esac; }

t3=$(http  "/v1/secret/metadata/")
t3b=$(http "/v1/secret/data/__probe__")
t1=$(http  "/v1/restricted/data/__probe__")
t2=$(http  "/v1/services/data/__probe__")
t2r=$(http "/v1/services/data/recovery/ssh/hypervisor")

printf '    Tier 3  secret/                     -> %s
' "$(verdict "$t3")"
printf '    Tier 3  secret/data read            -> %s
' "$(verdict "$t3b")"
printf '    Tier 2  services/                   -> %s
' "$(verdict "$t2")"
printf '    Tier 2  .../recovery/ssh/hypervisor -> %s
' "$(verdict "$t2r")"
printf '    Tier 1  restricted/                 -> %s
' "$(verdict "$t1")"
echo
rc=0
case "$t3"  in 200|404) ;; *) echo "[!] Tier 3 not granted ??? policy wrong"; rc=1 ;; esac
case "$t3b" in 200|404) ;; *) echo "[!] Tier 3 data read not granted"; rc=1 ;; esac
case "$t1"  in 403) ;; *) echo "[!] TIER 1 READABLE BY AGENT ??? ABORT"; rc=1 ;; esac
case "$t2"  in 403) ;; *) echo "[!] TIER 2 READABLE BY AGENT ??? ABORT"; rc=1 ;; esac
case "$t2r" in 403) ;; *) echo "[!] TIER 2 HOST KEYS READABLE BY AGENT ??? ABORT"; rc=1 ;; esac
[ "$rc" -ne 0 ] && { echo; echo "ABORT: do not store secrets until separation holds."; exit 1; }
echo "[OK] Tier separation holds: agent reads Tier 3 only."
