#!/usr/bin/env bash
# bao-guard.sh ??? pre-flight leak guard for every OpenBao secret operation.
#
# The contract: no secret VALUE may reach stdout, argv, a transcript, a log,
# or any tracked path. This script decides that BEFORE an operation runs,
# and refuses + proposes an alternative if it would leak.
#
# Usage:
#   bao-guard.sh check  <sink> <vault-path> [dest]     # pre-flight decision
#   bao-guard.sh keys   <vault-path>                   # key names only (safe)
#   bao-guard.sh exists <vault-path>                   # boolean only (safe)
#   bao-guard.sh hash   <vault-path> <field>           # sha256 only (safe)
#   bao-guard.sh count  <vault-path>                   # version count (safe)
#   bao-guard.sh file   <vault-path> <field> <dest>    # materialise 0600
#
# Exit codes: 0 = safe/performed ?? 3 = REFUSED (leak risk) ?? 1 = error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BAO_ADDR="${BAO_ADDR:-https://127.0.0.1:8200}"
BAO_CACERT="${BAO_CACERT:-$REPO_ROOT/secrets/openbao.localhost.crt}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/bao/agent-read.token}"
GUARD_LOG="${GUARD_LOG:-$HOME/.config/bao/guard-audit.log}"

# ---- policy boundaries (mirrors the ACLs the broker enforces) ---------------
TIER3_PREFIX="secret/"          # agent may read
TIER1_PREFIX="restricted/"      # agent may NOT read ??? no grant exists
TIER2_PREFIX="services/"        # human-minted, short TTL

log() { mkdir -p "$(dirname "$GUARD_LOG")"; printf '%s %s
' "$(date -u +%FT%TZ)" "$*" >>"$GUARD_LOG"; chmod 600 "$GUARD_LOG" 2>/dev/null || true; }

die() { printf 'guard: %s
' "$1" >&2; exit "${2:-1}"; }

bao() {
  BAO_ADDR="$BAO_ADDR" BAO_CACERT="$BAO_CACERT"   BAO_TOKEN="$(cat "$TOKEN_FILE" 2>/dev/null || true)" command bao "$@"
}

# ---- tier enforcement -------------------------------------------------------
assert_tier() {
  local p="$1"
  case "$p" in
    "$TIER1_PREFIX"*) die "REFUSED: '$p' is Tier 1 (restricted/). No agent grant exists by design. Operator action required." 3 ;;
    "$TIER2_PREFIX"*) die "REFUSED: '$p' is Tier 2 (services/). Mint a scoped token for the specific task, then re-run with TOKEN_FILE=<scoped>." 3 ;;
    "$TIER3_PREFIX"*) : ;;
    *) die "unknown path '$p' ??? outside all known mounts" 3 ;;
  esac
}

# ---- leak detection ---------------------------------------------------------
# Classifies a sink. Anything that can persist or display a value is UNSAFE.
sink_risk() {
  case "$1" in
    stdout|console|print|echo|cat|transcript|chat|reply) echo "DISPLAY" ;;
    argv|args|cmdline|process)                   echo "PERSIST" ;;
    file|write|redirect|tee)                     echo "PERSIST" ;;
    log|syslog|audit)                            echo "PERSIST" ;;
    git|stage|commit)                            echo "PERSIST" ;;
    env|environ|export)                          echo "PERSIST" ;;
    *)                                           echo "SAFE" ;;
  esac
}

# Universal Git working-tree check: walks up to the nearest existing ancestor
# directory of $dest and verifies that if it belongs to a Git repository, $dest
# is explicitly covered by .gitignore / git check-ignore.
in_tracked_path() {
  local dest="${1:-}"
  [ -z "$dest" ] && return 1
  local check_dir
  check_dir="$(dirname "$dest")"
  while [ ! -d "$check_dir" ] && [ "$check_dir" != "/" ] && [ "$check_dir" != "." ]; do
    check_dir="$(dirname "$check_dir")"
  done
  if git -C "$check_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local abs_dest
    if [[ "$dest" = /* ]]; then
      abs_dest="$dest"
    else
      abs_dest="$(cd "$check_dir" && pwd)/$(basename "$dest")"
    fi
    git -C "$check_dir" check-ignore -q "$abs_dest" 2>/dev/null && return 1 || return 0
  fi
  return 1
}

# ---- commands ---------------------------------------------------------------
cmd_check() {
  local sink="$1" path="$2" dest="${3:-}"
  assert_tier "$path"
  local risk; risk="$(sink_risk "$sink")"

  if in_tracked_path "$dest"; then
    log "REFUSE sink=$sink path=$path reason=tracked-path dest=$dest"
    die "REFUSED: destination '$dest' is inside a git working tree and not gitignored. A secret written there would be committable." 3
  fi

  if [ "$risk" = "DISPLAY" ]; then
    log "REFUSE sink=$sink path=$path reason=value-to-display"
    cat >&2 <<EOF
guard: REFUSED ??? sink '$sink' would render the secret VALUE.
  path : $path
  Why  : a value on stdout/argv/transcript is a permanent leak (scrollback,
         logs, process table, this conversation).
  Use instead:
    bao-guard.sh keys   $path      # field names only
    bao-guard.sh exists $path      # presence only
    bao-guard.sh hash   $path <f>  # sha256 for integrity, no value
    bao-guard.sh file   $path <f> <0600-dest>   # materialise to a private file
EOF
    exit 3
  fi

  log "ALLOW sink=$sink path=$path risk=$risk"
  printf 'ALLOW (%s)
' "$risk"
}

cmd_keys()   { assert_tier "$1"; bao kv get -format=json "$1" 2>/dev/null | jq -r '(.data.data.data // .data.data // .data) | keys[]'; }
cmd_exists() { assert_tier "$1"; if bao kv get "$1" >/dev/null 2>&1; then echo true; else echo false; fi; }
cmd_count()  { assert_tier "$1"; bao kv get -format=json "$1" 2>/dev/null | jq -r '.data.metadata.version // "none"'; }
cmd_hash()   { assert_tier "$1"; bao kv get -field="$2" "$1" 2>/dev/null | shasum -a 256 | cut -d' ' -f1; }

cmd_file() {
  local path="$1" field="$2" dest="$3"
  assert_tier "$path"
  [ -n "$dest" ] || die "materialise requires a destination path"
  in_tracked_path "$dest" && die "REFUSED: '$dest' is inside a tracked git tree." 3
  [ -e "$dest" ] && die "REFUSED: '$dest' already exists (refusing to overwrite)."
  local dir; dir="$(dirname "$dest")"
  mkdir -p "$dir"; chmod 700 "$dir"
  ( umask 077; bao kv get -field="$field" "$path" >"$dest" )
  chmod 600 "$dest"
  log "MATERIALISE path=$path field=$field dest=$dest mode=0600"
  printf 'materialised %s (0600, %s bytes, value not shown)
' "$dest" "$(wc -c <"$dest" | tr -d ' ')"
}

case "${1:-}" in
  check)  shift; cmd_check "$@" ;;
  keys)   shift; cmd_keys "$@" ;;
  exists) shift; cmd_exists "$@" ;;
  count)  shift; cmd_count "$@" ;;
  hash)   shift; cmd_hash "$@" ;;
  file)   shift; cmd_file "$@" ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac
