#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/bao-guard.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export GUARD_LOG="$TMP/guard-audit.log"
export TOKEN_FILE="$TMP/agent.token"
printf 'mock-token
' >"$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

# Create a mock `bao` CLI in PATH that returns a deterministic secret without needing a live server
mkdir -p "$TMP/bin"
cat > "$TMP/bin/bao" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  if [ "${3:-}" = "-format=json" ]; then
    printf '{"data":{"data":{"api_key":"super-secret-value-42"},"metadata":{"version":3}}}
'
    exit 0
  elif [[ "${3:-}" == -field=* ]]; then
    printf 'super-secret-value-42'
    exit 0
  else
    exit 0
  fi
fi
exit 1
EOF
chmod +x "$TMP/bin/bao"
export PATH="$TMP/bin:$PATH"

assert_exit() {
  local expected="$1"; shift
  set +e
  "$@" >/dev/null 2>&1
  local actual=$?
  set -e
  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL: expected exit $expected, got $actual for: $*" >&2
    exit 1
  fi
}

echo "[1/7] Testing DISPLAY sink refusal (exit 3)..."
for sink in stdout console print echo cat transcript chat reply; do
  assert_exit 3 "$GUARD" check "$sink" "secret/data/app/config"
done

echo "[2/7] Testing Tier 1 (restricted/) and Tier 2 (services/) refusal (exit 3)..."
assert_exit 3 "$GUARD" check file "restricted/data/infra/bmc" "$TMP/out.secret"
assert_exit 3 "$GUARD" check file "services/data/recovery/ssh" "$TMP/out.secret"
assert_exit 3 "$GUARD" hash "restricted/data/infra/bmc" "token"

echo "[3/7] Testing universal Git working-tree protection (exit 3 on tracked/unignored path)..."
mkdir -p "$TMP/git-repo"
git -C "$TMP/git-repo" init -q
printf 'ignored.secret
' > "$TMP/git-repo/.gitignore"
assert_exit 3 "$GUARD" check file "secret/data/app/config" "$TMP/git-repo/committable.secret"
assert_exit 0 "$GUARD" check file "secret/data/app/config" "$TMP/git-repo/ignored.secret"

echo "[4/7] Testing zero-knowledge SHA-256 hash verification..."
EXPECTED_HASH="$(printf 'super-secret-value-42' | shasum -a 256 | cut -d' ' -f1)"
ACTUAL_HASH="$("$GUARD" hash "secret/data/app/config" "api_key")"
[ "$EXPECTED_HASH" = "$ACTUAL_HASH" ] || { echo "FAIL: hash mismatch ($ACTUAL_HASH != $EXPECTED_HASH)"; exit 1; }

echo "[5/7] Testing metadata-only keys and version count..."
KEYS="$("$GUARD" keys "secret/data/app/config")"
[ "$KEYS" = "api_key" ] || { echo "FAIL: expected key 'api_key', got '$KEYS'"; exit 1; }
VER="$("$GUARD" count "secret/data/app/config")"
[ "$VER" = "3" ] || { echo "FAIL: expected version 3, got '$VER'"; exit 1; }

echo "[6/7] Testing 0600 file materialisation without value leak..."
MAT_OUT="$("$GUARD" file "secret/data/app/config" "api_key" "$TMP/git-repo/ignored.secret")"
echo "$MAT_OUT" | grep -q "super-secret-value-42" && { echo "FAIL: secret leaked in stdout!"; exit 1; }
[ "$(cat "$TMP/git-repo/ignored.secret")" = "super-secret-value-42" ] || { echo "FAIL: materialised file content mismatch"; exit 1; }

echo "[7/7] Validating Docker Compose & HCL templates..."
"$ROOT/scripts/validate-compose.sh"

echo "[OK] All 7 test suites passed with zero leaks."
