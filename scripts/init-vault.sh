#!/usr/bin/env bash
# Initializes a SecureVault server once and writes the unseal key shares and
# the root token to a private file (mode 600). They are never printed: the
# script reports only how many shares it got and where it put them.
#
#   scripts/init-vault.sh [-a ADDR] [-o FILE] [-n SHARES] [-t THRESHOLD]
#
#   -a ADDR       the server (default: $VAULT_ADDR, else http://127.0.0.1:8200)
#   -o FILE       where to write the result (default: ~/securevault-init.json)
#   -n SHARES     number of key shares (default: the server's config)
#   -t THRESHOLD  shares needed to unseal (default: the server's config)
#
# It refuses to run if FILE already holds an init result, and if the server is
# already initialized, so a second run can't overwrite the only copy of the
# keys. The result is written to a temporary file beside FILE and moved into
# place only once it's complete.
#
# Afterwards: give the shares to different holders or store them separately,
# keep the root token for break-glass use, then delete FILE.
set -euo pipefail

addr="${VAULT_ADDR:-http://127.0.0.1:8200}"
out="$HOME/securevault-init.json"
shares=0 threshold=0

die() { echo "init-vault: $*" >&2; exit 1; }
usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts a:o:n:t:h opt; do
  case "$opt" in
    a) addr="$OPTARG" ;;
    o) out="$OPTARG" ;;
    n) shares="$OPTARG" ;;
    t) threshold="$OPTARG" ;;
    h) usage ;;
    *) usage 2 ;;
  esac
done
[[ "$shares" =~ ^[0-9]+$ && "$threshold" =~ ^[0-9]+$ ]] || die "-n and -t take numbers"
command -v curl >/dev/null || die "needs curl"
command -v python3 >/dev/null || die "needs python3"
addr="${addr%/}"

if [ -e "$out" ] && grep -q root_token "$out" 2>/dev/null; then
  die "$out already holds an init result; move it somewhere safe first"
fi

status="$(curl -fsS --max-time 10 "$addr/v1/sys/seal-status")" || die "can't reach $addr"
initialized="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["initialized"])' <<<"$status")" \
  || die "unexpected answer from $addr/v1/sys/seal-status"
[ "$initialized" = False ] || die "$addr is already initialized; nothing to do"

umask 077
tmp="$(mktemp "$(dirname "$out")/.securevault-init.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

code="$(curl -sS --max-time 30 -o "$tmp" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"secret_shares\":$shares,\"secret_threshold\":$threshold}" \
  "$addr/v1/sys/init")" || die "init request to $addr failed"
# A failed init answers with a plain error message and no keys, so it's safe to show.
[ "$code" = 200 ] || die "init failed (HTTP $code): $(head -c 200 "$tmp")"

summary="$(python3 - "$tmp" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
keys, token = d.get("keys") or [], d.get("root_token") or ""
if not keys or len(set(keys)) != len(keys) or not token:
    sys.exit("the server's answer is missing keys or the root token")
print(f"{len(keys)} key shares and the root token")
EOF
)" || die "unexpected init answer; the result was not saved"

mv "$tmp" "$out"
trap - EXIT
chmod 600 "$out"

echo "Initialized $addr: wrote $summary to $out (mode 600)."
echo "Split the shares among their holders, store the root token safely, then delete $out."
