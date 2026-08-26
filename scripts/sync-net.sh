#!/usr/bin/env bash
# Re-vendor velxiogw/net from velxio-prod and re-apply the local patches.
# Usage: ./scripts/sync-net.sh /path/to/velxio-prod
set -euo pipefail
SRC="${1:?usage: sync-net.sh /path/to/velxio-prod}/pro/backend/app/services/picow_net"
DST="$(cd "$(dirname "$0")/.." && pwd)/velxiogw/net"
[[ -d "$SRC" ]] || { echo "not found: $SRC" >&2; exit 1; }
cp "$SRC"/*.py "$DST"/
python3 "$(dirname "$0")/apply-patches.py" "$DST"
echo "re-vendored from $SRC — review 'git diff velxiogw/net' before committing."
