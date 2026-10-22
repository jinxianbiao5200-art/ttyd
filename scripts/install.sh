#!/bin/bash
# Copy the built ttyd to a stable path and sign it with a stable identity,
# so macOS privacy (TCC) grants survive rebuilds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IDENTITY="${TTYD_SIGN_IDENTITY:-ttyd-local-signer}"
mkdir -p "$ROOT/bin"
cp -f "$ROOT/build/ttyd" "$ROOT/bin/ttyd.new"
/usr/bin/codesign -f -s "$IDENTITY" --identifier com.jinxianbiao.ttyd "$ROOT/bin/ttyd.new"
mv -f "$ROOT/bin/ttyd.new" "$ROOT/bin/ttyd"
/usr/bin/codesign --verify --strict "$ROOT/bin/ttyd"
echo "installed $ROOT/bin/ttyd (restart the LaunchAgent to use it)"
