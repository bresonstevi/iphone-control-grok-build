#!/bin/bash
# Re-sign WebDriverAgent with build-for-testing. Does not kill or start anything.
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  LINK_DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
  TARGET="$(readlink "$SOURCE")"
  case "$TARGET" in
    /*) SOURCE="$TARGET" ;;
    *) SOURCE="$LINK_DIR/$TARGET" ;;
  esac
done
DIR="$(cd "$(dirname "$SOURCE")" && pwd -P)"

eval "$(/usr/bin/python3 - "$DIR/policy.json" <<'PY'
import json
import os
import shlex
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    device = json.load(fh)["device"]

required = [
    "udid",
    "team_id",
    "wda_bundle_id",
    "wda_dir",
    "wda_project",
    "wda_scheme",
    "derived_data",
    "wda_build_log",
]
missing = [key for key in required if not device.get(key)]
if missing:
    sys.stderr.write("policy.json device section missing: %s\n" % ", ".join(missing))
    sys.exit(1)

def emit(name, value):
    print("%s=%s" % (name, shlex.quote(os.path.expanduser(str(value)))))

emit("UDID", device["udid"])
emit("TEAM_ID", device["team_id"])
emit("WDA_BUNDLE_ID", device["wda_bundle_id"])
emit("WDA_DIR", device["wda_dir"])
emit("WDA_PROJECT", device["wda_project"])
emit("WDA_SCHEME", device["wda_scheme"])
emit("DERIVED_DATA", device["derived_data"])
emit("WDA_BUILD_LOG", device["wda_build_log"])
emit("CODE_SIGN_STYLE", device.get("code_sign_style") or "Automatic")
PY
)"

mkdir -p "$(dirname "$WDA_BUILD_LOG")"
cd "$WDA_DIR"

echo "Building WebDriverAgent (build-for-testing)."
echo "Log: $WDA_BUILD_LOG"
echo "This script does not stop, kill, or start iproxy or xcodebuild."

{
  echo "===== $(date) build-for-testing ====="
  xcodebuild \
    -project "$WDA_PROJECT" \
    -scheme "$WDA_SCHEME" \
    -destination "id=${UDID}" \
    -derivedDataPath "$DERIVED_DATA" \
    -allowProvisioningUpdates \
    "DEVELOPMENT_TEAM=${TEAM_ID}" \
    "PRODUCT_BUNDLE_IDENTIFIER=${WDA_BUNDLE_ID}" \
    "CODE_SIGN_STYLE=${CODE_SIGN_STYLE}" \
    build-for-testing
} >>"$WDA_BUILD_LOG" 2>&1

cat <<EOF

Build finished. Log: ${WDA_BUILD_LOG}

Free Apple development signing expires after 7 days. Run resign.sh again before it expires.

This script does not stop or kill any process.
Stop the old WebDriverAgent xcodebuild run yourself, then start it again:

  ${DIR}/iphone start

The phone must be unlocked. If iOS shows an Untrusted Developer prompt, open Settings, General, VPN & Device Management, and trust the developer profile.
EOF
