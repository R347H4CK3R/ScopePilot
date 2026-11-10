#!/usr/bin/env bash
# No deployment, credentials, signing identities, billing changes or auto triggers.
set -euo pipefail
cd "${CM_BUILD_DIR:-$(pwd)}"
test "$(uname -s)" = Darwin
test ! -e cm-output
test ! -e cm-work
SOURCE_SHA=$(git rev-parse HEAD)
if [ -n "${CM_COMMIT:-}" ]; then test "$SOURCE_SHA" = "$CM_COMMIT"; fi
test -z "$(git status --porcelain)"
mkdir -p cm-output/diagnostics cm-work
printf '%s\n' "$SOURCE_SHA" > cm-output/diagnostics/source-commit.txt
xcodebuild -version | tee cm-output/diagnostics/xcode-version.txt
test "$(xcrun --sdk iphoneos --show-sdk-version | cut -d. -f1)" -ge 26
SERVER_PID=''
SIMULATOR_ID=''
cleanup() {
  result=$?
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [ -n "$SIMULATOR_ID" ]; then xcrun simctl shutdown "$SIMULATOR_ID" 2>/dev/null || true; fi
  if [ -d cm-work/simulator.xcresult ]; then
    ditto -c -k --keepParent cm-work/simulator.xcresult cm-output/diagnostics/simulator-results.zip || true
  fi
  exit "$result"
}
trap cleanup EXIT

python3 tests/test_codemagic_ipa.py

# Preserve the existing Node, generated-asset and browser regression gates.
npm test 2>&1 | tee cm-output/diagnostics/node-tests.log
python3 scripts/sync_assets.py
git diff --exit-code -- .
npm install --no-save --package-lock=false playwright@1.51.1
npx playwright install chromium
python3 -m http.server 8137 --bind 127.0.0.1 --directory web > cm-output/diagnostics/web-server.log 2>&1 &
SERVER_PID=$!
for attempt in {1..30}; do curl -fsS http://127.0.0.1:8137/ >/dev/null && break; sleep 1; done
curl -fsS http://127.0.0.1:8137/ >/dev/null
node tests/ui.mjs 2>&1 | tee cm-output/diagnostics/ui-tests.log
cp /tmp/scopepilot-*.png cm-output/diagnostics/

# Use the same Gradle version as GitHub CI and verify its official checksum.
mkdir -p cm-work/tools
curl --fail --location --retry 2 --connect-timeout 30 --max-time 300 https://services.gradle.org/distributions/gradle-8.9-bin.zip -o cm-work/tools/gradle.zip
echo 'd725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab  cm-work/tools/gradle.zip' | shasum -a 256 -c -
unzip -q cm-work/tools/gradle.zip -d cm-work/tools
test -d "$ANDROID_HOME/platforms/android-35"
# Uses already-accepted machine SDK licenses; do not auto-accept new terms.
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" 'build-tools;35.0.0' </dev/null
cm-work/tools/gradle-8.9/bin/gradle --no-daemon -p android assembleDebug lint 2>&1 | tee cm-output/diagnostics/android.log
unzip -t android/app/build/outputs/apk/debug/app-debug.apk > cm-output/diagnostics/apk-zip-check.txt

# Run the original iOS simulator test target before producing device output.
if ! command -v xcodegen >/dev/null; then HOMEBREW_NO_AUTO_UPDATE=1 brew install xcodegen; fi
python3 scripts/make_icon.py
(cd ios && xcodegen generate)
xcrun simctl list devices available -j > cm-work/simulators.json
SIMULATOR_ID=$(python3 - <<'PY'
import json
from pathlib import Path
devices = json.loads(Path("cm-work/simulators.json").read_text())["devices"]
choices = [d for runtime, group in sorted(devices.items(), reverse=True) if ".iOS-" in runtime for d in group if d.get("isAvailable") and d["name"].startswith("iPhone")]
if not choices:
    raise SystemExit("No available iPhone simulator")
print(choices[0]["udid"])
PY
)
xcrun simctl bootstatus "$SIMULATOR_ID" -b
xcodebuild test -project ios/ScopePilot.xcodeproj -scheme ScopePilot -destination "platform=iOS Simulator,id=$SIMULATOR_ID" -parallel-testing-enabled NO -resultBundlePath cm-work/simulator.xcresult CODE_SIGNING_ALLOWED=NO 2>&1 | tee cm-output/diagnostics/ios-simulator.log

xcodebuild -project ios/ScopePilot.xcodeproj -scheme ScopePilot -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath cm-work/device CODE_SIGNING_ALLOWED=NO build 2>&1 | tee cm-output/diagnostics/ios-device.log
APP=cm-work/device/Build/Products/Release-iphoneos/ScopePilot.app
test -d "$APP"
xcrun lipo "$APP/ScopePilot" -verify_arch arm64
xcrun vtool -show-build "$APP/ScopePilot" | tee cm-output/diagnostics/macho-platform.txt
grep -q 'platform IOS$' cm-output/diagnostics/macho-platform.txt
mkdir -p cm-work/package/Payload cm-output/candidate
ditto "$APP" "cm-work/package/Payload/ScopePilot.app"
(cd cm-work/package && ditto -c -k --keepParent Payload ../../cm-output/candidate/ScopePilot-unsigned.ipa)
python3 scripts/verify_codemagic_ipa.py --ipa cm-output/candidate/ScopePilot-unsigned.ipa --app-name ScopePilot --bundle-id app.scopepilot.mobile --version 0.3.0 --build 3 --minimum-os 16.0 --source-sha "$SOURCE_SHA" --web web --output cm-output/candidate/verification.json
cp android/app/build/outputs/apk/debug/app-debug.apk cm-output/candidate/ScopePilot-debug.apk
(cd cm-output/candidate && shasum -a 256 *.ipa *.apk verification.json > SHA256SUMS.txt)
# This directory is exposed as a candidate only after every gate above passed.
mv cm-output/candidate cm-output/verified
