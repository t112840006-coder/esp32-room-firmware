#!/usr/bin/env bash
# Build the public firmware, write + sign ota/manifest.json.
# usage: tools/release.sh <build-number> <version-label>
# The signing key is read from $OTA_KEY (default ~/.esp32-keys/ota_priv.pem) and never leaves this machine.
set -euo pipefail
BUILD="${1:?build number}"; VERSION="${2:?version label}"
KEY="${OTA_KEY:-$HOME/.esp32-keys/ota_priv.pem}"
cd "$(dirname "$0")/.."
export PLATFORMIO_BUILD_FLAGS="-DFW_BUILD=$BUILD -DFW_VERSION=$VERSION"
pio run -d firmware -e public
mkdir -p ota
cp firmware/.pio/build/public/firmware.bin ota/firmware.bin
SIZE=$(stat -c%s ota/firmware.bin)
SHA=$(sha256sum ota/firmware.bin | cut -d' ' -f1)
printf '{"build":%s,"version":"%s","size":%s,"sha256":"%s","file":"firmware.bin"}' "$BUILD" "$VERSION" "$SIZE" "$SHA" > ota/manifest.json
openssl dgst -sha256 -sign "$KEY" -out ota/manifest.sig ota/manifest.json
openssl dgst -sha256 -verify <(openssl ec -in "$KEY" -pubout 2>/dev/null) -signature ota/manifest.sig ota/manifest.json
echo "released build $BUILD ($VERSION): $SIZE bytes sha256=$SHA"
