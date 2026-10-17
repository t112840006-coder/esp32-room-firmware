#!/usr/bin/env bash
# Build the PRIVATE seed firmware (contains your Wi-Fi + admin password). Do not commit or publish the output.
# usage: SEED_SSID=... SEED_PASS=... SEED_WEBPASS=... tools/make_seed.sh <output.bin>
set -euo pipefail
OUT="${1:?output path}"
: "${SEED_SSID:?}" "${SEED_PASS:?}" "${SEED_WEBPASS:?}"
cd "$(dirname "$0")/.."
printf '#pragma once\n#define SEED_SSID "%s"\n#define SEED_PASS "%s"\n#define SEED_WEBPASS "%s"\n' "$SEED_SSID" "$SEED_PASS" "$SEED_WEBPASS" > firmware/src/seed_config.h
trap 'rm -f firmware/src/seed_config.h' EXIT
pio run -d firmware -e seed
cp firmware/.pio/build/seed/firmware.bin "$OUT"
echo "seed firmware: $OUT"
