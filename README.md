# esp32-room-firmware

ESP32 firmware with a small password-protected web UI and **signed OTA updates pulled from this repo**.

## How updates work
1. A release writes `ota/firmware.bin`, `ota/manifest.json` (build number, size, SHA-256) and `ota/manifest.sig`
   (ECDSA P-256 signature over the exact bytes of `manifest.json`).
2. The board checks `https://raw.githubusercontent.com/t112840006-coder/esp32-room-firmware/ota/ota/` every 30 minutes
   (or when you press *Check for update*), verifies the signature against the public key in `firmware/src/pubkey.h`,
   and offers the update. It installs only after you press *Install* (auto-install is optional and off by default).
3. The firmware is streamed into the spare OTA partition while hashing; the SHA-256 must match the signed manifest
   before the board switches over. Anything that fails verification is discarded.

The signing key stays on the maintainer's machine and is **not** in this repo. Wi-Fi name/password and the admin
password are stored in the board's flash, never in the source or in published binaries.

## Layout
- `firmware/` PlatformIO project (`public` env = published build, `seed` env = private first-install build)
- `ota/` published release artifacts (`firmware.bin`, `manifest.json`, `manifest.sig`)
- `tools/release.sh` build + sign a release; `tools/make_seed.sh` build the private first-install image
