#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET_DIR="${ASSET_DIR:-$ROOT_DIR/internal/geo/assets}"
TMP_BIN="${TMP_BIN:-$(mktemp -t nwall-geobuild.XXXXXX)}"
cleanup() {
  rm -f "$TMP_BIN"
}
trap cleanup EXIT

go build -tags geobuild -o "$TMP_BIN" "$ROOT_DIR/cmd/geobuild"
"$TMP_BIN" --asset-dir "$ASSET_DIR"
