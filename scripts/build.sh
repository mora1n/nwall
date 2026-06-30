#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
BIN_NAME="${BIN_NAME:-nwall}"

mkdir -p "$OUT_DIR"
CGO_ENABLED="${CGO_ENABLED:-0}" go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/$BIN_NAME" "$ROOT_DIR/cmd/nwall"
printf '%s\n' "$OUT_DIR/$BIN_NAME"
