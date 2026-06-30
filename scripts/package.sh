#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"

if [[ -z "$VERSION" ]]; then
  printf 'VERSION is required, for example: VERSION=v0.1.0 scripts/package.sh\n' >&2
  exit 1
fi
if [[ "$GOOS" != "linux" || "$GOARCH" != "amd64" ]]; then
  printf 'only linux/amd64 release packages are supported now\n' >&2
  exit 1
fi

PKG_NAME="nwall-linux-amd64-$VERSION"
PKG_DIR="$OUT_DIR/$PKG_NAME"
ARCHIVE="$OUT_DIR/$PKG_NAME.tar.gz"
VERSION_VALUE="${VERSION#v}"

rm -rf "$PKG_DIR" "$ARCHIVE" "$ARCHIVE.sha256"
install -d -m 0755 "$PKG_DIR/systemd" "$OUT_DIR"

CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags="-s -w -X github.com/mora1n/nwall/internal/version.Version=$VERSION_VALUE" -o "$PKG_DIR/nwall" "$ROOT_DIR/cmd/nwall"
install -m 0755 "$ROOT_DIR/scripts/install.sh" "$PKG_DIR/install.sh"
install -m 0755 "$ROOT_DIR/scripts/uninstall.sh" "$PKG_DIR/uninstall.sh"
install -m 0644 "$ROOT_DIR"/systemd/*.service "$PKG_DIR/systemd/"
install -m 0644 "$ROOT_DIR"/systemd/*.timer "$PKG_DIR/systemd/"
install -m 0644 "$ROOT_DIR/README.md" "$PKG_DIR/README.md"

(cd "$OUT_DIR" && tar -czf "$PKG_NAME.tar.gz" "$PKG_NAME")
(cd "$OUT_DIR" && sha256sum "$PKG_NAME.tar.gz" > "$PKG_NAME.tar.gz.sha256")

printf '%s\n' "$ARCHIVE"
printf '%s\n' "$ARCHIVE.sha256"
