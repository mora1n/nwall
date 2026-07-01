#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-mora1n/nwall}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local}"
STATEDIR="${STATEDIR:-/var/lib/nwall}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
DRY_RUN=0
CLEANUP_DIR=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: install.sh [--version latest|vX.Y.Z] [--repo owner/name] [--dry-run]

Options:
  --version       GitHub Release version to install. Default: latest.
  --repo          GitHub repository. Default: mora1n/nwall.
  --prefix        Install prefix. Default: /usr/local.
  --statedir      State directory. Default: /var/lib/nwall.
  --systemd-dir   systemd unit directory. Default: /etc/systemd/system.
  --dry-run       Print actions without changing the system.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:?missing value for --version}"
      shift
      ;;
    --repo)
      REPO="${2:?missing value for --repo}"
      shift
      ;;
    --prefix)
      PREFIX="${2:?missing value for --prefix}"
      shift
      ;;
    --statedir)
      STATEDIR="${2:?missing value for --statedir}"
      shift
      ;;
    --systemd-dir)
      SYSTEMD_DIR="${2:?missing value for --systemd-dir}"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

run() {
  if [[ "$DRY_RUN" == 1 ]]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

release_version() {
  if [[ "$VERSION" != "latest" ]]; then
    printf '%s\n' "$VERSION"
    return 0
  fi
  need_cmd curl
  curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/##'
}

verify_release_checksum() {
  local tmpdir="$1"
  local asset="$2"
  local checksums="$tmpdir/SHA256SUMS"
  local entry="$tmpdir/$asset.sha256"
  local hash name rest

  while read -r hash name rest; do
    name="${name#\*}"
    if [[ "$name" == "$asset" ]]; then
      printf '%s  %s\n' "$hash" "$asset" > "$entry"
      (cd "$tmpdir" && sha256sum -c "$asset.sha256")
      return 0
    fi
  done < "$checksums"

  printf 'checksum entry not found for %s in SHA256SUMS\n' "$asset" >&2
  exit 1
}

download_release() {
  need_cmd curl
  need_cmd tar
  need_cmd sha256sum
  local version="$1"
  local tmpdir="$2"
  local asset="nwall-linux-amd64-$version.tar.gz"
  local base="https://github.com/$REPO/releases/download/$version"
  curl -fsSLo "$tmpdir/$asset" "$base/$asset"
  curl -fsSLo "$tmpdir/SHA256SUMS" "$base/SHA256SUMS"
  verify_release_checksum "$tmpdir" "$asset"
  tar -xzf "$tmpdir/$asset" -C "$tmpdir"
  printf '%s\n' "$tmpdir/nwall-linux-amd64-$version"
}

dry_run_remote_install() {
  local version="$1"
  local asset="nwall-linux-amd64-$version.tar.gz"
  local base="https://github.com/$REPO/releases/download/$version"
  printf 'DRY-RUN: curl -fsSLo %q %q\n' "$asset" "$base/$asset"
  printf 'DRY-RUN: curl -fsSLo %q %q\n' "SHA256SUMS" "$base/SHA256SUMS"
  printf 'DRY-RUN: verify %q with SHA256SUMS\n' "$asset"
  printf 'DRY-RUN: tar -xzf %q\n' "$asset"
  run install -d -m 0755 "$PREFIX/bin" "$STATEDIR" "$SYSTEMD_DIR"
  run install -m 0755 "nwall-linux-amd64-$version/nwall" "$PREFIX/bin/nwall"
  printf 'DRY-RUN: install systemd units from %s\n' "nwall-linux-amd64-$version/systemd"
}

install_from_dir() {
  local src_dir="$1"
  local bin_src="$src_dir/nwall"
  local unit_dir="$src_dir/systemd"
  if [[ ! -x "$bin_src" ]]; then
    printf 'missing executable: %s\n' "$bin_src" >&2
    exit 1
  fi
  run install -d -m 0755 "$PREFIX/bin" "$STATEDIR" "$SYSTEMD_DIR"
  run install -m 0755 "$bin_src" "$PREFIX/bin/nwall"
  if [[ -d "$unit_dir" ]]; then
    for unit in "$unit_dir"/*.service; do
      [[ -e "$unit" ]] || continue
      run install -m 0644 "$unit" "$SYSTEMD_DIR/$(basename "$unit")"
    done
  fi
  remove_legacy_units
}

remove_legacy_units() {
  local units=(
    nwall-dpi.service
    nwall-lease.service
    nwall-lease-trigger.service
    nwall-downmask.service
    nwall-downmask-reconcile.service
    nwall-downmask-reconcile.timer
  )
  if command -v systemctl >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == 1 ]]; then
      run systemctl disable --now "${units[@]}"
    else
      systemctl disable --now "${units[@]}" >/dev/null 2>&1 || true
    fi
  fi
  for unit in "${units[@]}"; do
    run rm -f "$SYSTEMD_DIR/$unit"
  done
}

main() {
  local src_dir="$SCRIPT_DIR"
  local tmpdir=""
  trap '[[ -n "${CLEANUP_DIR:-}" ]] && rm -rf "$CLEANUP_DIR"' EXIT
  if [[ ! -x "$src_dir/nwall" ]]; then
    local version
    if [[ "$DRY_RUN" == 1 && "$VERSION" == "latest" ]]; then
      version="latest"
    else
      version="$(release_version)"
    fi
    if [[ "$DRY_RUN" == 1 ]]; then
      dry_run_remote_install "$version"
      printf '%s\n' 'DRY-RUN: systemctl daemon-reload'
      return 0
    fi
    tmpdir="$(mktemp -d)"
    CLEANUP_DIR="$tmpdir"
    src_dir="$(download_release "$version" "$tmpdir")"
  fi
  install_from_dir "$src_dir"
  if [[ "$DRY_RUN" == 0 ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  elif [[ "$DRY_RUN" == 1 ]]; then
    printf '%s\n' 'DRY-RUN: systemctl daemon-reload'
  fi
}

main
