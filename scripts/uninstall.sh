#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x "$SCRIPT_DIR/nwall" ]]; then
  exec "$SCRIPT_DIR/nwall" uninstall "$@"
fi

if [[ -x /usr/local/bin/nwall ]]; then
  exec /usr/local/bin/nwall uninstall "$@"
fi

printf 'nwall executable not found; cannot run uninstall.\n' >&2
exit 1
