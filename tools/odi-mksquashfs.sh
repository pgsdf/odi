#!/bin/sh
# odi-mksquashfs.sh
# Build a deterministic SquashFS image suitable for use as an ODI payload.
#
# Usage:
#   tools/odi-mksquashfs.sh <rootdir> <out.sqfs> [sortfile]
#
# Environment:
#   SOURCE_DATE_EPOCH  If set, used as the reproducible timestamp.
#
# Notes:
# - This script is a convenience wrapper around mksquashfs(1).
# - Pin your squashfs-tools version in CI/build systems for true byte-for-byte determinism.

set -eu

if [ $# -lt 2 ]; then
  echo "usage: $0 <rootdir> <out.sqfs> [sortfile]" >&2
  exit 2
fi

ROOTDIR="$1"
OUT="$2"
SORTFILE="${3:-}"

TIME="${SOURCE_DATE_EPOCH:-1700000000}"

if [ -z "$SORTFILE" ]; then
  SORTFILE="$(mktemp)"
  trap 'rm -f "$SORTFILE"' EXIT
  # Stable ordering
  find "$ROOTDIR" -print | LC_ALL=C sort > "$SORTFILE"
fi

exec mksquashfs "$ROOTDIR" "$OUT"   -comp xz -b 1M   -repro-time "$TIME"   -sort "$SORTFILE"   -all-root   -no-xattrs   -no-exports   -nopad
