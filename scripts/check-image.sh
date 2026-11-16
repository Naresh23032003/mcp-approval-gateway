#!/usr/bin/env sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <image>" >&2
  exit 1
fi

IMAGE="$1"

found="$(docker run --rm --entrypoint sh "$IMAGE" -c 'find / -xdev \( -name .git -o -name "*.map" \) -not -path "/proc/*" 2>/dev/null || true')"
if [ -n "$found" ]; then
  echo "Disallowed .git or .map files found in image:" >&2
  echo "$found" >&2
  exit 1
fi

uid="$(docker run --rm --entrypoint id "$IMAGE" -u | tr -d '\r\n')"
if [ "$uid" = "0" ]; then
  echo "Container user must not be root (uid 0)" >&2
  exit 1
fi
