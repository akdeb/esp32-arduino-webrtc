#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output="$(mktemp -d)"
trap 'rm -rf "$output"' EXIT
${CC:-cc} -std=c11 -D_DEFAULT_SOURCE -O1 -fsanitize=address,undefined -I src test/srtp_smoke.c src/vendor/srtp/srtp/*.c src/vendor/srtp/crypto/*/*.c -o "$output/srtp_smoke"
"$output/srtp_smoke"
