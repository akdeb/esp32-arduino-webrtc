#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output="$(mktemp -d)"
trap 'rm -rf "$output"' EXIT
${CC:-cc} -std=c11 -D_POSIX_C_SOURCE=200809L -O1 -fsanitize=address,undefined -I src test/tls_smoke.c src/vendor/tls/library/*.c -o "$output/tls_smoke"
"$output/tls_smoke"
