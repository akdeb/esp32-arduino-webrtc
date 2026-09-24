#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output="$(mktemp -d)"
trap 'rm -rf "$output"' EXIT
${CXX:-c++} -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -I src test/audio_test.cpp -o "$output/audio_test"
"$output/audio_test"
${CXX:-c++} -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -I src test/codec_test.cpp src/detail/AudioCodec.cpp -o "$output/codec_test"
"$output/codec_test"
