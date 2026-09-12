#!/usr/bin/env sh
# Build + run the ATECC command-deadline asserts. Pure logic with an injected clock: no ESP
# stack, no hardware, no wedged bus. Deterministic and fast.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/build"; GCC="${GCC:-gcc}"
mkdir -p "$OUT"
"$GCC" -std=c11 -O2 -Wall -Wextra -I "$ROOT/cryptoauthlib/lib/hal" \
    "$ROOT/cryptoauthlib/lib/hal/atca_deadline.c" "$HERE/test_atca_deadline.c" \
    -o "$OUT/test_atca_deadline"
echo "built $OUT/test_atca_deadline"
"$OUT/test_atca_deadline"
